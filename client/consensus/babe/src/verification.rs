// Copyright 2019-2020 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

//! Verification for BABE headers.
use sp_runtime::{traits::Header, traits::DigestItemFor};
use sp_consensus_babe::{SlotNumber, AuthorityId};
use sp_consensus_babe::digests::{PreDigest, CompatibleDigestItem, SpartanPreDigest, Solution};
use sc_consensus_slots::CheckedHeader;
use log::{debug, trace};
use super::{find_pre_digest, babe_err, Epoch, BlockT, Error};
use crate::{SOLUTION_RANGE, Piece, PRIME_SIZE_BYTES, PIECE_SIZE, GENESIS_PIECE_SEED, ENCODE_ROUNDS, SIGNING_CONTEXT, SALT, Tag};
use spartan::Spartan;
use ring::{digest, hmac};
use std::io::Write;
use std::convert::TryInto;
use sp_core::Public;

/// BABE verification parameters
pub(super) struct VerificationParams<'a, B: 'a + BlockT> {
	/// The header being verified.
	pub(super) header: B::Header,
	/// The pre-digest of the header being verified. this is optional - if prior
	/// verification code had to read it, it can be included here to avoid duplicate
	/// work.
	pub(super) pre_digest: Option<PreDigest>,
	/// The slot number of the current time.
	pub(super) slot_now: SlotNumber,
	/// Epoch descriptor of the epoch this block _should_ be under, if it's valid.
	pub(super) epoch: &'a Epoch,
}

/// Check a header has been signed by the right key. If the slot is too far in
/// the future, an error will be returned. If successful, returns the pre-header
/// and the digest item containing the seal.
///
/// The seal must be the last digest.  Otherwise, the whole header is considered
/// unsigned.  This is required for security and must not be changed.
///
/// This digest item will always return `Some` when used with `as_babe_pre_digest`.
///
/// The given header can either be from a primary or secondary slot assignment,
/// with each having different validation logic.
pub(super) fn check_header<B: BlockT + Sized>(
	params: VerificationParams<B>,
) -> Result<CheckedHeader<B::Header, VerifiedHeaderInfo<B>>, Error<B>> where
	DigestItemFor<B>: CompatibleDigestItem,
{
	let VerificationParams {
		mut header,
		pre_digest,
		slot_now,
		epoch,
	} = params;

	let pre_digest = pre_digest.map(Ok).unwrap_or_else(|| find_pre_digest::<B>(&header))?;

	trace!(target: "babe", "Checking header");
	let seal = match header.digest_mut().pop() {
		Some(x) => x,
		None => return Err(babe_err(Error::HeaderUnsealed(header.hash()))),
	};

	// TODO
	let _sig = seal.as_babe_seal().ok_or_else(|| {
		babe_err(Error::HeaderBadSeal(header.hash()))
	})?;

	// the pre-hash of the header doesn't include the seal
	// and that's what we sign
	let pre_hash = header.hash();

	if pre_digest.slot_number() > slot_now {
		header.digest_mut().push(seal);
		return Ok(CheckedHeader::Deferred(header, pre_digest.slot_number()));
	}

	let author = pre_digest.public_key().clone();

	match &pre_digest {
		PreDigest::Primary(primary) => {
			debug!(target: "babe", "Verifying Primary block");

			check_primary_header::<B>(
				pre_hash,
				primary,
				&epoch,
				epoch.config.c,
			)?;
		},
		_ => {
			return Err(babe_err(Error::SecondarySlotAssignmentsDisabled));
		}
	}

	let info = VerifiedHeaderInfo {
		pre_digest: CompatibleDigestItem::babe_pre_digest(pre_digest),
		seal,
		author,
	};
	Ok(CheckedHeader::Checked(header, info))
}

pub(super) struct VerifiedHeaderInfo<B: BlockT> {
	pub(super) pre_digest: DigestItemFor<B>,
	pub(super) seal: DigestItemFor<B>,
	pub(super) author: AuthorityId,
}

/// Check a primary slot proposal header. We validate that the given header is
/// properly signed by the expected authority, and that the contained VRF proof
/// is valid. Additionally, the weight of this block must increase compared to
/// its parent since it is a primary block.
fn check_primary_header<B: BlockT + Sized>(
	_pre_hash: B::Hash,
	pre_digest: &SpartanPreDigest,
	epoch: &Epoch,
	_c: (u64, u64),
) -> Result<(), Error<B>> {
	if !is_within_solution_range(
		&pre_digest.solution,
		crate::create_challenge(epoch, pre_digest.slot_number),
		SOLUTION_RANGE,
	) {
		panic!("Solution is outside of solution range for slot {}", pre_digest.slot_number);
	}

	if !is_commitment_valid(&pre_digest.solution) {
		panic!("Solution commitment is incorrect for slot {}", pre_digest.slot_number);
	}

	if !is_signature_valid(&pre_digest.solution) {
		panic!("Solution signature is invalid for slot {}", pre_digest.slot_number);
	}

	if !is_encoding_valid(&pre_digest.solution) {
		panic!("Solution encoding is incorrect for slot {}", pre_digest.slot_number);
	}

	// TODO: Other verification?

	Ok(())
}

fn is_within_solution_range(solution: &Solution, challenge: [u8; 8], solution_range: u64) -> bool {
	let target = u64::from_be_bytes(challenge);
	let tag = u64::from_be_bytes(solution.tag);

	let (lower, is_lower_overflowed) = target.overflowing_sub(solution_range / 2);
	let (upper, is_upper_overflowed) = target.overflowing_add(solution_range / 2);
	if is_lower_overflowed || is_upper_overflowed {
		upper <= tag || tag <= lower
	} else {
		lower <= tag && tag <= upper
	}
}

fn is_commitment_valid(solution: &Solution) -> bool {
	let correct_tag: Tag = create_hmac(&solution.encoding, &SALT)[..8].try_into().unwrap();
	correct_tag == solution.tag
}

fn is_signature_valid(solution: &Solution) -> bool {
	// TODO: These should not be created on each verification
	let ctx = schnorrkel::context::signing_context(SIGNING_CONTEXT);
	let public_key = match schnorrkel::PublicKey::from_bytes(solution.public_key.as_slice()) {
		Ok(public_key) => public_key,
		Err(_) => {
			return false;
		}
	};
	let signature = match schnorrkel::Signature::from_bytes(&solution.signature) {
		Ok(signature) => signature,
		Err(_) => {
			return false;
		}
	};
	public_key.verify(ctx.bytes(&solution.tag), &signature).is_ok()
}

fn is_encoding_valid(solution: &Solution) -> bool {
	// TODO: This should not be created on each verification
	let spartan: Spartan<PRIME_SIZE_BYTES, PIECE_SIZE> =
		Spartan::<PRIME_SIZE_BYTES, PIECE_SIZE>::new(genesis_piece_from_seed(GENESIS_PIECE_SEED));
	let encoding = match solution.encoding.as_slice().try_into() {
		Ok(piece) => piece,
		Err(_) => {
			return false;
		}
	};
	spartan.is_valid(encoding, hash_public_key(&solution.public_key), solution.nonce, ENCODE_ROUNDS)
}

fn create_hmac(message: &[u8], key: &[u8]) -> [u8; 32] {
	let key = hmac::Key::new(hmac::HMAC_SHA256, key);
	let mut array = [0u8; 32];
	let hmac = hmac::sign(&key, message).as_ref().to_vec();
	array.copy_from_slice(&hmac[0..32]);
	array
}

// TODO: This should be only generated once on startup
fn genesis_piece_from_seed(seed: &str) -> Piece {
	// TODO: This is not efficient
	let mut piece = [0u8; PIECE_SIZE];
	let mut input = seed.as_bytes().to_vec();
	for mut chunk in piece.chunks_mut(digest::SHA256.output_len) {
		input = digest::digest(&digest::SHA256, &input).as_ref().to_vec();
		chunk.write_all(input.as_ref()).unwrap();
	}
	piece
}

fn hash_public_key(public_key: &AuthorityId) -> [u8; PRIME_SIZE_BYTES] {
	let mut array = [0u8; PRIME_SIZE_BYTES];
	let hash = digest::digest(&digest::SHA256, public_key.as_ref());
	array.copy_from_slice(&hash.as_ref()[..PRIME_SIZE_BYTES]);
	array
}
