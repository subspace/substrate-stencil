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
use sp_core::{Pair, Public};
use sp_consensus_babe::{make_transcript, AuthoritySignature, SlotNumber, AuthorityPair, AuthorityId};
use sp_consensus_babe::digests::{PreDigest, PrimaryPreDigest, CompatibleDigestItem, SpartanPreDigest};
use sc_consensus_slots::CheckedHeader;
use log::{debug, trace};
use super::{find_pre_digest, babe_err, Epoch, BlockT, Error};
use super::authorship::{calculate_primary_threshold, check_primary_threshold};

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

	let authorities = &epoch.authorities;
	let pre_digest = pre_digest.map(Ok).unwrap_or_else(|| find_pre_digest::<B>(&header))?;

	trace!(target: "babe", "Checking header");
	let seal = match header.digest_mut().pop() {
		Some(x) => x,
		None => return Err(babe_err(Error::HeaderUnsealed(header.hash()))),
	};

	let sig = seal.as_babe_seal().ok_or_else(|| {
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
	pre_hash: B::Hash,
	pre_digest: &SpartanPreDigest,
	epoch: &Epoch,
	c: (u64, u64),
) -> Result<(), Error<B>> {
	// TODO: Actually verify
	Ok(())
}
