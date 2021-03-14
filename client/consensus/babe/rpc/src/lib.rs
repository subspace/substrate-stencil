// This file is part of Substrate.

// Copyright (C) 2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! RPC api for babe.

use sc_consensus_babe::{Epoch, Config};
use jsonrpc_derive::rpc;
use sc_consensus_epochs::{SharedEpochChanges};
use sp_consensus_babe::{
	BabeApi as BabeRuntimeApi,
};
use serde::{Deserialize, Serialize};
use sc_keystore::KeyStorePtr;
use sp_api::{ProvideRuntimeApi};
use sp_runtime::traits::{Block as BlockT};
use sp_consensus::{SelectChain, Error as ConsensusError};
use sp_blockchain::{HeaderBackend, HeaderMetadata, Error as BlockChainError};
use std::{sync::Arc};

#[derive(Debug, Serialize, Deserialize)]
pub struct SlotInfo {
	pub slot_number: u64,
	pub epoch_randomness: Vec<u8>,
}

/// Provides rpc methods for interacting with Babe.
#[rpc]
pub trait BabeApi {
	/// RPC metadata
	type Metadata;
}

/// Implements the BabeRpc trait for interacting with Babe.
pub struct BabeRpcHandler<B: BlockT, C, SC> {
	/// shared reference to the client.
	client: Arc<C>,
	/// shared reference to EpochChanges
	shared_epoch_changes: SharedEpochChanges<B, Epoch>,
	/// shared reference to the Keystore
	keystore: KeyStorePtr,
	/// config (actually holds the slot duration)
	babe_config: Config,
	/// The SelectChain strategy
	select_chain: SC,
}

impl<B: BlockT, C, SC> BabeRpcHandler<B, C, SC> {
	/// Creates a new instance of the BabeRpc handler.
	pub fn new(
		client: Arc<C>,
		shared_epoch_changes: SharedEpochChanges<B, Epoch>,
		keystore: KeyStorePtr,
		babe_config: Config,
		select_chain: SC,
	) -> Self {
		Self {
			client,
			shared_epoch_changes,
			keystore,
			babe_config,
			select_chain,
		}
	}
}

impl<B, C, SC> BabeApi for BabeRpcHandler<B, C, SC>
	where
		B: BlockT,
		C: ProvideRuntimeApi<B> + HeaderBackend<B> + HeaderMetadata<B, Error=BlockChainError> + 'static,
		C::Api: BabeRuntimeApi<B>,
		SC: SelectChain<B> + Clone + 'static,
{
	type Metadata = sc_rpc_api::Metadata;
}

/// Holds information about the `slot_number`'s that can be claimed by a given key.
#[derive(Default, Debug, Deserialize, Serialize)]
pub struct EpochAuthorship {
	/// the array of primary slots that can be claimed
	primary: Vec<u64>,
	/// the array of secondary slots that can be claimed
	secondary: Vec<u64>,
	/// The array of secondary VRF slots that can be claimed.
	secondary_vrf: Vec<u64>,
}

/// Errors encountered by the RPC
#[derive(Debug, derive_more::Display, derive_more::From)]
pub enum Error {
	/// Consensus error
	Consensus(ConsensusError),
	/// Errors that can be formatted as a String
	StringError(String)
}

impl From<Error> for jsonrpc_core::Error {
	fn from(error: Error) -> Self {
		jsonrpc_core::Error {
			message: format!("{}", error),
			code: jsonrpc_core::ErrorCode::ServerError(1234),
			data: None,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use substrate_test_runtime_client::{
		runtime::Block,
		Backend,
		DefaultTestClientBuilderExt,
		TestClient,
		TestClientBuilderExt,
		TestClientBuilder,
	};
	use sp_application_crypto::AppPair;
	use sp_keyring::Ed25519Keyring;
	use sc_keystore::Store;

	use std::sync::Arc;
	use sc_consensus_babe::{Config, block_import, AuthorityPair};
	use jsonrpc_core::IoHandler;

	/// creates keystore backed by a temp file
	fn create_temp_keystore<P: AppPair>(authority: Ed25519Keyring) -> (KeyStorePtr, tempfile::TempDir) {
		let keystore_path = tempfile::tempdir().expect("Creates keystore path");
		let keystore = Store::open(keystore_path.path(), None).expect("Creates keystore");
		keystore.write().insert_ephemeral_from_seed::<P>(&authority.to_seed())
			.expect("Creates authority key");

		(keystore, keystore_path)
	}

	fn test_babe_rpc_handler(
		deny_unsafe: DenyUnsafe
	) -> BabeRpcHandler<Block, TestClient, sc_consensus::LongestChain<Backend, Block>> {
		let builder = TestClientBuilder::new();
		let (client, longest_chain) = builder.build_with_longest_chain();
		let client = Arc::new(client);
		let config = Config::get_or_compute(&*client).expect("config available");
		let (_, link) = block_import(
			config.clone(),
			client.clone(),
			client.clone(),
		).expect("can initialize block-import");

		let epoch_changes = link.epoch_changes().clone();
		let keystore = create_temp_keystore::<AuthorityPair>(Ed25519Keyring::Alice).0;

		BabeRpcHandler::new(
			client.clone(),
			epoch_changes,
			keystore,
			config,
			longest_chain,
			deny_unsafe,
		)
	}
}
