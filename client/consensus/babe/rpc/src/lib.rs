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

use std::io::Write;
use sc_consensus_babe::{Epoch, Config, SlotNumber, NewSlotNotifier, NewSlotInfo};
use futures::{FutureExt as _, TryFutureExt as _, SinkExt, TryStreamExt, compat::Compat as _};
use jsonrpc_core::{
	Error as RpcError,
	futures::future as rpc_future,
	Result as RpcResult,
	futures::{
		stream,
		Future,
		Sink,
		Stream,
		future::Future as Future01,
		future::Executor as Executor01,
	},
};
use jsonrpc_derive::rpc;
use jsonrpc_pubsub::{typed::Subscriber, SubscriptionId, manager::SubscriptionManager};
use sc_consensus_epochs::{descendent_query, Epoch as EpochT, SharedEpochChanges};
use sp_consensus_babe::{
	AuthorityId,
	BabeApi as BabeRuntimeApi,
	digests::PreDigest,
};
use serde::{Deserialize, Serialize};
use sp_core::{
	crypto::Public,
	traits::BareCryptoStore,
};
use sp_application_crypto::AppKey;
use sc_keystore::KeyStorePtr;
use sc_rpc_api::DenyUnsafe;
use sp_api::{ProvideRuntimeApi, BlockId};
use sp_runtime::traits::{Block as BlockT, Header as _};
use sp_consensus::{SelectChain, Error as ConsensusError};
use sp_blockchain::{HeaderBackend, HeaderMetadata, Error as BlockChainError};
use std::{collections::HashMap, sync::Arc};
use log::warn;
use std::sync::mpsc;

type FutureResult<T> = Box<dyn rpc_future::Future<Item = T, Error = RpcError> + Send>;

// TODO: De-duplicate
#[derive(Debug, Deserialize)]
pub struct Solution {
	pub public_key: [u8; 32],
	pub nonce: u32,
	pub encoding: Vec<u8>,
	pub signature: [u8; 32],
	pub tag: [u8; 32],
	pub randomness: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct ProposedProofOfSpaceResult {
	slot_number: SlotNumber,
	solution: Option<Solution>,
}

/// Provides rpc methods for interacting with Babe.
#[rpc]
pub trait BabeApi {
	/// RPC metadata
	type Metadata;

	// TODO: Add ProposedProofOfSpaceResult as a parameter here
	#[rpc(name = "babe_proposeProofOfSpace")]
	fn propose_proof_of_space(&self) -> FutureResult<()>;


	/// Slot info subscription
	#[pubsub(subscription = "babe_slot_info", subscribe, name = "babe_subscribeSlotInfo")]
	fn subscribe_slot_info(&self, metadata: Self::Metadata, subscriber: Subscriber<NewSlotInfo>);

	/// Unsubscribe from slot info subscription.
	#[pubsub(subscription = "babe_slot_info", unsubscribe, name = "babe_unsubscribeSlotInfo")]
	fn unsubscribe_slot_info(
		&self,
		metadata: Option<Self::Metadata>,
		id: SubscriptionId,
	) -> RpcResult<bool>;
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
	manager: SubscriptionManager,
}

impl<B: BlockT, C, SC> BabeRpcHandler<B, C, SC> {
	/// Creates a new instance of the BabeRpc handler.
	pub fn new<E>(
		client: Arc<C>,
		shared_epoch_changes: SharedEpochChanges<B, Epoch>,
		keystore: KeyStorePtr,
		babe_config: Config,
		select_chain: SC,
		executor: E,
		new_slot_notifier: NewSlotNotifier,
	) -> Self
		where
			E: Executor01<Box<dyn Future01<Item = (), Error = ()> + Send>> + Send + Sync + 'static,
	{
		std::thread::Builder::new()
			.name("babe_rpc_nsn_handler".to_string())
			.spawn(move || {
				let mut new_slot_notifier = new_slot_notifier();
				while let Ok((new_slot_info, solution_sender)) = new_slot_notifier.recv() {
					// TODO
				}
			})
			.expect("Failed to spawn babe rpc new slot notifier handler");
		let manager = SubscriptionManager::new(Arc::new(executor));
		Self {
			client,
			shared_epoch_changes,
			keystore,
			babe_config,
			select_chain,
			manager,
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

	fn propose_proof_of_space(&self) -> FutureResult<()> {
		let future = async {
			println!("Received block proposal message");
			// TODO
			Ok(())
		}.boxed();
		Box::new(future.compat())
	}

	fn subscribe_slot_info(&self, _metadata: Self::Metadata, subscriber: Subscriber<NewSlotInfo>) {
		self.manager.add(subscriber, |sink| {
			let (mut tx, rx) = futures::channel::mpsc::unbounded::<Result<NewSlotInfo, ()>>();
			std::thread::spawn(move || {
				let mut slot_number: u64 = 0;
				loop {
					std::thread::sleep(std::time::Duration::from_secs(1));
					if let Err(_) = futures::executor::block_on(tx.send(Ok(NewSlotInfo {
						slot_number,
						epoch_randomness: vec![1u8; 32]
					}))) {
						break;
					}

					slot_number += 1;
				}
			});

			sink
				.sink_map_err(|e| warn!("Error sending notifications: {:?}", e))
				.send_all(rx.compat().map(|res| Ok(res)))
				.map(|_| ())
		});
	}

	fn unsubscribe_slot_info(&self, _metadata: Option<Self::Metadata>, id: SubscriptionId) -> RpcResult<bool> {
		Ok(self.manager.cancel(id))
	}
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
