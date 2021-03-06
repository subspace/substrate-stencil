//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use std::sync::Arc;
use sc_client_api::{ExecutorProvider, RemoteBackend};
use node_template_runtime::{self, opaque::Block, RuntimeApi};
use sc_service::{
	config::Configuration, error::{Error as ServiceError},
	RpcHandlers, TaskManager,
};
use sp_inherents::InherentDataProviders;
use sp_runtime::traits::Block as BlockT;
use sc_executor::native_executor_instance;
pub use sc_executor::NativeExecutor;
use sc_network::NetworkService;

// Our native executor instance.
native_executor_instance!(
	pub Executor,
	node_template_runtime::api::dispatch,
	node_template_runtime::native_version,
	frame_benchmarking::benchmarking::HostFunctions,
);

type FullClient = sc_service::TFullClient<Block, RuntimeApi, Executor>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;
type LightClient = sc_service::TLightClient<Block, RuntimeApi, Executor>;

pub fn new_partial(
	config: &Configuration,
) -> Result<sc_service::PartialComponents<
	FullClient, FullBackend, FullSelectChain,
	sp_consensus::DefaultImportQueue<Block, FullClient>,
	sc_transaction_pool::FullPool<Block, FullClient>,
	(
		(
			sc_consensus_babe::BabeBlockImport<Block, FullClient, Arc<FullClient>>,
			sc_consensus_babe::BabeLink<Block>,
		),
	)
>, ServiceError> {
	let (client, backend, keystore, task_manager) =
		sc_service::new_full_parts::<Block, RuntimeApi, Executor>(&config)?;
	let client = Arc::new(client);

	let select_chain = sc_consensus::LongestChain::new(backend.clone());

	let transaction_pool = sc_transaction_pool::BasicPool::new_full(
		config.transaction_pool.clone(),
		config.prometheus_registry(),
		task_manager.spawn_handle(),
		client.clone(),
	);

	let (block_import, babe_link) = sc_consensus_babe::block_import(
		sc_consensus_babe::Config::get_or_compute(&*client)?,
		client.clone(),
		client.clone(),
	)?;

	let inherent_data_providers = sp_inherents::InherentDataProviders::new();

	let import_queue = sc_consensus_babe::import_queue(
		babe_link.clone(),
		block_import.clone(),
		None,
		None,
		client.clone(),
		select_chain.clone(),
		inherent_data_providers.clone(),
		&task_manager.spawn_handle(),
		config.prometheus_registry(),
		sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone()),
	)?;

	let import_setup = (block_import, babe_link);

	Ok(sc_service::PartialComponents {
		client, backend, task_manager, keystore, select_chain, import_queue, transaction_pool,
		inherent_data_providers,
		other: (import_setup,)
	})
}

pub struct NewFullBase {
	pub task_manager: TaskManager,
	pub inherent_data_providers: InherentDataProviders,
	pub client: Arc<FullClient>,
	pub network: Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
	pub network_status_sinks: sc_service::NetworkStatusSinks<Block>,
	pub transaction_pool: Arc<sc_transaction_pool::FullPool<Block, FullClient>>,
}

/// Creates a full service from the configuration.
pub fn new_full_base(
	config: Configuration,
	with_startup_data: impl FnOnce(
		&sc_consensus_babe::BabeBlockImport<Block, FullClient, Arc<FullClient>>,
		&sc_consensus_babe::BabeLink<Block>,
	)
) -> Result<NewFullBase, ServiceError> {
	let sc_service::PartialComponents {
		client, backend, mut task_manager, import_queue, keystore, select_chain, transaction_pool,
		inherent_data_providers,
		other: (import_setup,),
	} = new_partial(&config)?;

	let (network, network_status_sinks, system_rpc_tx, network_starter) =
		sc_service::build_network(sc_service::BuildNetworkParams {
			config: &config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue,
			on_demand: None,
			block_announce_validator_builder: None,
			finality_proof_request_builder: None,
			finality_proof_provider: None,
		})?;

	if config.offchain_worker.enabled {
		sc_service::build_offchain_workers(
			&config, backend.clone(), task_manager.spawn_handle(), client.clone(), network.clone(),
		);
	}

	// let role = config.role.clone();
	let force_authoring = config.force_authoring;
	let prometheus_registry = config.prometheus_registry().cloned();
	let telemetry_connection_sinks = sc_service::TelemetryConnectionSinks::default();

	let (block_import, babe_link) = import_setup.clone();

	(with_startup_data)(&block_import, &babe_link);

	let new_slot_notifier;

	// if let sc_service::config::Role::Authority { .. } = &role {
		let proposer = sc_basic_authorship::ProposerFactory::new(
			client.clone(),
			transaction_pool.clone(),
			prometheus_registry.as_ref(),
		);

		let can_author_with =
			sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone());

		let babe_config = sc_consensus_babe::BabeParams {
			client: client.clone(),
			select_chain: select_chain.clone(),
			env: proposer,
			block_import,
			sync_oracle: network.clone(),
			inherent_data_providers: inherent_data_providers.clone(),
			force_authoring,
			babe_link,
			can_author_with,
		};

		let babe = sc_consensus_babe::start_babe(babe_config)?;
		new_slot_notifier = babe.get_new_slot_notifier();
		task_manager.spawn_essential_handle().spawn_blocking("babe-proposer", babe);
	// }

	let (rpc_extensions_builder,) = {
		let client = client.clone();
		let pool = transaction_pool.clone();

		let rpc_extensions_builder = move |deny_unsafe, subscription_executor| {
			let deps = crate::rpc::FullDeps {
				client: client.clone(),
				pool: pool.clone(),
				deny_unsafe,
				babe: crate::rpc::BabeDeps {
					subscription_executor,
					new_slot_notifier: Arc::clone(&new_slot_notifier),
				},
			};

			crate::rpc::create_full(deps)
		};

		(rpc_extensions_builder,)
	};

	sc_service::spawn_tasks(sc_service::SpawnTasksParams {
		config,
		backend: backend.clone(),
		client: client.clone(),
		keystore: keystore.clone(),
		network: network.clone(),
		rpc_extensions_builder: Box::new(rpc_extensions_builder),
		transaction_pool: transaction_pool.clone(),
		task_manager: &mut task_manager,
		on_demand: None,
		remote_blockchain: None,
		telemetry_connection_sinks: telemetry_connection_sinks.clone(),
		network_status_sinks: network_status_sinks.clone(),
		system_rpc_tx,
	})?;

	// // Spawn authority discovery module.
	// if matches!(role, Role::Authority{..} | Role::Sentry {..}) {
	// 	let (sentries, authority_discovery_role) = match role {
	// 		sc_service::config::Role::Authority { ref sentry_nodes } => (
	// 			sentry_nodes.clone(),
	// 			sc_authority_discovery::Role::Authority (
	// 				keystore.clone(),
	// 			),
	// 		),
	// 		sc_service::config::Role::Sentry {..} => (
	// 			vec![],
	// 			sc_authority_discovery::Role::Sentry,
	// 		),
	// 		_ => unreachable!("Due to outer matches! constraint; qed.")
	// 	};

	// 	let dht_event_stream = network.event_stream("authority-discovery")
	// 		.filter_map(|e| async move { match e {
	// 			Event::Dht(e) => Some(e),
	// 			_ => None,
	// 		}}).boxed();
	// 	let (authority_discovery_worker, _service) = sc_authority_discovery::new_worker_and_service(
	// 		client.clone(),
	// 		network.clone(),
	// 		sentries,
	// 		dht_event_stream,
	// 		authority_discovery_role,
	// 		prometheus_registry.clone(),
	// 	);

	// 	task_manager.spawn_handle().spawn("authority-discovery-worker", authority_discovery_worker);
	// }

	network_starter.start_network();
	Ok(NewFullBase {
		task_manager, inherent_data_providers, client, network, network_status_sinks,
		transaction_pool,
	})
}

/// Builds a new service for a full client.
pub fn new_full(config: Configuration)
-> Result<TaskManager, ServiceError> {
	new_full_base(config, |_, _| ()).map(|NewFullBase { task_manager, .. }| {
		task_manager
	})
}

pub fn new_light_base(config: Configuration) -> Result<(
	TaskManager, RpcHandlers, Arc<LightClient>,
	Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
	Arc<sc_transaction_pool::LightPool<Block, LightClient, sc_network::config::OnDemand<Block>>>
), ServiceError> {
	let (client, backend, keystore, mut task_manager, on_demand) =
		sc_service::new_light_parts::<Block, RuntimeApi, Executor>(&config)?;

	let select_chain = sc_consensus::LongestChain::new(backend.clone());

	let transaction_pool = Arc::new(sc_transaction_pool::BasicPool::new_light(
		config.transaction_pool.clone(),
		config.prometheus_registry(),
		task_manager.spawn_handle(),
		client.clone(),
		on_demand.clone(),
	));

	let (babe_block_import, babe_link) = sc_consensus_babe::block_import(
		sc_consensus_babe::Config::get_or_compute(&*client)?,
		client.clone(),
		client.clone(),
	)?;

	let inherent_data_providers = sp_inherents::InherentDataProviders::new();

	let import_queue = sc_consensus_babe::import_queue(
		babe_link,
		babe_block_import,
		None,
		None,
		client.clone(),
		select_chain.clone(),
		inherent_data_providers.clone(),
		&task_manager.spawn_handle(),
		config.prometheus_registry(),
		sp_consensus::NeverCanAuthor,
	)?;

	let (network, network_status_sinks, system_rpc_tx, network_starter) =
		sc_service::build_network(sc_service::BuildNetworkParams {
			config: &config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue,
			on_demand: Some(on_demand.clone()),
			block_announce_validator_builder: None,
			finality_proof_request_builder: None,
			finality_proof_provider: None,
		})?;
	network_starter.start_network();

	if config.offchain_worker.enabled {
		sc_service::build_offchain_workers(
			&config, backend.clone(), task_manager.spawn_handle(), client.clone(), network.clone(),
		);
	}

	let light_deps = crate::rpc::LightDeps {
		remote_blockchain: backend.remote_blockchain(),
		fetcher: on_demand.clone(),
		client: client.clone(),
		pool: transaction_pool.clone(),
	};

	let rpc_extensions = crate::rpc::create_light(light_deps);

	let rpc_handlers =
		sc_service::spawn_tasks(sc_service::SpawnTasksParams {
			on_demand: Some(on_demand),
			remote_blockchain: Some(backend.remote_blockchain()),
			rpc_extensions_builder: Box::new(sc_service::NoopRpcExtensionBuilder(rpc_extensions)),
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			config, keystore, backend, network_status_sinks, system_rpc_tx,
			network: network.clone(),
			telemetry_connection_sinks: sc_service::TelemetryConnectionSinks::default(),
			task_manager: &mut task_manager,
		})?;

	Ok((task_manager, rpc_handlers, client, network, transaction_pool))
}

/// Builds a new service for a light client.
pub fn new_light(config: Configuration) -> Result<TaskManager, ServiceError> {
	new_light_base(config).map(|(task_manager, _, _, _, _)| {
		task_manager
	})
}

#[cfg(test)]
mod tests {
	use std::{sync::Arc, borrow::Cow, any::Any};
	use sc_consensus_babe::{CompatibleDigestItem, BabeIntermediate, INTERMEDIATE_KEY};
	use sc_consensus_epochs::descendent_query;
	use sp_consensus::{
		Environment, Proposer, BlockImportParams, BlockOrigin, ForkChoiceStrategy, BlockImport,
		RecordProof,
	};
	use node_primitives::{Block, DigestItem, Signature};
	use node_runtime::{BalancesCall, Call, UncheckedExtrinsic, Address};
	use node_runtime::constants::{currency::CENTS, time::SLOT_DURATION};
	use codec::Encode;
	use sp_core::{crypto::Pair as CryptoPair, H256};
	use sp_runtime::{
		generic::{BlockId, Era, Digest, SignedPayload},
		traits::{Block as BlockT, Header as HeaderT},
		traits::Verify,
	};
	use sp_timestamp;
	use sp_finality_tracker;
	use sp_keyring::AccountKeyring;
	use sc_service_test::TestNetNode;
	use crate::service::{new_full_base, new_light_base, NewFullBase};
	use sp_runtime::traits::IdentifyAccount;
	use sp_transaction_pool::{MaintainedTransactionPool, ChainEvent};
	use sc_client_api::BlockBackend;

	type AccountPublic = <Signature as Verify>::Signer;

	#[test]
	// It is "ignored", but the node-cli ignored tests are running on the CI.
	// This can be run locally with `cargo test --release -p node-cli test_sync -- --ignored`.
	#[ignore]
	fn test_sync() {
		let keystore_path = tempfile::tempdir().expect("Creates keystore path");
		let keystore = sc_keystore::Store::open(keystore_path.path(), None)
			.expect("Creates keystore");
		let alice = keystore.write().insert_ephemeral_from_seed::<sc_consensus_babe::AuthorityPair>("//Alice")
			.expect("Creates authority pair");

		let chain_spec = crate::chain_spec::tests::integration_test_config_with_single_authority();

		// For the block factory
		let mut slot_num = 1u64;

		// For the extrinsics factory
		let bob = Arc::new(AccountKeyring::Bob.pair());
		let charlie = Arc::new(AccountKeyring::Charlie.pair());
		let mut index = 0;

		sc_service_test::sync(
			chain_spec,
			|config| {
				let mut setup_handles = None;
				let NewFullBase {
					task_manager, inherent_data_providers, client, network, transaction_pool, ..
				} = new_full_base(config,
					|
						block_import: &sc_consensus_babe::BabeBlockImport<Block, _, _>,
						babe_link: &sc_consensus_babe::BabeLink<Block>,
					| {
						setup_handles = Some((block_import.clone(), babe_link.clone()));
					}
				)?;

				let node = sc_service_test::TestNetComponents::new(
					task_manager, client, network, transaction_pool
				);
				Ok((node, (inherent_data_providers, setup_handles.unwrap())))
			},
			|config| {
				let (keep_alive, _, client, network, transaction_pool) = new_light_base(config)?;
				Ok(sc_service_test::TestNetComponents::new(keep_alive, client, network, transaction_pool))
			},
			|service, &mut (ref inherent_data_providers, (ref mut block_import, ref babe_link))| {
				let mut inherent_data = inherent_data_providers
					.create_inherent_data()
					.expect("Creates inherent data.");
				inherent_data.replace_data(sp_finality_tracker::INHERENT_IDENTIFIER, &1u64);

				let parent_id = BlockId::number(service.client().chain_info().best_number);
				let parent_header = service.client().header(&parent_id).unwrap().unwrap();
				let parent_hash = parent_header.hash();
				let parent_number = *parent_header.number();

				futures::executor::block_on(
					service.transaction_pool().maintain(
						ChainEvent::NewBestBlock {
							hash: parent_header.hash(),
							tree_route: None,
						},
					)
				);

				let mut proposer_factory = sc_basic_authorship::ProposerFactory::new(
					service.client(),
					service.transaction_pool(),
					None,
				);

				let epoch_descriptor = babe_link.epoch_changes().lock().epoch_descriptor_for_child_of(
					descendent_query(&*service.client()),
					&parent_hash,
					parent_number,
					slot_num,
				).unwrap().unwrap();

				let mut digest = Digest::<H256>::default();

				// even though there's only one authority some slots might be empty,
				// so we must keep trying the next slots until we can claim one.
				let babe_pre_digest = loop {
					inherent_data.replace_data(sp_timestamp::INHERENT_IDENTIFIER, &(slot_num * SLOT_DURATION));
					if let Some(babe_pre_digest) = sc_consensus_babe::test_helpers::claim_slot(
						slot_num,
						&parent_header,
						&*service.client(),
						&keystore,
						&babe_link,
					) {
						break babe_pre_digest;
					}

					slot_num += 1;
				};

				digest.push(<DigestItem as CompatibleDigestItem>::babe_pre_digest(babe_pre_digest));

				let new_block = futures::executor::block_on(async move {
					let proposer = proposer_factory.init(&parent_header).await;
					proposer.unwrap().propose(
						inherent_data,
						digest,
						std::time::Duration::from_secs(1),
						RecordProof::Yes,
					).await
				}).expect("Error making test block").block;

				let (new_header, new_body) = new_block.deconstruct();
				let pre_hash = new_header.hash();
				// sign the pre-sealed hash of the block and then
				// add it to a digest item.
				let to_sign = pre_hash.encode();
				let signature = alice.sign(&to_sign[..]);
				let item = <DigestItem as CompatibleDigestItem>::babe_seal(
					signature.into(),
				);
				slot_num += 1;

				let mut params = BlockImportParams::new(BlockOrigin::File, new_header);
				params.post_digests.push(item);
				params.body = Some(new_body);
				params.intermediates.insert(
					Cow::from(INTERMEDIATE_KEY),
					Box::new(BabeIntermediate::<Block> { epoch_descriptor }) as Box<dyn Any>,
				);
				params.fork_choice = Some(ForkChoiceStrategy::LongestChain);

				block_import.import_block(params, Default::default())
					.expect("error importing test block");
			},
			|service, _| {
				let amount = 5 * CENTS;
				let to: Address = AccountPublic::from(bob.public()).into_account().into();
				let from: Address = AccountPublic::from(charlie.public()).into_account().into();
				let genesis_hash = service.client().block_hash(0).unwrap().unwrap();
				let best_block_id = BlockId::number(service.client().chain_info().best_number);
				let (spec_version, transaction_version) = {
					let version = service.client().runtime_version_at(&best_block_id).unwrap();
					(version.spec_version, version.transaction_version)
				};
				let signer = charlie.clone();

				let function = Call::Balances(BalancesCall::transfer(to.into(), amount));

				let check_spec_version = frame_system::CheckSpecVersion::new();
				let check_tx_version = frame_system::CheckTxVersion::new();
				let check_genesis = frame_system::CheckGenesis::new();
				let check_era = frame_system::CheckEra::from(Era::Immortal);
				let check_nonce = frame_system::CheckNonce::from(index);
				let check_weight = frame_system::CheckWeight::new();
				let payment = pallet_transaction_payment::ChargeTransactionPayment::from(0);
				let extra = (
					check_spec_version,
					check_tx_version,
					check_genesis,
					check_era,
					check_nonce,
					check_weight,
					payment,
				);
				let raw_payload = SignedPayload::from_raw(
					function,
					extra,
					(spec_version, transaction_version, genesis_hash, genesis_hash, (), (), ())
				);
				let signature = raw_payload.using_encoded(|payload|	{
					signer.sign(payload)
				});
				let (function, extra, _) = raw_payload.deconstruct();
				index += 1;
				UncheckedExtrinsic::new_signed(
					function,
					from.into(),
					signature.into(),
					extra,
				).into()
			},
		);
	}

	#[test]
	#[ignore]
	fn test_consensus() {
		sc_service_test::consensus(
			crate::chain_spec::tests::integration_test_config_with_two_authorities(),
			|config| {
				let NewFullBase { task_manager, client, network, transaction_pool, .. }
					= new_full_base(config,|_, _| ())?;
				Ok(sc_service_test::TestNetComponents::new(task_manager, client, network, transaction_pool))
			},
			|config| {
				let (keep_alive, _, client, network, transaction_pool) = new_light_base(config)?;
				Ok(sc_service_test::TestNetComponents::new(keep_alive, client, network, transaction_pool))
			},
			vec![
				"//Alice".into(),
				"//Bob".into(),
			],
		)
	}
}
