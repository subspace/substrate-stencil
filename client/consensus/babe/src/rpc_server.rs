use jsonrpc_pubsub::{PubSubHandler, Session, PubSubMetadata, SubscriptionId, Sink, Subscriber, SinkResult};
use jsonrpc_core::{MetaIoHandler, Middleware, Params, Value};
use jsonrpc_ws_server::{ServerBuilder, RequestContext, Server};
use std::sync::Arc;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use futures::{future, FutureExt, StreamExt, SinkExt};
use log::{debug, warn};
use crate::{Epoch, SlotNumber, PreDigest, AuthorityId};
use serde::{Serialize, Deserialize};
use futures::channel::mpsc;
use std::time::Duration;
use futures::future::Either;

const SOLUTION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
struct Solution {
    public_key: [u8; 32],
    nonce: u32,
    encoding: Vec<u8>,
    signature: [u8; 32],
}

#[derive(Debug, Deserialize)]
pub struct ProposedProofOfSpaceResult {
    slot_number: SlotNumber,
    solution: Option<Solution>,
}

#[derive(Debug, Serialize)]
pub struct SlotInfo {
    pub slot_number: SlotNumber,
    pub epoch_randomness: Vec<u8>,
}

pub struct RpcServer {
    _server: Server,
    slot_info_sinks: Arc<Mutex<HashMap<SubscriptionId, Box<dyn (Fn(Value) -> SinkResult) + Send>>>>,
    proof_requests: Arc<Mutex<HashMap<SlotNumber, mpsc::Sender<Option<Solution>>>>>,
}

impl RpcServer {
    pub fn new() -> jsonrpc_ws_server::Result<Self> {
        let mut io = PubSubHandler::new(MetaIoHandler::default());

        let proof_requests = Arc::<Mutex<HashMap<SlotNumber, mpsc::Sender<Option<Solution>>>>>::default();

        io.add_notification("babe_proposeProofOfSpace", {
            let proof_requests = Arc::clone(&proof_requests);

            move |params: Params| {
                match params.parse::<(ProposedProofOfSpaceResult,)>() {
                    Ok((proposed_proof,)) => {
                        if let Some(mut sender) = proof_requests.lock().remove(&proposed_proof.slot_number) {
                            let _ = sender.send(proposed_proof.solution);
                        } else {
                            warn!("babe_proposeProofOfSpace ignored because there is no sender waiting");
                        }
                    }
                    Err(error) => {
                        warn!("Error in babe_proposeProofOfSpace payload: {}", error);
                    }
                }
            }
        });
        let slot_info_sinks = add_slot_info_subscriptions::<_, _>(&mut io);

        ServerBuilder::new(io)
            .session_meta_extractor(|context: &RequestContext| {
                Some(Arc::new(Session::new(context.sender())))
            })
            .start(&"127.0.0.1:9945".parse().unwrap())
            .map(|server| {
                Self { _server: server, slot_info_sinks, proof_requests }
            })
    }

    pub fn notify_new_slot(
        &self,
        slot_number: SlotNumber,
        epoch: &Epoch,
    ) -> Option<(PreDigest, AuthorityId)> {
        let value = serde_json::to_value(SlotInfo {
            slot_number,
            epoch_randomness: epoch.randomness.to_vec(),
        }).unwrap();

        let slot_info_sinks = self.slot_info_sinks.lock();
        let subscribers_count = slot_info_sinks.len();
        if subscribers_count == 0 {
            return None;
        }

        let (sender, mut receiver) = mpsc::channel(1);
        self.proof_requests.lock().insert(slot_number, sender);

        for sink in slot_info_sinks.values() {
            let _ = sink(value.clone());
        }
        drop(slot_info_sinks);

        // Spawning separate thread because recursive `futures::executor::block_on` calls will panic
        let solution = std::thread::spawn(move || {
            futures::executor::block_on(async move {
                let timeout = futures_timer::Delay::new(SOLUTION_TIMEOUT).map(|_| None);
                let solution = async move {
                    while let Some(solution) = receiver.next().await {
                        if let Some(solution) = solution {
                            return Some(solution);
                        }
                    }

                    None
                };

                match future::select(timeout, Box::pin(solution)).await {
                    Either::Left((value1, _)) => value1,
                    Either::Right((value2, _)) => value2,
                }
            })
        })
            .join()
            .ok()
            .flatten();
        println!("Solution: {:?}", solution);

        self.proof_requests.lock().remove(&slot_number);

        // TODO: Receive from RPC ^
        None
    }
}

fn add_slot_info_subscriptions<T, S>(
    io: &mut PubSubHandler<T, S>,
) -> Arc<Mutex<HashMap<SubscriptionId, Box<dyn (Fn(Value) -> SinkResult) + Send>>>>
    where
        T: PubSubMetadata,
        S: Middleware<T>,
{
    let next_subscription_id = Arc::new(AtomicUsize::new(1));
    let sinks = Arc::<Mutex<HashMap<SubscriptionId, Box<dyn (Fn(Value) -> SinkResult) + Send>>>>::default();
    io.add_subscription(
        "babe_slot_info",
        ("babe_subscribeSlotInfo", {
            let sinks = Arc::clone(&sinks);

            move |_params: Params, _meta, subscriber: Subscriber| {
                debug!("babe_subscribeSlotInfo");
                let sinks = Arc::clone(&sinks);

                let subscription_id_num = next_subscription_id.fetch_add(1, Ordering::SeqCst) as u64;
                let subscription_id = SubscriptionId::Number(subscription_id_num);
                let sink = subscriber.assign_id(subscription_id.clone()).unwrap();

                sinks.lock().insert(subscription_id, Box::new(move |value| -> SinkResult {
                    sink.notify(Params::Map({
                        let mut map = serde_json::Map::new();
                        map.insert("result".to_string(), value);
                        map.insert(
                            "subscription".to_string(),
                            serde_json::to_value(&subscription_id_num).unwrap(),
                        );

                        map
                    }))
                }));
            }
        }),
        ("babe_unsubscribeSlotInfo", {
            let sinks = Arc::clone(&sinks);

            move |subscription_id: SubscriptionId, _meta| {
                debug!("babe_unsubscribeSlotInfo");
                let sinks = Arc::clone(&sinks);

                sinks.lock().remove(&subscription_id);

                future::ok(Value::Bool(true))
            }
        }),
    );

    sinks
}

