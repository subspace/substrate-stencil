use jsonrpc_pubsub::{PubSubHandler, Session, PubSubMetadata, SubscriptionId, Sink, Subscriber};
use jsonrpc_core::{MetaIoHandler, Middleware, Params, Value};
use jsonrpc_ws_server::{ServerBuilder, RequestContext, Server};
use std::sync::Arc;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use futures::future;
use log::debug;
use crate::{Epoch, SlotNumber};
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SlotInfo {
    pub slot_number: SlotNumber,
    pub epoch_randomness: Vec<u8>,
}

pub struct RpcServer {
    server: Server,
    slot_info_sinks: Arc<Mutex<HashMap<SubscriptionId, Sink>>>,
}

impl RpcServer {
    pub fn new() -> jsonrpc_ws_server::Result<Self> {
        let mut io = PubSubHandler::new(MetaIoHandler::default());
        io.add_sync_method("babe_proposeProofOfSpace", move |_params: Params| {
            Ok(Value::String("TODO".to_string()))
        });
        let slot_info_sinks = add_slot_info_subscriptions::<_, _>(&mut io);

        ServerBuilder::new(io)
            .session_meta_extractor(|context: &RequestContext| {
                Some(Arc::new(Session::new(context.sender())))
            })
            .start(&"127.0.0.1:9945".parse().unwrap())
            .map(|server| {
                Self { server, slot_info_sinks }
            })
    }

    pub fn notify_new_slot(&self, slot_number: SlotNumber, epoch: &Epoch) {
        let params = Params::Array(vec![serde_json::to_value(SlotInfo {
            slot_number,
            epoch_randomness: epoch.randomness.to_vec(),
        }).unwrap()]);
        for sink in self.slot_info_sinks.lock().values() {
            let _ = sink.notify(params.clone());
        }
    }
}

fn add_slot_info_subscriptions<T, S>(
    io: &mut PubSubHandler<T, S>,
) -> Arc<Mutex<HashMap<SubscriptionId, Sink>>>
    where
        T: PubSubMetadata,
        S: Middleware<T>,
{
    let next_subscription_id = Arc::new(AtomicUsize::new(1));
    let sinks = Arc::<Mutex<HashMap<SubscriptionId, Sink>>>::default();
    io.add_subscription(
        "babe_slot_info",
        ("babe_subscribeSlotInfo", {
            let sinks = Arc::clone(&sinks);

            move |_params: Params, _meta, subscriber: Subscriber| {
                debug!("babe_subscribeSlotInfo");
                let sinks = Arc::clone(&sinks);

                let subscription_id = SubscriptionId::Number(
                    next_subscription_id.fetch_add(1, Ordering::SeqCst) as u64,
                );
                let sink = subscriber.assign_id(subscription_id.clone()).unwrap();

                sinks.lock().insert(subscription_id, sink);
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

