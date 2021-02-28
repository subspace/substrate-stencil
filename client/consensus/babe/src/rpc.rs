use jsonrpc_pubsub::{PubSubHandler, Session, PubSubMetadata, SubscriptionId, Sink, Subscriber};
use jsonrpc_core::{MetaIoHandler, Middleware, Params, Value};
use jsonrpc_ws_server::{ServerBuilder, RequestContext, Server};
use std::sync::Arc;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use futures::{future, StreamExt};
use log::debug;
use futures::channel::mpsc::{Sender, channel};
use sc_consensus_epochs::ViableEpochDescriptor;
use sp_api::NumberFor;
use crate::Epoch;
use sp_runtime::traits::Block as BlockT;
use serde::{Serialize, Deserialize};
use codec::Encode;

#[derive(Debug, Serialize, Deserialize)]
pub struct SlotInfo {
    pub slot_number: u64,
    pub epoch_randomness: Vec<u8>,
}

pub struct RpcServer {
    server: Server,
}

impl RpcServer {
    pub fn new<B>(
        slot_notification_sinks: Arc<Mutex<Vec<Sender<(u64, ViableEpochDescriptor<B::Hash, NumberFor<B>, Epoch>)>>>>,
    ) -> jsonrpc_ws_server::Result<Self>
        where
            B: BlockT,
    {
        let mut io = PubSubHandler::new(MetaIoHandler::default());
        io.add_sync_method("babe_proposeProofOfSpace", move |_params: Params| {
            Ok(Value::String("TODO".to_string()))
        });
        add_subscriptions::<_, _, B>(&mut io, slot_notification_sinks);

        ServerBuilder::new(io)
            .session_meta_extractor(|context: &RequestContext| {
                Some(Arc::new(Session::new(context.sender())))
            })
            .start(&"127.0.0.1:9945".parse().unwrap())
            .map(|server| {
                Self { server }
            })
    }
}

fn add_subscriptions<T, S, B>(
    io: &mut PubSubHandler<T, S>,
    slot_notification_sinks: Arc<Mutex<Vec<Sender<(u64, ViableEpochDescriptor<B::Hash, NumberFor<B>, Epoch>)>>>>,
)
    where
        T: PubSubMetadata,
        S: Middleware<T>,
        B: BlockT,
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

    std::thread::spawn(move || {
        futures::executor::block_on(async move {
            const CHANNEL_BUFFER_SIZE: usize = 1024;

            let (sink, mut stream) = channel(CHANNEL_BUFFER_SIZE);
            slot_notification_sinks.lock().push(sink);

            while let Some((slot_number, epoch)) = stream.next().await {
                if let ViableEpochDescriptor::Signaled(identifier, _header) = epoch {
                    let params = Params::Array(vec![serde_json::to_value(SlotInfo {
                        slot_number,
                        epoch_randomness: identifier.hash.encode(),
                    }).unwrap()]);
                    for sink in sinks.lock().values() {
                        let _ = sink.notify(params.clone());
                    }
                }
            }
        });
    });
}

