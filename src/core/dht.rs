//! Decentralized Hash Table (DHT) implementation for vendor discovery

use crate::core::error::Error;
use crate::models::VendorListing;
use crate::Result;

use libp2p::kad::behaviour::{Kademlia, KademliaEvent};
use libp2p::{
    kad::{store::MemoryStore, QueryId, QueryResult, Record},
    swarm::SwarmEvent,
    tcp::Config as TokioTcpConfig,
    Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use serde_json;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

/// Maximum time to wait for DHT operations (in seconds)
const DHT_TIMEOUT_SECS: u64 = 30;

/// Commands that can be sent to the DHT service
#[derive(Debug)]
enum DhtCommand {
    PublishListing {
        listing: VendorListing,
        tags: Vec<String>,
        respond_to: oneshot::Sender<Result<()>>,
    },
    SearchByTags {
        tags: Vec<String>,
        respond_to: oneshot::Sender<Result<Vec<VendorListing>>>,
    },
    SearchByLocation {
        latitude: f64,
        longitude: f64,
        max_distance_km: f64,
        respond_to: oneshot::Sender<Result<Vec<VendorListing>>>,
    },
    GetListing {
        vendor_public_key: String,
        respond_to: oneshot::Sender<Result<Option<VendorListing>>>,
    },
    Shutdown {
        respond_to: oneshot::Sender<Result<()>>,
    },
}

/// Network behavior combining Kademlia DHT
#[derive(NetworkBehaviour)]
struct DhtBehaviour {
    kademlia: Kademlia<MemoryStore>,
}

/// DHT service for vendor discovery and listing publication
pub struct DhtService {
    command_sender: mpsc::Sender<DhtCommand>,
}

impl DhtService {
    pub async fn new(bootstrap_addresses: Vec<String>) -> Result<Self> {
        let (command_sender, command_receiver) = mpsc::channel(100);

        let bootstrap_addrs = bootstrap_addresses
            .into_iter()
            .filter_map(|addr| Multiaddr::from_str(&addr).ok())
            .collect::<Vec<_>>();

        tokio::spawn(run_dht_service(command_receiver, bootstrap_addrs));

        Ok(Self { command_sender })
    }

    pub async fn publish_listing(&self, listing: VendorListing, tags: Vec<String>) -> Result<()> {
        let (sender, receiver) = oneshot::channel();

        self.command_sender
            .send(DhtCommand::PublishListing {
                listing,
                tags,
                respond_to: sender,
            })
            .await
            .map_err(|_| Error::Dht("Failed to send publish command".into()))?;

        receive_response(receiver).await
    }

    pub async fn search_by_tags(&self, tags: Vec<String>) -> Result<Vec<VendorListing>> {
        let (sender, receiver) = oneshot::channel();

        self.command_sender
            .send(DhtCommand::SearchByTags {
                tags,
                respond_to: sender,
            })
            .await
            .map_err(|_| Error::Dht("Failed to send search command".into()))?;

        receive_response(receiver).await
    }

    pub async fn search_by_location(
        &self,
        latitude: f64,
        longitude: f64,
        max_distance_km: f64,
    ) -> Result<Vec<VendorListing>> {
        let (sender, receiver) = oneshot::channel();

        self.command_sender
            .send(DhtCommand::SearchByLocation {
                latitude,
                longitude,
                max_distance_km,
                respond_to: sender,
            })
            .await
            .map_err(|_| Error::Dht("Failed to send location search command".into()))?;

        receive_response(receiver).await
    }

    pub async fn get_listing(&self, vendor_public_key: String) -> Result<Option<VendorListing>> {
        let (sender, receiver) = oneshot::channel();

        self.command_sender
            .send(DhtCommand::GetListing {
                vendor_public_key,
                respond_to: sender,
            })
            .await
            .map_err(|_| Error::Dht("Failed to send get listing command".into()))?;

        receive_response(receiver).await
    }

    pub async fn shutdown(&self) -> Result<()> {
        let (sender, receiver) = oneshot::channel();

        self.command_sender
            .send(DhtCommand::Shutdown { respond_to: sender })
            .await
            .map_err(|_| Error::Dht("Failed to send shutdown command".into()))?;

        receive_response(receiver).await
    }
}

async fn receive_response<T>(receiver: oneshot::Receiver<Result<T>>) -> Result<T> {
    match timeout(Duration::from_secs(DHT_TIMEOUT_SECS), receiver).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(Error::Dht("Response channel closed".into())),
        Err(_) => Err(Error::Dht("Operation timed out".into())),
    }
}

async fn run_dht_service(
    mut command_receiver: mpsc::Receiver<DhtCommand>,
    bootstrap_addrs: Vec<Multiaddr>,
) {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {}", local_peer_id);

    let transport = TokioTcpConfig::new()
        .nodelay(true)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(local_key.clone()).into_authenticated())
        .multiplex(yamux::YamuxConfig::default())
        .boxed();

    let store = MemoryStore::new(local_peer_id);
    let mut kademlia = Kademlia::new(local_peer_id, store);
    let mut pending_queries = HashMap::new();

    for addr in &bootstrap_addrs {
        if let Some(peer_id) = addr.iter().last() {
            if let libp2p::multiaddr::Protocol::P2p(multihash) = peer_id {
                if let Ok(peer_id) = PeerId::from_multihash(multihash.clone()) {
                    kademlia.add_address(&peer_id, addr.clone());
                }
            }
        }
    }

    let mut swarm =
        SwarmBuilder::with_tokio_executor(transport, DhtBehaviour { kademlia }, local_peer_id)
            .build();

    swarm
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .expect("Should listen");

    if !bootstrap_addrs.is_empty() {
        if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
            eprintln!("Failed to bootstrap: {:?}", e);
        }
    }

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                handle_swarm_event(event, &mut swarm, &mut pending_queries);
            },
            cmd = command_receiver.recv() => {
                if let Some(cmd) = cmd {
                    handle_command(cmd, &mut swarm, &mut pending_queries).await;
                } else {
                    break;
                }
            }
        }
    }
    println!("DHT service shut down");
}

fn handle_swarm_event(
    event: SwarmEvent<libp2p::kad::KademliaEvent>,
    swarm: &mut Swarm<DhtBehaviour>,
    pending_queries: &mut HashMap<QueryId, oneshot::Sender<QueryResult>>,
) {
    match event {
        SwarmEvent::Behaviour(DhtBehaviourEvent::Kademlia(
            KademliaEvent::OutboundQueryProgressed { id, result, .. },
        )) => {
            if let Some(sender) = pending_queries.remove(&id) {
                let _ = sender.send(result);
            }
        }
        SwarmEvent::NewListenAddr { address, .. } => {
            println!("Listening on {}", address);
        }
        SwarmEvent::Behaviour(DhtBehaviourEvent::Kademlia(event)) => {
            println!("Unhandled Kademlia event: {:?}", event);
        }
        _ => {}
    }
}

async fn handle_command(
    cmd: DhtCommand,
    swarm: &mut Swarm<DhtBehaviour>,
    pending_queries: &mut HashMap<QueryId, oneshot::Sender<QueryResult>>,
) {
    match cmd {
        DhtCommand::PublishListing {
            listing,
            tags,
            respond_to,
        } => {
            let result = handle_publish_listing(swarm, listing, tags).await;
            let _ = respond_to.send(result);
        }
        DhtCommand::SearchByTags { tags, respond_to } => {
            let result = handle_search_by_tags(swarm, tags, pending_queries).await;
            let _ = respond_to.send(result);
        }
        DhtCommand::SearchByLocation {
            latitude,
            longitude,
            max_distance_km,
            respond_to,
        } => {
            let result = handle_search_by_location(
                swarm,
                latitude,
                longitude,
                max_distance_km,
                pending_queries,
            )
            .await;
            let _ = respond_to.send(result);
        }
        DhtCommand::GetListing {
            vendor_public_key,
            respond_to,
        } => {
            let result = handle_get_listing(swarm, vendor_public_key, pending_queries).await;
            let _ = respond_to.send(result);
        }
        DhtCommand::Shutdown { respond_to } => {
            let _ = respond_to.send(Ok(()));
        }
    }
}

async fn handle_publish_listing(
    swarm: &mut Swarm<DhtBehaviour>,
    listing: VendorListing,
    tags: Vec<String>,
) -> Result<()> {
    let listing_json = serde_json::to_vec(&listing).map_err(Error::Serialization)?;
    let vendor_key = RecordKey::new(&listing.vendor_identity_key_public);

    let record = Record {
        key: vendor_key,
        value: listing_json.clone(),
        publisher: None,
        expires: None,
    };

    swarm.behaviour_mut().kademlia.put_record(record)?;

    for tag in tags {
        let tag_key = RecordKey::new(&format!("tag:{}", tag));
        let tag_record = Record {
            key: tag_key,
            value: listing_json.clone(),
            publisher: None,
            expires: None,
        };
        swarm.behaviour_mut().kademlia.put_record(tag_record)?;
    }

    if let Some(location) = &listing.location {
        let lat_lon_key = format!(
            "location:{}:{}",
            (location.latitude * 10.0).round() / 10.0,
            (location.longitude * 10.0).round() / 10.0
        );
        let location_key = RecordKey::new(&lat_lon_key);
        let location_record = Record {
            key: location_key,
            value: listing_json,
            publisher: None,
            expires: None,
        };
        swarm.behaviour_mut().kademlia.put_record(location_record)?;
    }

    Ok(())
}

async fn handle_search_by_tags(
    swarm: &mut Swarm<DhtBehaviour>,
    tags: Vec<String>,
    pending_queries: &mut HashMap<QueryId, oneshot::Sender<QueryResult>>,
) -> Result<Vec<VendorListing>> {
    let mut listings = HashSet::new();
    let (sender, receiver) = mpsc::channel(10);

    for tag in tags {
        let tag_key = RecordKey::new(&format!("tag:{}", tag));
        let query_id = swarm.behaviour_mut().kademlia.get_record(tag_key);
        pending_queries.insert(query_id, sender.clone());
    }

    let mut results = Vec::new();
    let mut receiver = Some(receiver);

    while let Some(result) = receiver.as_mut().unwrap().recv().await {
        if let QueryResult::GetRecord(Ok(get_record)) = result {
            for record in get_record.records {
                if let Ok(listing) = serde_json::from_slice::<VendorListing>(&record.value) {
                    listings.insert(listing);
                }
            }
        }
    }

    results.extend(listings.into_iter());
    Ok(results)
}

// Other handler functions (handle_search_by_location, handle_get_listing) would follow similar patterns

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::Multiaddr;

    #[tokio::test]
    async fn test_dht_basic_operations() {
        let _ = env_logger::try_init();

        let node1 = DhtService::new(vec![]).await.unwrap();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

        // Test code would continue with creating listings and testing operations
    }
}
