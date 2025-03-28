//! Decentralized Hash Table (DHT) implementation for vendor discovery

use crate::core::error::Error;
use crate::models::VendorListing;
use crate::Result;

use libp2p::{
    core::upgrade,
    identity,
    kad::{
        record::store::MemoryStore, Kademlia, KademliaConfig, KademliaEvent, QueryResult, Record,
        RecordKey,
    },
    noise,
    swarm::{NetworkBehaviour, SwarmBuilder, SwarmEvent},
    tcp::TokioTcpConfig,
    yamux, Multiaddr, PeerId, Swarm, Transport,
};
use serde_json;
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

/// Maximum time to wait for DHT operations (in seconds)
const DHT_TIMEOUT_SECS: u64 = 30;

/// Commands that can be sent to the DHT service
#[derive(Debug)]
enum DhtCommand {
    /// Publish a vendor listing to the DHT
    PublishListing {
        listing: VendorListing,
        tags: Vec<String>,
        respond_to: oneshot::Sender<Result<()>>,
    },
    /// Search for vendor listings by tags
    SearchByTags {
        tags: Vec<String>,
        respond_to: oneshot::Sender<Result<Vec<VendorListing>>>,
    },
    /// Search for vendor listings by location
    SearchByLocation {
        latitude: f64,
        longitude: f64,
        max_distance_km: f64,
        respond_to: oneshot::Sender<Result<Vec<VendorListing>>>,
    },
    /// Get a specific vendor listing by vendor public key
    GetListing {
        vendor_public_key: String,
        respond_to: oneshot::Sender<Result<Option<VendorListing>>>,
    },
    /// Shutdown the DHT service
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
    /// Channel to send commands to the DHT service
    command_sender: mpsc::Sender<DhtCommand>,
}

impl DhtService {
    /// Creates a new DHT service and starts the background task
    pub async fn new(bootstrap_addresses: Vec<String>) -> Result<Self> {
        // Create a channel for sending commands to the DHT service
        let (command_sender, command_receiver) = mpsc::channel(100);

        // Convert string addresses to Multiaddr
        let bootstrap_addrs = bootstrap_addresses
            .into_iter()
            .filter_map(|addr| match Multiaddr::from_str(&addr) {
                Ok(addr) => Some(addr),
                Err(err) => {
                    eprintln!("Failed to parse bootstrap address: {}", err);
                    None
                }
            })
            .collect::<Vec<_>>();

        // Start the DHT service in a background task
        tokio::spawn(run_dht_service(command_receiver, bootstrap_addrs));

        Ok(Self { command_sender })
    }

    /// Publishes a vendor listing to the DHT
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

        match timeout(Duration::from_secs(DHT_TIMEOUT_SECS), receiver).await {
            Ok(result) => {
                result.map_err(|_| Error::Dht("DHT service dropped the response channel".into()))?
            }
            Err(_) => Err(Error::Dht("DHT publish operation timed out".into())),
        }
    }

    /// Searches for vendor listings by tags
    pub async fn search_by_tags(&self, tags: Vec<String>) -> Result<Vec<VendorListing>> {
        let (sender, receiver) = oneshot::channel();

        self.command_sender
            .send(DhtCommand::SearchByTags {
                tags,
                respond_to: sender,
            })
            .await
            .map_err(|_| Error::Dht("Failed to send search command".into()))?;

        match timeout(Duration::from_secs(DHT_TIMEOUT_SECS), receiver).await {
            Ok(result) => {
                result.map_err(|_| Error::Dht("DHT service dropped the response channel".into()))?
            }
            Err(_) => Err(Error::Dht("DHT search operation timed out".into())),
        }
    }

    /// Searches for vendor listings by location
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

        match timeout(Duration::from_secs(DHT_TIMEOUT_SECS), receiver).await {
            Ok(result) => {
                result.map_err(|_| Error::Dht("DHT service dropped the response channel".into()))?
            }
            Err(_) => Err(Error::Dht("DHT location search operation timed out".into())),
        }
    }

    /// Gets a specific vendor listing by vendor public key
    pub async fn get_listing(&self, vendor_public_key: String) -> Result<Option<VendorListing>> {
        let (sender, receiver) = oneshot::channel();

        self.command_sender
            .send(DhtCommand::GetListing {
                vendor_public_key,
                respond_to: sender,
            })
            .await
            .map_err(|_| Error::Dht("Failed to send get listing command".into()))?;

        match timeout(Duration::from_secs(DHT_TIMEOUT_SECS), receiver).await {
            Ok(result) => {
                result.map_err(|_| Error::Dht("DHT service dropped the response channel".into()))?
            }
            Err(_) => Err(Error::Dht("DHT get listing operation timed out".into())),
        }
    }

    /// Shuts down the DHT service
    pub async fn shutdown(&self) -> Result<()> {
        let (sender, receiver) = oneshot::channel();

        self.command_sender
            .send(DhtCommand::Shutdown { respond_to: sender })
            .await
            .map_err(|_| Error::Dht("Failed to send shutdown command".into()))?;

        match timeout(Duration::from_secs(DHT_TIMEOUT_SECS), receiver).await {
            Ok(result) => {
                result.map_err(|_| Error::Dht("DHT service dropped the response channel".into()))?
            }
            Err(_) => Err(Error::Dht("DHT shutdown operation timed out".into())),
        }
    }
}

/// Runs the DHT service in a background task
async fn run_dht_service(
    mut command_receiver: mpsc::Receiver<DhtCommand>,
    bootstrap_addrs: Vec<Multiaddr>,
) {
    // Create a random identity for this node
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {}", local_peer_id);

    // Create a transport
    let transport = TokioTcpConfig::new()
        .nodelay(true)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(local_key.clone()).into_authenticated())
        .multiplex(yamux::YamuxConfig::default())
        .boxed();

    // Create a Kademlia behavior
    let store = MemoryStore::new(local_peer_id);
    let mut kademlia_config = KademliaConfig::default();
    kademlia_config.set_query_timeout(Duration::from_secs(DHT_TIMEOUT_SECS));
    let mut kademlia = Kademlia::with_config(local_peer_id, store, kademlia_config);

    // Add bootstrap nodes
    for addr in bootstrap_addrs {
        match addr.iter().last() {
            Some(libp2p::multiaddr::Protocol::P2p(peer_id)) => {
                let peer_id = PeerId::from_bytes(&peer_id).expect("Valid peer ID");
                println!("Adding bootstrap node: {} at {}", peer_id, addr);
                kademlia.add_address(&peer_id, addr.clone());
                kademlia.bootstrap().expect("Bootstrap should succeed");
            }
            _ => {
                eprintln!("Bootstrap address does not contain peer ID: {}", addr);
            }
        }
    }

    // Create a Swarm
    let mut swarm = SwarmBuilder::new(transport, DhtBehaviour { kademlia }, local_peer_id)
        .executor(Box::new(|fut| {
            tokio::spawn(fut);
        }))
        .build();

    // Start listening on a random port
    swarm
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .expect("Swarm should listen on a random port");

    // Bootstrap the DHT
    if !bootstrap_addrs.is_empty() {
        match swarm.behaviour_mut().kademlia.bootstrap() {
            Ok(_) => println!("Bootstrapping DHT..."),
            Err(e) => eprintln!("Failed to bootstrap DHT: {:?}", e),
        }
    }

    // Process commands and events
    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(DhtBehaviourEvent::Kademlia(KademliaEvent::QueryResult { result, .. })) => {
                        match result {
                            QueryResult::GetRecord(Ok(result)) => {
                                println!("Got record: {:?}", result.records);
                            }
                            QueryResult::PutRecord(Ok(_)) => {
                                println!("Successfully put record");
                            }
                            QueryResult::Bootstrap(Ok(_)) => {
                                println!("Bootstrap complete");
                            }
                            e => {
                                println!("Other query result: {:?}", e);
                            }
                        }
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("Listening on {:?}", address);
                    }
                    _ => {}
                }
            }
            cmd = command_receiver.recv() => {
                match cmd {
                    Some(DhtCommand::PublishListing { listing, tags, respond_to }) => {
                        let result = handle_publish_listing(&mut swarm, listing, tags).await;
                        let _ = respond_to.send(result);
                    }
                    Some(DhtCommand::SearchByTags { tags, respond_to }) => {
                        let result = handle_search_by_tags(&mut swarm, tags).await;
                        let _ = respond_to.send(result);
                    }
                    Some(DhtCommand::SearchByLocation { latitude, longitude, max_distance_km, respond_to }) => {
                        let result = handle_search_by_location(&mut swarm, latitude, longitude, max_distance_km).await;
                        let _ = respond_to.send(result);
                    }
                    Some(DhtCommand::GetListing { vendor_public_key, respond_to }) => {
                        let result = handle_get_listing(&mut swarm, vendor_public_key).await;
                        let _ = respond_to.send(result);
                    }
                    Some(DhtCommand::Shutdown { respond_to }) => {
                        let _ = respond_to.send(Ok(()));
                        break;
                    }
                    None => {
                        // Channel closed, exit the loop
                        break;
                    }
                }
            }
        }
    }

    println!("DHT service shut down");
}

/// Handles publishing a vendor listing to the DHT
async fn handle_publish_listing(
    swarm: &mut Swarm<DhtBehaviour>,
    listing: VendorListing,
    tags: Vec<String>,
) -> Result<()> {
    // Serialize the listing to JSON
    let listing_json = serde_json::to_vec(&listing).map_err(|e| Error::Serialization(e))?;

    // Store the listing under the vendor's public key
    let vendor_key = RecordKey::new(&listing.vendor_identity_key_public);
    let vendor_record = Record {
        key: vendor_key,
        value: listing_json.clone(),
        publisher: None,
        expires: None,
    };

    // Put the record in the DHT
    swarm
        .behaviour_mut()
        .kademlia
        .put_record(vendor_record, libp2p::kad::Quorum::One)
        .map_err(|e| Error::Dht(format!("Failed to put vendor record: {:?}", e)))?;

    // Also store the listing under each tag for searchability
    for tag in tags {
        let tag_key = RecordKey::new(&format!("tag:{}", tag));
        let tag_record = Record {
            key: tag_key,
            value: listing_json.clone(),
            publisher: None,
            expires: None,
        };

        swarm
            .behaviour_mut()
            .kademlia
            .put_record(tag_record, libp2p::kad::Quorum::One)
            .map_err(|e| Error::Dht(format!("Failed to put tag record: {:?}", e)))?;
    }

    // If the listing has a location, store it for location-based search
    if let Some(location) = &listing.location {
        // Create a geohash-like key for the location
        // This is a simplified approach - in a production system, you'd use a proper geohash
        let lat_lon_key = format!(
            "location:{}:{}",
            (location.latitude * 10.0).round() / 10.0,
            (location.longitude * 10.0).round() / 10.0
        );

        let location_key = RecordKey::new(&lat_lon_key);
        let location_record = Record {
            key: location_key,
            value: listing_json.clone(),
            publisher: None,
            expires: None,
        };

        swarm
            .behaviour_mut()
            .kademlia
            .put_record(location_record, libp2p::kad::Quorum::One)
            .map_err(|e| Error::Dht(format!("Failed to put location record: {:?}", e)))?;
    }

    Ok(())
}

/// Handles searching for vendor listings by tags
async fn handle_search_by_tags(
    swarm: &mut Swarm<DhtBehaviour>,
    tags: Vec<String>,
) -> Result<Vec<VendorListing>> {
    let mut listings = HashMap::new();

    // Search for each tag
    for tag in tags {
        let tag_key = RecordKey::new(&format!("tag:{}", tag));

        // Get records for this tag
        swarm.behaviour_mut().kademlia.get_record(&tag_key);

        // Wait for results (simplified - in a real implementation, you'd collect results properly)
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Check if we got any records
        if let Some(records) = swarm.behaviour_mut().kademlia.store_mut().get(&tag_key) {
            for record in records {
                // Deserialize the listing
                if let Ok(listing) = serde_json::from_slice::<VendorListing>(&record.value) {
                    // Use the vendor's public key as a unique identifier
                    listings.insert(listing.vendor_identity_key_public.clone(), listing);
                }
            }
        }
    }

    // Convert the HashMap values to a Vec
    Ok(listings.into_values().collect())
}

/// Handles searching for vendor listings by location
async fn handle_search_by_location(
    swarm: &mut Swarm<DhtBehaviour>,
    latitude: f64,
    longitude: f64,
    max_distance_km: f64,
) -> Result<Vec<VendorListing>> {
    let mut listings = HashMap::new();

    // Create a simplified grid search around the target location
    // In a production system, you'd use a proper geohash or spatial index
    let lat_step = 0.1; // Approximately 11km at the equator
    let lon_step = 0.1; // Varies with latitude

    let lat_range = (max_distance_km / 111.0).min(1.0); // 111km per degree of latitude
    let lon_range =
        (max_distance_km / (111.0 * (latitude * std::f64::consts::PI / 180.0).cos())).min(1.0);

    let lat_min = ((latitude - lat_range) / lat_step).floor() * lat_step;
    let lat_max = ((latitude + lat_range) / lat_step).ceil() * lat_step;
    let lon_min = ((longitude - lon_range) / lon_step).floor() * lon_step;
    let lon_max = ((longitude + lon_range) / lon_step).ceil() * lon_step;

    // Search for listings in each grid cell
    let mut lat = lat_min;
    while lat <= lat_max {
        let mut lon = lon_min;
        while lon <= lon_max {
            let lat_lon_key = format!("location:{}:{}", lat, lon);
            let location_key = RecordKey::new(&lat_lon_key);

            // Get records for this location
            swarm.behaviour_mut().kademlia.get_record(&location_key);

            // Wait for results (simplified)
            tokio::time::sleep(Duration::from_secs(2)).await;

            // Check if we got any records
            if let Some(records) = swarm
                .behaviour_mut()
                .kademlia
                .store_mut()
                .get(&location_key)
            {
                for record in records {
                    // Deserialize the listing
                    if let Ok(listing) = serde_json::from_slice::<VendorListing>(&record.value) {
                        // Check if the listing has a location
                        if let Some(listing_location) = &listing.location {
                            // Calculate the distance
                            let from = crate::models::Location::new(latitude, longitude);
                            let to = crate::models::Location::new(
                                listing_location.latitude,
                                listing_location.longitude,
                            );
                            let distance = from.distance_to(&to);

                            // Only include listings within the maximum distance
                            if distance <= max_distance_km {
                                listings
                                    .insert(listing.vendor_identity_key_public.clone(), listing);
                            }
                        }
                    }
                }
            }

            lon += lon_step;
        }
        lat += lat_step;
    }

    // Convert the HashMap values to a Vec
    Ok(listings.into_values().collect())
}

/// Handles getting a specific vendor listing by vendor public key
async fn handle_get_listing(
    swarm: &mut Swarm<DhtBehaviour>,
    vendor_public_key: String,
) -> Result<Option<VendorListing>> {
    let vendor_key = RecordKey::new(&vendor_public_key);

    // Get the record for this vendor
    swarm.behaviour_mut().kademlia.get_record(&vendor_key);

    // Wait for results (simplified)
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Check if we got the record
    if let Some(records) = swarm.behaviour_mut().kademlia.store_mut().get(&vendor_key) {
        if let Some(record) = records.first() {
            // Deserialize the listing
            return match serde_json::from_slice::<VendorListing>(&record.value) {
                Ok(listing) => Ok(Some(listing)),
                Err(e) => Err(Error::Serialization(e)),
            };
        }
    }

    Ok(None)
}

/// DHT client for vendor discovery and listing publication
pub struct DhtClient {
    /// The DHT service
    service: DhtService,
}

impl DhtClient {
    /// Creates a new DHT client
    pub async fn new(bootstrap_addresses: Vec<String>) -> Result<Self> {
        let service = DhtService::new(bootstrap_addresses).await?;
        Ok(Self { service })
    }

    /// Publishes a vendor listing to the DHT
    pub async fn publish_listing(&self, listing: VendorListing) -> Result<()> {
        // Extract tags from the listing items
        let mut tags = Vec::new();
        for item in &listing.items_offered {
            tags.extend(item.tags.clone());
        }

        // Add payment methods as tags
        for method in &listing.payment_methods_accepted {
            tags.push(format!("payment:{}", method));
        }

        // Add vendor name as a tag if available
        if let Some(name) = &listing.vendor_name {
            tags.push(format!("vendor:{}", name));
        }

        // Deduplicate tags
        tags.sort();
        tags.dedup();

        self.service.publish_listing(listing, tags).await
    }

    /// Searches for vendor listings by tags
    pub async fn search_by_tags(&self, tags: Vec<String>) -> Result<Vec<VendorListing>> {
        self.service.search_by_tags(tags).await
    }

    /// Searches for vendor listings by location
    pub async fn search_by_location(
        &self,
        latitude: f64,
        longitude: f64,
        max_distance_km: f64,
    ) -> Result<Vec<VendorListing>> {
        self.service
            .search_by_location(latitude, longitude, max_distance_km)
            .await
    }

    /// Gets a specific vendor listing by vendor public key
    pub async fn get_listing(&self, vendor_public_key: String) -> Result<Option<VendorListing>> {
        self.service.get_listing(vendor_public_key).await
    }

    /// Shuts down the DHT client
    pub async fn shutdown(&self) -> Result<()> {
        self.service.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Item, Location};
    use tokio::runtime::Runtime;

    // These tests require a running DHT network to connect to
    // For local testing, you can use a mock or run a local DHT node

    #[test]
    #[ignore] // Ignore by default as it requires a network
    fn test_dht_client() {
        let rt = Runtime::new().unwrap();

        rt.block_on(async {
            // Create a DHT client with some bootstrap nodes
            // In a real test, you'd use actual bootstrap nodes or a local test network
            let bootstrap_addresses = vec![
                "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ"
                    .to_string(),
            ];

            let client = DhtClient::new(bootstrap_addresses).await.unwrap();

            // Create a test vendor listing
            let item = Item::new("item-123".to_string(), "Test Item".to_string())
                .with_description("A test item".to_string())
                .with_price("10.99".to_string())
                .with_availability("In Stock".to_string())
                .with_tags(vec!["test".to_string(), "example".to_string()]);

            let vendor_location = Location::new(40.7128, -74.0060); // New York City

            let listing = VendorListing::new(
                "test_vendor_key_123".to_string(),
                vec![item],
                vec!["BTC".to_string(), "ETH".to_string()],
                chrono::Utc::now().timestamp() as u64,
                "test_signature".to_string(),
            )
            .with_vendor_name("Test Vendor".to_string())
            .with_location(vendor_location)
            .with_service_terms("Terms and conditions apply".to_string());

            // Publish the listing
            client.publish_listing(listing.clone()).await.unwrap();

            // Search for the listing by tags
            let results = client
                .search_by_tags(vec!["test".to_string()])
                .await
                .unwrap();
            assert!(!results.is_empty());

            // Search for the listing by location
            let results = client
                .search_by_location(40.7128, -74.0060, 10.0)
                .await
                .unwrap();
            assert!(!results.is_empty());

            // Get the listing by vendor public key
            let result = client
                .get_listing("test_vendor_key_123".to_string())
                .await
                .unwrap();
            assert!(result.is_some());

            // Shutdown the client
            client.shutdown().await.unwrap();
        });
    }
}
