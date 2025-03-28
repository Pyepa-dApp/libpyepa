//! Peer discovery mechanisms

use crate::core::error::Error;
use crate::network::peer::{PeerInfo, PeerManager};
use crate::Result;

use libp2p::{
    core::Multiaddr,
    identity,
    kad::{
        record::store::MemoryStore, GetClosestPeersOk, Kademlia, KademliaConfig, KademliaEvent,
        QueryResult,
    },
    mdns::{Mdns, MdnsConfig, MdnsEvent},
    swarm::{NetworkBehaviour, NetworkBehaviourEventProcess},
    PeerId,
};
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Discovery configuration
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Whether to enable mDNS discovery
    pub enable_mdns: bool,
    /// Whether to enable Kademlia discovery
    pub enable_kademlia: bool,
    /// Bootstrap nodes for Kademlia
    pub bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
    /// Discovery interval in seconds
    pub discovery_interval: u64,
    /// Maximum number of peers to discover
    pub max_peers: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enable_mdns: true,
            enable_kademlia: true,
            bootstrap_nodes: Vec::new(),
            discovery_interval: 300, // 5 minutes
            max_peers: 100,
        }
    }
}

/// Discovery event
#[derive(Debug)]
pub enum DiscoveryEvent {
    /// Peer discovered
    PeerDiscovered {
        /// The discovered peer
        peer_id: PeerId,
        /// The address of the peer
        addr: Option<Multiaddr>,
    },
    /// Bootstrap completed
    BootstrapCompleted,
}

/// Combined discovery behaviour
#[derive(NetworkBehaviour)]
#[behaviour(event_process = true)]
pub struct DiscoveryBehaviour {
    /// Kademlia DHT for peer discovery
    #[behaviour(ignore)]
    kademlia: Option<Kademlia<MemoryStore>>,
    /// mDNS for local peer discovery
    #[behaviour(ignore)]
    mdns: Option<Mdns>,
    /// Peer manager
    #[behaviour(ignore)]
    peer_manager: PeerManager,
    /// Last discovery time
    #[behaviour(ignore)]
    last_discovery: Instant,
    /// Discovery interval
    #[behaviour(ignore)]
    discovery_interval: Duration,
    /// Maximum number of peers to discover
    #[behaviour(ignore)]
    max_peers: usize,
    /// Discovered peers
    #[behaviour(ignore)]
    discovered_peers: HashSet<PeerId>,
}

impl DiscoveryBehaviour {
    /// Creates a new DiscoveryBehaviour
    pub async fn new(
        local_peer_id: PeerId,
        config: DiscoveryConfig,
        peer_manager: PeerManager,
    ) -> Result<Self> {
        let mut kademlia = None;
        let mut mdns = None;

        // Initialize Kademlia if enabled
        if config.enable_kademlia {
            let store = MemoryStore::new(local_peer_id);
            let mut kad_config = KademliaConfig::default();
            kad_config.set_query_timeout(Duration::from_secs(60));

            let mut kad = Kademlia::with_config(local_peer_id, store, kad_config);

            // Add bootstrap nodes
            for (peer_id, addr) in &config.bootstrap_nodes {
                kad.add_address(peer_id, addr.clone());
            }

            kademlia = Some(kad);
        }

        // Initialize mDNS if enabled
        if config.enable_mdns {
            mdns = Some(
                Mdns::new(MdnsConfig::default())
                    .await
                    .map_err(|e| Error::Network(format!("Failed to create mDNS: {}", e)))?,
            );
        }

        Ok(Self {
            kademlia,
            mdns,
            peer_manager,
            last_discovery: Instant::now(),
            discovery_interval: Duration::from_secs(config.discovery_interval),
            max_peers: config.max_peers,
            discovered_peers: HashSet::new(),
        })
    }

    /// Bootstraps the Kademlia DHT
    pub fn bootstrap(&mut self) -> Result<()> {
        if let Some(kad) = &mut self.kademlia {
            kad.bootstrap()
                .map_err(|e| Error::Network(format!("Failed to bootstrap Kademlia: {}", e)))?;
        }

        Ok(())
    }

    /// Starts peer discovery
    pub fn start_discovery(&mut self) -> Result<()> {
        if let Some(kad) = &mut self.kademlia {
            // Get closest peers to a random peer ID
            let random_peer_id = PeerId::random();
            kad.get_closest_peers(random_peer_id);
        }

        self.last_discovery = Instant::now();
        Ok(())
    }

    /// Adds a peer to the discovery system
    pub fn add_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        if let Some(kad) = &mut self.kademlia {
            kad.add_address(&peer_id, addr.clone());
        }

        self.discovered_peers.insert(peer_id);

        // Add to peer manager
        self.peer_manager.add_or_update_peer(peer_id, Some(addr));
    }

    /// Gets the number of discovered peers
    pub fn discovered_count(&self) -> usize {
        self.discovered_peers.len()
    }

    /// Checks if discovery should be performed
    pub fn should_discover(&self) -> bool {
        // Check if we've reached the maximum number of peers
        if self.peer_manager.total_count() >= self.max_peers {
            return false;
        }

        // Check if it's time to discover again
        Instant::now().duration_since(self.last_discovery) >= self.discovery_interval
    }
}

impl NetworkBehaviourEventProcess<MdnsEvent> for DiscoveryBehaviour {
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(peers) => {
                for (peer_id, addr) in peers {
                    if !self.discovered_peers.contains(&peer_id) {
                        self.discovered_peers.insert(peer_id);

                        // Add to peer manager
                        self.peer_manager
                            .add_or_update_peer(peer_id, Some(addr.clone()));

                        // Add to Kademlia if enabled
                        if let Some(kad) = &mut self.kademlia {
                            kad.add_address(&peer_id, addr.clone());
                        }
                    }
                }
            }
            MdnsEvent::Expired(peers) => {
                for (peer_id, _) in peers {
                    // We don't remove from discovered_peers here because the peer
                    // might still be reachable through other means

                    // Update peer manager
                    if let Some(peer) = self.peer_manager.get_peer_mut(&peer_id) {
                        // Only mark as disconnected if this was an mDNS-only peer
                        if peer.addresses.len() <= 1 {
                            self.peer_manager.mark_disconnected(&peer_id);
                        }
                    }
                }
            }
        }
    }
}

impl NetworkBehaviourEventProcess<KademliaEvent> for DiscoveryBehaviour {
    fn inject_event(&mut self, event: KademliaEvent) {
        match event {
            KademliaEvent::RoutingUpdated { peer, .. } => {
                if !self.discovered_peers.contains(&peer) {
                    self.discovered_peers.insert(peer);

                    // Add to peer manager
                    self.peer_manager.add_or_update_peer(peer, None);
                }
            }
            KademliaEvent::OutboundQueryCompleted { result, .. } => {
                match result {
                    QueryResult::Bootstrap(Ok(_)) => {
                        log::info!("Kademlia bootstrap completed");
                    }
                    QueryResult::GetClosestPeers(Ok(GetClosestPeersOk { peers, .. })) => {
                        for peer in peers {
                            if !self.discovered_peers.contains(&peer) {
                                self.discovered_peers.insert(peer);

                                // Add to peer manager
                                self.peer_manager.add_or_update_peer(peer, None);
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}
