//! Peer management for the P2P network

use crate::core::error::Error;
use crate::Result;

use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Maximum number of inactive peers to keep in memory
const MAX_INACTIVE_PEERS: usize = 100;

/// Time after which a peer is considered inactive (in seconds)
const PEER_INACTIVE_THRESHOLD_SECS: u64 = 300; // 5 minutes

/// Peer connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerConnectionState {
    /// Connected and active
    Connected,
    /// Disconnected but known
    Disconnected,
    /// Connection is being established
    Connecting,
    /// Peer has been banned
    Banned,
}

/// Peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer ID
    pub peer_id: PeerId,
    /// Known addresses for this peer
    pub addresses: Vec<Multiaddr>,
    /// Connection state
    pub state: PeerConnectionState,
    /// Last seen timestamp (seconds since UNIX epoch)
    pub last_seen: u64,
    /// Protocol version
    pub protocol_version: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Public identity key (if known)
    pub identity_key: Option<String>,
    /// Peer reputation score (0-100)
    pub reputation: u8,
    /// Whether this peer is a vendor
    pub is_vendor: bool,
    /// Whether this peer is a buyer
    pub is_buyer: bool,
    /// Whether this peer is a mediator
    pub is_mediator: bool,
}

impl PeerInfo {
    /// Creates a new PeerInfo
    pub fn new(peer_id: PeerId) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();

        Self {
            peer_id,
            addresses: Vec::new(),
            state: PeerConnectionState::Disconnected,
            last_seen: now,
            protocol_version: None,
            user_agent: None,
            identity_key: None,
            reputation: 50, // Default neutral reputation
            is_vendor: false,
            is_buyer: false,
            is_mediator: false,
        }
    }

    /// Adds an address for this peer
    pub fn add_address(&mut self, addr: Multiaddr) {
        if !self.addresses.contains(&addr) {
            self.addresses.push(addr);
        }
    }

    /// Updates the last seen timestamp
    pub fn update_last_seen(&mut self) {
        self.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();
    }

    /// Sets the peer as a vendor
    pub fn set_as_vendor(&mut self, is_vendor: bool) {
        self.is_vendor = is_vendor;
    }

    /// Sets the peer as a buyer
    pub fn set_as_buyer(&mut self, is_buyer: bool) {
        self.is_buyer = is_buyer;
    }

    /// Sets the peer as a mediator
    pub fn set_as_mediator(&mut self, is_mediator: bool) {
        self.is_mediator = is_mediator;
    }

    /// Sets the identity key for this peer
    pub fn set_identity_key(&mut self, key: String) {
        self.identity_key = Some(key);
    }

    /// Updates the reputation score
    pub fn update_reputation(&mut self, score: i8) {
        // Adjust the reputation score, ensuring it stays within 0-100
        let new_score = self.reputation as i16 + score as i16;
        self.reputation = new_score.clamp(0, 100) as u8;
    }

    /// Checks if the peer is active (seen recently)
    pub fn is_active(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();

        now - self.last_seen < PEER_INACTIVE_THRESHOLD_SECS
    }
}

/// Peer manager for tracking and managing network peers
pub struct PeerManager {
    /// Map of peer IDs to peer information
    peers: HashMap<PeerId, PeerInfo>,
    /// Set of connected peer IDs
    connected_peers: HashSet<PeerId>,
    /// Set of banned peer IDs
    banned_peers: HashSet<PeerId>,
    /// Last cleanup time
    last_cleanup: Instant,
    /// Cleanup interval in seconds
    cleanup_interval: u64,
}

impl PeerManager {
    /// Creates a new PeerManager
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            connected_peers: HashSet::new(),
            banned_peers: HashSet::new(),
            last_cleanup: Instant::now(),
            cleanup_interval: 3600, // Clean up once per hour
        }
    }

    /// Adds or updates a peer
    pub fn add_or_update_peer(
        &mut self,
        peer_id: PeerId,
        addr: Option<Multiaddr>,
    ) -> &mut PeerInfo {
        let peer = self
            .peers
            .entry(peer_id)
            .or_insert_with(|| PeerInfo::new(peer_id));

        if let Some(address) = addr {
            peer.add_address(address);
        }

        peer.update_last_seen();
        peer
    }

    /// Gets peer information
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    /// Gets mutable peer information
    pub fn get_peer_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerInfo> {
        self.peers.get_mut(peer_id)
    }

    /// Marks a peer as connected
    pub fn mark_connected(&mut self, peer_id: PeerId, addr: Option<Multiaddr>) -> Result<()> {
        let peer = self.add_or_update_peer(peer_id, addr);

        if self.banned_peers.contains(&peer_id) {
            return Err(Error::Network(format!("Peer {} is banned", peer_id)));
        }

        peer.state = PeerConnectionState::Connected;
        self.connected_peers.insert(peer_id);

        Ok(())
    }

    /// Marks a peer as disconnected
    pub fn mark_disconnected(&mut self, peer_id: &PeerId) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.state = PeerConnectionState::Disconnected;
            peer.update_last_seen();
        }

        self.connected_peers.remove(peer_id);
    }

    /// Bans a peer
    pub fn ban_peer(&mut self, peer_id: PeerId, reason: &str) {
        if let Some(peer) = self.peers.get_mut(&peer_id) {
            peer.state = PeerConnectionState::Banned;
            peer.update_last_seen();
        } else {
            let mut peer = PeerInfo::new(peer_id);
            peer.state = PeerConnectionState::Banned;
            self.peers.insert(peer_id, peer);
        }

        self.banned_peers.insert(peer_id);
        self.connected_peers.remove(&peer_id);

        log::warn!("Banned peer {} for reason: {}", peer_id, reason);
    }

    /// Unbans a peer
    pub fn unban_peer(&mut self, peer_id: &PeerId) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.state = PeerConnectionState::Disconnected;
        }

        self.banned_peers.remove(peer_id);
    }

    /// Checks if a peer is banned
    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        self.banned_peers.contains(peer_id)
    }

    /// Gets all connected peers
    pub fn connected_peers(&self) -> Vec<&PeerInfo> {
        self.connected_peers
            .iter()
            .filter_map(|peer_id| self.peers.get(peer_id))
            .collect()
    }

    /// Gets all vendor peers
    pub fn vendor_peers(&self) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|peer| peer.is_vendor && peer.state == PeerConnectionState::Connected)
            .collect()
    }

    /// Gets all buyer peers
    pub fn buyer_peers(&self) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|peer| peer.is_buyer && peer.state == PeerConnectionState::Connected)
            .collect()
    }

    /// Gets all mediator peers
    pub fn mediator_peers(&self) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|peer| peer.is_mediator && peer.state == PeerConnectionState::Connected)
            .collect()
    }

    /// Cleans up inactive peers
    pub fn cleanup_inactive_peers(&mut self) {
        // Only clean up periodically
        if self.last_cleanup.elapsed() < Duration::from_secs(self.cleanup_interval) {
            return;
        }

        // Get all inactive peers
        let inactive_peers: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, info)| {
                !info.is_active()
                    && info.state == PeerConnectionState::Disconnected
                    && !self.banned_peers.contains(&info.peer_id)
            })
            .map(|(peer_id, _)| *peer_id)
            .collect();

        // If we have too many inactive peers, remove the oldest ones
        if inactive_peers.len() > MAX_INACTIVE_PEERS {
            // Sort by last seen (oldest first)
            let mut inactive_with_time: Vec<(PeerId, u64)> = inactive_peers
                .into_iter()
                .map(|peer_id| {
                    let last_seen = self.peers.get(&peer_id).map_or(0, |p| p.last_seen);
                    (peer_id, last_seen)
                })
                .collect();

            inactive_with_time.sort_by_key(|(_, last_seen)| *last_seen);

            // Remove oldest peers to get down to MAX_INACTIVE_PEERS
            let to_remove = inactive_with_time.len() - MAX_INACTIVE_PEERS;
            for (peer_id, _) in inactive_with_time.iter().take(to_remove) {
                self.peers.remove(peer_id);
            }
        }

        self.last_cleanup = Instant::now();
    }

    /// Gets the number of connected peers
    pub fn connected_count(&self) -> usize {
        self.connected_peers.len()
    }

    /// Gets the total number of known peers
    pub fn total_count(&self) -> usize {
        self.peers.len()
    }

    /// Gets the number of banned peers
    pub fn banned_count(&self) -> usize {
        self.banned_peers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity;

    fn create_test_peer_id() -> PeerId {
        let keypair = identity::Keypair::generate_ed25519();
        PeerId::from(keypair.public())
    }

    #[test]
    fn test_peer_manager_basic_operations() {
        let mut manager = PeerManager::new();
        let peer_id = create_test_peer_id();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/8080".parse().unwrap();

        // Add a peer
        manager.add_or_update_peer(peer_id, Some(addr.clone()));

        // Check the peer exists
        let peer = manager.get_peer(&peer_id).unwrap();
        assert_eq!(peer.peer_id, peer_id);
        assert_eq!(peer.addresses.len(), 1);
        assert_eq!(peer.addresses[0], addr);
        assert_eq!(peer.state, PeerConnectionState::Disconnected);

        // Mark as connected
        manager.mark_connected(peer_id, None).unwrap();

        // Check the peer is connected
        let peer = manager.get_peer(&peer_id).unwrap();
        assert_eq!(peer.state, PeerConnectionState::Connected);
        assert!(manager.connected_peers.contains(&peer_id));

        // Mark as disconnected
        manager.mark_disconnected(&peer_id);

        // Check the peer is disconnected
        let peer = manager.get_peer(&peer_id).unwrap();
        assert_eq!(peer.state, PeerConnectionState::Disconnected);
        assert!(!manager.connected_peers.contains(&peer_id));
    }

    #[test]
    fn test_peer_banning() {
        let mut manager = PeerManager::new();
        let peer_id = create_test_peer_id();

        // Ban a peer
        manager.ban_peer(peer_id, "Test ban reason");

        // Check the peer is banned
        assert!(manager.is_banned(&peer_id));
        let peer = manager.get_peer(&peer_id).unwrap();
        assert_eq!(peer.state, PeerConnectionState::Banned);

        // Try to connect a banned peer
        let result = manager.mark_connected(peer_id, None);
        assert!(result.is_err());

        // Unban the peer
        manager.unban_peer(&peer_id);

        // Check the peer is no longer banned
        assert!(!manager.is_banned(&peer_id));
        let peer = manager.get_peer(&peer_id).unwrap();
        assert_eq!(peer.state, PeerConnectionState::Disconnected);

        // Now we should be able to connect
        let result = manager.mark_connected(peer_id, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_peer_roles() {
        let mut manager = PeerManager::new();
        let vendor_id = create_test_peer_id();
        let buyer_id = create_test_peer_id();
        let mediator_id = create_test_peer_id();

        // Add peers with different roles
        let vendor = manager.add_or_update_peer(vendor_id, None);
        vendor.set_as_vendor(true);
        manager.mark_connected(vendor_id, None).unwrap();

        let buyer = manager.add_or_update_peer(buyer_id, None);
        buyer.set_as_buyer(true);
        manager.mark_connected(buyer_id, None).unwrap();

        let mediator = manager.add_or_update_peer(mediator_id, None);
        mediator.set_as_mediator(true);
        manager.mark_connected(mediator_id, None).unwrap();

        // Check role-specific queries
        assert_eq!(manager.vendor_peers().len(), 1);
        assert_eq!(manager.buyer_peers().len(), 1);
        assert_eq!(manager.mediator_peers().len(), 1);
        assert_eq!(manager.connected_peers().len(), 3);
    }
}
