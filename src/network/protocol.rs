//! Network protocol implementation

use crate::core::error::Error;
use crate::network::message::{MessageHandler, MessageType, NetworkMessage};
use crate::network::peer::{PeerInfo, PeerManager};
use crate::network::transport::MessageCodec;
use crate::Result;

use futures::prelude::*;
use libp2p::{
    core::connection::ConnectionId,
    swarm::{
        NetworkBehaviour, NetworkBehaviourAction, NotifyHandler, OneShotHandler,
        OneShotHandlerConfig, OneShotHandlerIn, OneShotHandlerOut, PollParameters,
    },
    Multiaddr, PeerId,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// Protocol name
pub const PROTOCOL_NAME: &[u8] = b"/p2p-order/1.0.0";

/// Protocol configuration
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    /// Maximum number of concurrent connections
    pub max_connections: usize,
    /// Ping interval in seconds
    pub ping_interval: u64,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Whether to enable message relaying
    pub enable_relaying: bool,
    /// Maximum number of relayed messages to keep in memory
    pub max_relayed_messages: usize,
    /// Whether to enable secure channels
    pub enable_secure_channels: bool,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            max_connections: 50,
            ping_interval: 60,
            connection_timeout: 30,
            max_message_size: 1_048_576, // 1 MB
            enable_relaying: true,
            max_relayed_messages: 1000,
            enable_secure_channels: true,
        }
    }
}

/// Protocol event
#[derive(Debug)]
pub enum ProtocolEvent {
    /// Message received from a peer
    MessageReceived {
        /// The message
        message: NetworkMessage,
        /// The peer that sent the message
        from: PeerId,
    },
    /// Message sent to a peer
    MessageSent {
        /// The message ID
        message_id: String,
        /// The peer the message was sent to
        to: PeerId,
    },
    /// Failed to send a message to a peer
    MessageSendFailed {
        /// The message ID
        message_id: String,
        /// The peer the message was supposed to be sent to
        to: PeerId,
        /// The error
        error: String,
    },
    /// Peer connected
    PeerConnected {
        /// The peer that connected
        peer_id: PeerId,
        /// The address of the peer
        addr: Multiaddr,
    },
    /// Peer disconnected
    PeerDisconnected {
        /// The peer that disconnected
        peer_id: PeerId,
    },
    /// Peer discovery
    PeerDiscovered {
        /// The discovered peer
        peer_id: PeerId,
        /// The address of the peer
        addr: Option<Multiaddr>,
    },
}

/// Protocol input
#[derive(Debug)]
pub enum ProtocolInput {
    /// Send a message to a peer
    SendMessage {
        /// The message to send
        message: NetworkMessage,
    },
    /// Connect to a peer
    ConnectToPeer {
        /// The peer to connect to
        peer_id: PeerId,
        /// The address of the peer
        addr: Multiaddr,
    },
    /// Disconnect from a peer
    DisconnectPeer {
        /// The peer to disconnect from
        peer_id: PeerId,
    },
    /// Ban a peer
    BanPeer {
        /// The peer to ban
        peer_id: PeerId,
        /// The reason for the ban
        reason: String,
    },
}

/// Protocol handler input
pub type ProtocolHandlerIn = OneShotHandlerIn<Vec<u8>>;

/// Protocol handler output
pub type ProtocolHandlerOut = OneShotHandlerOut<Vec<u8>, Vec<u8>>;

/// Protocol handler config
pub type ProtocolHandlerConfig = OneShotHandlerConfig<Vec<u8>>;

/// Protocol behaviour
pub struct ProtocolBehaviour {
    /// Protocol configuration
    config: ProtocolConfig,
    /// Peer manager
    peer_manager: PeerManager,
    /// Message handlers
    message_handlers: Vec<Box<dyn MessageHandler>>,
    /// Pending events to emit
    pending_events: VecDeque<NetworkBehaviourAction<ProtocolInput, ProtocolEvent>>,
    /// Pending outbound messages
    pending_outbound: VecDeque<(PeerId, NetworkMessage)>,
    /// Recently seen message IDs to avoid duplicates
    seen_messages: HashSet<String>,
    /// Last ping time for each peer
    last_ping: HashMap<PeerId, Instant>,
    /// Last pong time for each peer
    last_pong: HashMap<PeerId, Instant>,
    /// Secure channels
    secure_channels: HashMap<PeerId, Vec<u8>>, // Peer ID -> Shared secret
}

impl ProtocolBehaviour {
    /// Creates a new ProtocolBehaviour
    pub fn new(config: ProtocolConfig) -> Self {
        Self {
            config,
            peer_manager: PeerManager::new(),
            message_handlers: Vec::new(),
            pending_events: VecDeque::new(),
            pending_outbound: VecDeque::new(),
            seen_messages: HashSet::new(),
            last_ping: HashMap::new(),
            last_pong: HashMap::new(),
            secure_channels: HashMap::new(),
        }
    }

    /// Adds a message handler
    pub fn add_message_handler(&mut self, handler: Box<dyn MessageHandler>) {
        self.message_handlers.push(handler);
    }

    /// Sends a message to a peer
    pub fn send_message(&mut self, peer_id: PeerId, message: NetworkMessage) {
        self.pending_outbound.push_back((peer_id, message));
    }

    /// Broadcasts a message to all connected peers
    pub fn broadcast_message(&mut self, message: NetworkMessage) {
        for peer in self.peer_manager.connected_peers() {
            let mut msg = message.clone();
            msg.recipient = Some(peer.peer_id);
            self.pending_outbound.push_back((peer.peer_id, msg));
        }
    }

    /// Handles a received message
    fn handle_message(&mut self, from: PeerId, message: NetworkMessage) {
        // Check if we've already seen this message
        if self.seen_messages.contains(&message.id) {
            return;
        }

        // Add to seen messages
        self.seen_messages.insert(message.id.clone());

        // Limit the size of seen_messages
        if self.seen_messages.len() > self.config.max_relayed_messages {
            // Remove oldest messages (this is inefficient but simple)
            let to_remove = self.seen_messages.len() - self.config.max_relayed_messages;
            let mut messages: Vec<_> = self.seen_messages.iter().cloned().collect();
            messages.sort(); // Sort by message ID (which includes timestamp)
            for msg_id in messages.into_iter().take(to_remove) {
                self.seen_messages.remove(&msg_id);
            }
        }

        // Handle special message types
        match &message.message_type {
            MessageType::Ping => {
                // Respond with a pong
                let pong =
                    NetworkMessage::pong(message.recipient.unwrap_or(PeerId::random()), Some(from));
                self.send_message(from, pong);
                return;
            }
            MessageType::Pong => {
                // Update last pong time
                self.last_pong.insert(from, Instant::now());
                return;
            }
            _ => {}
        }

        // Check if the message is for us
        if let Some(recipient) = &message.recipient {
            if recipient != &message.recipient.unwrap_or(PeerId::random()) {
                // This message is not for us, relay it if enabled
                if self.config.enable_relaying && message.decrement_ttl() {
                    if let Some(target_peer) = self.peer_manager.get_peer(recipient) {
                        if target_peer.state == crate::network::peer::PeerConnectionState::Connected
                        {
                            self.send_message(*recipient, message.clone());
                        }
                    }
                }
                return;
            }
        }

        // Emit message received event
        self.pending_events
            .push_back(NetworkBehaviourAction::GenerateEvent(
                ProtocolEvent::MessageReceived {
                    message: message.clone(),
                    from,
                },
            ));

        // Pass the message to handlers
        for handler in &self.message_handlers {
            if handler.supported_types().contains(&message.message_type) {
                if let Ok(Some(response)) = handler.handle_message(message.clone()) {
                    self.send_message(from, response);
                }
            }
        }
    }

    /// Sends periodic pings to connected peers
    fn send_pings(&mut self) {
        let now = Instant::now();
        let ping_interval = Duration::from_secs(self.config.ping_interval);

        for peer in self.peer_manager.connected_peers() {
            let last_ping = self
                .last_ping
                .get(&peer.peer_id)
                .cloned()
                .unwrap_or(Instant::now() - ping_interval * 2);

            if now.duration_since(last_ping) >= ping_interval {
                let ping = NetworkMessage::ping(
                    PeerId::random(), // Our peer ID
                    Some(peer.peer_id),
                );
                self.send_message(peer.peer_id, ping);
                self.last_ping.insert(peer.peer_id, now);
            }
        }
    }

    /// Checks for peers that haven't responded to pings
    fn check_peer_timeouts(&mut self) {
        let now = Instant::now();
        let timeout = Duration::from_secs(self.config.connection_timeout);

        let mut to_disconnect = Vec::new();

        for peer in self.peer_manager.connected_peers() {
            let last_pong = self
                .last_pong
                .get(&peer.peer_id)
                .cloned()
                .unwrap_or(Instant::now() - timeout * 2);

            if now.duration_since(last_pong) >= timeout {
                to_disconnect.push(peer.peer_id);
            }
        }

        for peer_id in to_disconnect {
            self.pending_events
                .push_back(NetworkBehaviourAction::GenerateEvent(
                    ProtocolEvent::PeerDisconnected { peer_id },
                ));
            self.peer_manager.mark_disconnected(&peer_id);
        }
    }
}

impl NetworkBehaviour for ProtocolBehaviour {
    type ConnectionHandler = OneShotHandler<Vec<u8>, Vec<u8>, Vec<u8>>;
    type OutEvent = ProtocolEvent;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        let mut config = ProtocolHandlerConfig::default();
        config.max_response_size = self.config.max_message_size;
        config.max_request_size = self.config.max_message_size;

        OneShotHandler::new(PROTOCOL_NAME.to_vec(), config)
    }

    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        if let Some(peer) = self.peer_manager.get_peer(peer_id) {
            peer.addresses.clone()
        } else {
            Vec::new()
        }
    }

    fn inject_connected(
        &mut self,
        peer_id: &PeerId,
        conn: &ConnectionId,
        endpoint: &libp2p::core::ConnectedPoint,
    ) {
        let addr = match endpoint {
            libp2p::core::ConnectedPoint::Dialer { address, .. } => address.clone(),
            libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr.clone(),
        };

        if let Err(e) = self
            .peer_manager
            .mark_connected(*peer_id, Some(addr.clone()))
        {
            log::warn!("Failed to mark peer as connected: {}", e);
            return;
        }

        // Initialize ping/pong tracking
        self.last_ping.insert(*peer_id, Instant::now());
        self.last_pong.insert(*peer_id, Instant::now());

        // Emit peer connected event
        self.pending_events
            .push_back(NetworkBehaviourAction::GenerateEvent(
                ProtocolEvent::PeerConnected {
                    peer_id: *peer_id,
                    addr,
                },
            ));
    }

    fn inject_disconnected(
        &mut self,
        peer_id: &PeerId,
        _: &ConnectionId,
        _: &libp2p::core::ConnectedPoint,
    ) {
        self.peer_manager.mark_disconnected(peer_id);

        // Clean up ping/pong tracking
        self.last_ping.remove(peer_id);
        self.last_pong.remove(peer_id);

        // Clean up secure channels
        self.secure_channels.remove(peer_id);

        // Emit peer disconnected event
        self.pending_events
            .push_back(NetworkBehaviourAction::GenerateEvent(
                ProtocolEvent::PeerDisconnected { peer_id: *peer_id },
            ));
    }

    fn inject_event(
        &mut self,
        peer_id: PeerId,
        _: ConnectionId,
        event: <Self::ConnectionHandler as libp2p::swarm::ConnectionHandler>::OutEvent,
    ) {
        match event {
            ProtocolHandlerOut::Response(response) => {
                // Handle response from peer
                match NetworkMessage::deserialize(&response) {
                    Ok(message) => {
                        self.handle_message(peer_id, message);
                    }
                    Err(e) => {
                        log::warn!("Failed to deserialize message from {}: {}", peer_id, e);
                    }
                }
            }
            ProtocolHandlerOut::Upgrade(upgrade) => {
                // Handle protocol upgrade
                match NetworkMessage::deserialize(&upgrade) {
                    Ok(message) => {
                        self.handle_message(peer_id, message);
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to deserialize upgrade message from {}: {}",
                            peer_id,
                            e
                        );
                    }
                }
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        _: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        // Process pending events
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event);
        }

        // Send periodic pings
        self.send_pings();

        // Check for peer timeouts
        self.check_peer_timeouts();

        // Clean up inactive peers
        self.peer_manager.cleanup_inactive_peers();

        // Process pending outbound messages
        if let Some((peer_id, message)) = self.pending_outbound.pop_front() {
            // Check if the peer is connected
            if let Some(peer) = self.peer_manager.get_peer(&peer_id) {
                if peer.state == crate::network::peer::PeerConnectionState::Connected {
                    // Encode the message
                    match MessageCodec::encode(&message) {
                        Ok(encoded) => {
                            // Send the message
                            return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                                peer_id,
                                handler: NotifyHandler::Any,
                                event: ProtocolHandlerIn::Request { request: encoded },
                            });
                        }
                        Err(e) => {
                            // Emit message send failed event
                            self.pending_events
                                .push_back(NetworkBehaviourAction::GenerateEvent(
                                    ProtocolEvent::MessageSendFailed {
                                        message_id: message.id,
                                        to: peer_id,
                                        error: format!("Failed to encode message: {}", e),
                                    },
                                ));
                        }
                    }
                } else {
                    // Peer is not connected
                    self.pending_events
                        .push_back(NetworkBehaviourAction::GenerateEvent(
                            ProtocolEvent::MessageSendFailed {
                                message_id: message.id,
                                to: peer_id,
                                error: "Peer is not connected".into(),
                            },
                        ));
                }
            } else {
                // Peer is unknown
                self.pending_events
                    .push_back(NetworkBehaviourAction::GenerateEvent(
                        ProtocolEvent::MessageSendFailed {
                            message_id: message.id,
                            to: peer_id,
                            error: "Peer is unknown".into(),
                        },
                    ));
            }

            // Try again with the next message
            return self.poll(cx, _);
        }

        Poll::Pending
    }
}
