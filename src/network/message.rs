//! Network message types and serialization

use crate::core::error::Error;
use crate::models::Message as OrderMessage;
use crate::Result;

use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum message size in bytes
pub const MAX_MESSAGE_SIZE: usize = 1_048_576; // 1 MB

/// Network message types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MessageType {
    /// Ping message to check if a peer is alive
    Ping,
    /// Pong response to a ping
    Pong,
    /// Order-related message
    Order(OrderMessage),
    /// Request for vendor listings
    ListingRequest,
    /// Response with vendor listings
    ListingResponse(Vec<u8>), // Serialized vendor listings
    /// Direct message to a specific peer
    DirectMessage {
        /// Content of the message
        content: Vec<u8>,
        /// Content type (e.g., "text/plain", "application/json")
        content_type: String,
    },
    /// Request to establish a secure channel
    SecureChannelRequest,
    /// Response to a secure channel request
    SecureChannelResponse {
        /// Accepted or rejected
        accepted: bool,
        /// If rejected, the reason
        reason: Option<String>,
        /// Ephemeral public key for the secure channel
        ephemeral_key: Option<Vec<u8>>,
    },
}

/// Network message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMessage {
    /// Message ID
    pub id: String,
    /// Sender peer ID
    pub sender: PeerId,
    /// Recipient peer ID (if None, broadcast to all peers)
    pub recipient: Option<PeerId>,
    /// Message type
    pub message_type: MessageType,
    /// Timestamp (seconds since UNIX epoch)
    pub timestamp: u64,
    /// Time-to-live (number of hops)
    pub ttl: u8,
    /// Signature of the message
    pub signature: Option<Vec<u8>>,
}

impl NetworkMessage {
    /// Creates a new NetworkMessage
    pub fn new(sender: PeerId, recipient: Option<PeerId>, message_type: MessageType) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let id = format!("{}_{}", sender.to_base58(), now);

        Self {
            id,
            sender,
            recipient,
            message_type,
            timestamp: now,
            ttl: 32, // Default TTL
            signature: None,
        }
    }

    /// Creates a ping message
    pub fn ping(sender: PeerId, recipient: Option<PeerId>) -> Self {
        Self::new(sender, recipient, MessageType::Ping)
    }

    /// Creates a pong message
    pub fn pong(sender: PeerId, recipient: Option<PeerId>) -> Self {
        Self::new(sender, recipient, MessageType::Pong)
    }

    /// Creates an order message
    pub fn order(sender: PeerId, recipient: Option<PeerId>, order_message: OrderMessage) -> Self {
        Self::new(sender, recipient, MessageType::Order(order_message))
    }

    /// Creates a listing request message
    pub fn listing_request(sender: PeerId, recipient: Option<PeerId>) -> Self {
        Self::new(sender, recipient, MessageType::ListingRequest)
    }

    /// Creates a listing response message
    pub fn listing_response(sender: PeerId, recipient: Option<PeerId>, listings: Vec<u8>) -> Self {
        Self::new(sender, recipient, MessageType::ListingResponse(listings))
    }

    /// Creates a direct message
    pub fn direct_message(
        sender: PeerId,
        recipient: PeerId,
        content: Vec<u8>,
        content_type: String,
    ) -> Self {
        Self::new(
            sender,
            Some(recipient),
            MessageType::DirectMessage {
                content,
                content_type,
            },
        )
    }

    /// Creates a secure channel request
    pub fn secure_channel_request(sender: PeerId, recipient: PeerId) -> Self {
        Self::new(sender, Some(recipient), MessageType::SecureChannelRequest)
    }

    /// Creates a secure channel response
    pub fn secure_channel_response(
        sender: PeerId,
        recipient: PeerId,
        accepted: bool,
        reason: Option<String>,
        ephemeral_key: Option<Vec<u8>>,
    ) -> Self {
        Self::new(
            sender,
            Some(recipient),
            MessageType::SecureChannelResponse {
                accepted,
                reason,
                ephemeral_key,
            },
        )
    }

    /// Sets the signature for the message
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Sets the TTL for the message
    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    /// Serializes the message to bytes
    pub fn serialize(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Serialization(serde_json::Error::custom(e)))
    }

    /// Deserializes bytes to a message
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| Error::Serialization(serde_json::Error::custom(e)))
    }

    /// Checks if the message is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Message is expired if it's older than 1 hour
        now - self.timestamp > 3600
    }

    /// Decrements the TTL and checks if the message is still alive
    pub fn decrement_ttl(&mut self) -> bool {
        if self.ttl > 0 {
            self.ttl -= 1;
            true
        } else {
            false
        }
    }

    /// Checks if the message is a broadcast
    pub fn is_broadcast(&self) -> bool {
        self.recipient.is_none()
    }

    /// Checks if the message is for a specific recipient
    pub fn is_for(&self, peer_id: &PeerId) -> bool {
        match &self.recipient {
            Some(recipient) => recipient == peer_id,
            None => true, // Broadcast messages are for everyone
        }
    }
}

/// Message handler trait for processing network messages
pub trait MessageHandler: Send + Sync {
    /// Handles a network message
    fn handle_message(&self, message: NetworkMessage) -> Result<Option<NetworkMessage>>;

    /// Gets the supported message types
    fn supported_types(&self) -> Vec<MessageType>;
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
    fn test_message_serialization() {
        let sender = create_test_peer_id();
        let recipient = create_test_peer_id();

        let message = NetworkMessage::ping(sender, Some(recipient));

        // Serialize
        let bytes = message.serialize().unwrap();

        // Deserialize
        let deserialized = NetworkMessage::deserialize(&bytes).unwrap();

        // Check equality
        assert_eq!(deserialized.sender, message.sender);
        assert_eq!(deserialized.recipient, message.recipient);
        assert_eq!(deserialized.message_type, message.message_type);
        assert_eq!(deserialized.timestamp, message.timestamp);
        assert_eq!(deserialized.ttl, message.ttl);
    }

    #[test]
    fn test_message_types() {
        let sender = create_test_peer_id();
        let recipient = create_test_peer_id();

        // Test ping
        let ping = NetworkMessage::ping(sender, Some(recipient));
        assert!(matches!(ping.message_type, MessageType::Ping));

        // Test pong
        let pong = NetworkMessage::pong(sender, Some(recipient));
        assert!(matches!(pong.message_type, MessageType::Pong));

        // Test direct message
        let content = b"Hello, world!".to_vec();
        let direct = NetworkMessage::direct_message(
            sender,
            recipient,
            content.clone(),
            "text/plain".to_string(),
        );

        if let MessageType::DirectMessage {
            content: msg_content,
            content_type,
        } = direct.message_type
        {
            assert_eq!(msg_content, content);
            assert_eq!(content_type, "text/plain");
        } else {
            panic!("Expected DirectMessage");
        }
    }

    #[test]
    fn test_ttl_and_expiry() {
        let sender = create_test_peer_id();
        let recipient = create_test_peer_id();

        let mut message = NetworkMessage::ping(sender, Some(recipient)).with_ttl(2);

        // Check TTL decrement
        assert_eq!(message.ttl, 2);
        assert!(message.decrement_ttl());
        assert_eq!(message.ttl, 1);
        assert!(message.decrement_ttl());
        assert_eq!(message.ttl, 0);
        assert!(!message.decrement_ttl());
        assert_eq!(message.ttl, 0);

        // Check expiry (this should not be expired as we just created it)
        assert!(!message.is_expired());
    }
}
