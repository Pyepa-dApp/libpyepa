//! Network transport layer

use crate::core::error::Error;
use crate::network::message::{NetworkMessage, MAX_MESSAGE_SIZE};
use crate::Result;

use libp2p::core::transport::OrTransport;
use libp2p::dns::TokioDnsConfig;
use libp2p::mplex;
use libp2p::websocket::WsConfig;
use libp2p::{core::upgrade, identity, noise, tcp::Config as TokioTcpConfig, yamux, Transport};
use std::time::Duration;

/// Default timeout for connections (in seconds)
const DEFAULT_CONNECTION_TIMEOUT: u64 = 30;

/// Creates a libp2p transport with noise encryption and yamux/mplex multiplexing
pub fn create_transport(
    keypair: &identity::Keypair,
    connection_timeout: Option<Duration>,
) -> Result<libp2p::core::transport::Boxed<(libp2p::PeerId, libp2p::core::muxing::StreamMuxerBox)>>
{
    // Create an authenticated noise protocol using the provided keypair
    let noise_keys = noise::Config::new(&keypair)
        .unwrap()
        .into_authenticated()
        .map_err(|e| Error::Network(format!("Failed to create noise keys: {}", e)))?;

    let timeout =
        connection_timeout.unwrap_or_else(|| Duration::from_secs(DEFAULT_CONNECTION_TIMEOUT));

    // Create a TCP transport with DNS name resolution
    let tcp_transport = TokioDnsConfig::system(TokioTcpConfig::new().nodelay(true))
        .map_err(|e| Error::Network(format!("Failed to create DNS config: {}", e)))?;

    // Create a WebSocket transport
    let ws_transport =
        TokioDnsConfig::system(WsConfig::new(TokioTcpConfig::new().nodelay(true)))
            .map_err(|e| Error::Network(format!("Failed to create WebSocket DNS config: {}", e)))?;

    // Combine TCP and WebSocket transports
    let transport = OrTransport::new(tcp_transport, ws_transport)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise_keys)
        .multiplex(upgrade::SelectUpgrade::new(
            yamux::Config::default(),
            mplex::MplexConfig::default(),
        ))
        .timeout(timeout)
        .boxed();

    Ok(transport)
}

/// Message codec for encoding/decoding network messages
pub struct MessageCodec;

impl MessageCodec {
    /// Encodes a network message to bytes
    pub fn encode(message: &NetworkMessage) -> Result<Vec<u8>> {
        let bytes = message.serialize()?;

        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(Error::Network(format!(
                "Message size exceeds maximum allowed size: {} > {}",
                bytes.len(),
                MAX_MESSAGE_SIZE
            )));
        }

        // Prefix with length (4 bytes, big-endian)
        let mut encoded = Vec::with_capacity(4 + bytes.len());
        encoded.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&bytes);

        Ok(encoded)
    }

    /// Decodes bytes to a network message
    pub fn decode(bytes: &[u8]) -> Result<NetworkMessage> {
        if bytes.len() < 4 {
            return Err(Error::Network("Message too short".into()));
        }

        // Extract length prefix
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&bytes[0..4]);
        let length = u32::from_be_bytes(length_bytes) as usize;

        if length > MAX_MESSAGE_SIZE {
            return Err(Error::Network(format!(
                "Message size exceeds maximum allowed size: {} > {}",
                length, MAX_MESSAGE_SIZE
            )));
        }

        if bytes.len() < 4 + length {
            return Err(Error::Network("Incomplete message".into()));
        }

        // Decode the message
        NetworkMessage::deserialize(&bytes[4..4 + length])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::message::MessageType;
    use libp2p::PeerId;

    #[test]
    fn test_message_codec() {
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        // Create a test message
        let message = NetworkMessage::new(peer_id, None, MessageType::Ping);

        // Encode the message
        let encoded = MessageCodec::encode(&message).unwrap();

        // Decode the message
        let decoded = MessageCodec::decode(&encoded).unwrap();

        // Check equality
        assert_eq!(decoded.sender, message.sender);
        assert_eq!(decoded.recipient, message.recipient);
        assert_eq!(decoded.message_type, message.message_type);
        assert_eq!(decoded.timestamp, message.timestamp);
    }

    #[test]
    fn test_message_codec_with_large_message() {
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let recipient = PeerId::random();

        // Create a large message that exceeds the maximum size
        let large_content = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let large_message = NetworkMessage::direct_message(
            peer_id,
            recipient,
            large_content,
            "application/octet-stream".to_string(),
        );

        // Encoding should fail
        let result = MessageCodec::encode(&large_message);
        assert!(result.is_err());
    }
}
