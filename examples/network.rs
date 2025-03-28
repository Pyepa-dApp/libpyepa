//! Example usage of the network module

use my_p2p_order_sdk::{
    core::crypto::Crypto,
    models::Message as OrderMessage,
    network::{
        discovery::{DiscoveryBehaviour, DiscoveryConfig},
        message::{MessageType, NetworkMessage},
        peer::PeerManager,
        protocol::{ProtocolBehaviour, ProtocolConfig, ProtocolEvent},
        transport::create_transport,
    },
};

use futures::prelude::*;
use libp2p::{
    core::Multiaddr,
    identity,
    swarm::{Swarm, SwarmEvent},
    PeerId,
};
use std::error::Error;
use std::str::FromStr;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    env_logger::init();

    println!("Starting P2P network example...");

    // Generate a random identity
    let local_keypair = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_keypair.public());

    println!("Local peer ID: {}", local_peer_id);

    // Create a transport
    let transport = create_transport(&local_keypair, None)?;

    // Create a peer manager
    let peer_manager = PeerManager::new();

    // Create protocol configuration
    let protocol_config = ProtocolConfig {
        max_connections: 50,
        ping_interval: 60,
        connection_timeout: 30,
        max_message_size: 1_048_576, // 1 MB
        enable_relaying: true,
        max_relayed_messages: 1000,
        enable_secure_channels: true,
    };

    // Create protocol behaviour
    let mut protocol_behaviour = ProtocolBehaviour::new(protocol_config);

    // Create discovery configuration
    let discovery_config = DiscoveryConfig {
        enable_mdns: true,
        enable_kademlia: true,
        bootstrap_nodes: vec![
            // Add some bootstrap nodes here
            // For example:
            // (PeerId::from_str("QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ")?,
            //  "/ip4/104.131.131.82/tcp/4001".parse()?),
        ],
        discovery_interval: 300,
        max_peers: 100,
    };

    // Create discovery behaviour
    let discovery_behaviour =
        DiscoveryBehaviour::new(local_peer_id, discovery_config, peer_manager).await?;

    // Combine behaviours
    #[derive(libp2p::swarm::NetworkBehaviour)]
    struct CombinedBehaviour {
        protocol: ProtocolBehaviour,
        discovery: DiscoveryBehaviour,
    }

    let combined_behaviour = CombinedBehaviour {
        protocol: protocol_behaviour,
        discovery: discovery_behaviour,
    };

    // Create a swarm using SwarmBuilder with an executor
    let mut swarm = libp2p::swarm::SwarmBuilder::new(transport, combined_behaviour, local_peer_id)
        .executor(Box::new(|fut| {
            tokio::spawn(fut);
        }))
        .build();
    // Listen on all interfaces
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    // Bootstrap the discovery
    swarm.behaviour_mut().discovery.bootstrap()?;

    // If you want to connect to a specific peer
    if let Some(peer_to_connect) = std::env::args().nth(1) {
        let addr: Multiaddr = peer_to_connect.parse()?;
        swarm.dial(addr)?;
        println!("Dialed {}", peer_to_connect);
    }

    // Event loop
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("Listening on {}", address);
            }
            SwarmEvent::Behaviour(event) => {
                match event {
                    // Protocol events
                    libp2p::swarm::BehaviourEvent::Protocol(protocol_event) => {
                        match protocol_event {
                            ProtocolEvent::MessageReceived { message, from } => {
                                println!(
                                    "Received message from {}: {:?}",
                                    from, message.message_type
                                );

                                // Example: respond to direct messages
                                if let MessageType::DirectMessage {
                                    content,
                                    content_type,
                                } = &message.message_type
                                {
                                    if content_type == "text/plain" {
                                        let text = String::from_utf8_lossy(content);
                                        println!("Message content: {}", text);

                                        // Send a response
                                        let response = NetworkMessage::direct_message(
                                            local_peer_id,
                                            from,
                                            format!("Received your message: {}", text).into_bytes(),
                                            "text/plain".to_string(),
                                        );

                                        swarm.behaviour_mut().protocol.send_message(from, response);
                                    }
                                }
                            }
                            ProtocolEvent::PeerConnected { peer_id, addr } => {
                                println!("Connected to {} at {}", peer_id, addr);

                                // Example: send a greeting message
                                let greeting = NetworkMessage::direct_message(
                                    local_peer_id,
                                    peer_id,
                                    b"Hello from the P2P Order SDK!".to_vec(),
                                    "text/plain".to_string(),
                                );

                                swarm
                                    .behaviour_mut()
                                    .protocol
                                    .send_message(peer_id, greeting);
                            }
                            ProtocolEvent::PeerDisconnected { peer_id } => {
                                println!("Disconnected from {}", peer_id);
                            }
                            ProtocolEvent::PeerDiscovered { peer_id, addr } => {
                                println!("Discovered peer {} at {:?}", peer_id, addr);
                            }
                            _ => {}
                        }
                    }
                    // Discovery events
                    libp2p::swarm::BehaviourEvent::Discovery(_) => {
                        // Handle discovery events if needed
                    }
                }
            }
            _ => {}
        }
    }
}
