//! Command-line interface for the P2P order protocol

use libpyepa::{
    api::{buyer::BuyerApi, vendor::VendorApi},
    core::{
        crypto::Crypto,
        dht::DhtClient,
        dispute::{DisputeClient, DisputeParty, DisputeState, EvidenceType},
        payment::{EscrowType, PaymentManager, PaymentMethod, PaymentStatus, USDCChain},
        types::OrderState,
    },
    models::{Item, Location, Message, Order, OrderItem, Reputation, VendorListing},
    network::{
        discovery::{DiscoveryBehaviour, DiscoveryConfig},
        message::{MessageType, NetworkMessage},
        peer::PeerManager,
        protocol::{ProtocolBehaviour, ProtocolConfig},
        transport::create_transport,
    },
};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use libp2p::{identity, Multiaddr, PeerId};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use tokio::fs;
use uuid::Uuid;

// Update the imports for libp2p in the network section
use futures::prelude::*;
use libp2p::{
    core::Multiaddr,
    identity,
    swarm::{Swarm, SwarmEvent},
    PeerId,
};

/// P2P Order Protocol CLI
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Path to the config directory
    #[clap(short, long, default_value = ".p2p-order")]
    config_dir: PathBuf,

    /// Subcommands
    #[clap(subcommand)]
    command: Commands,
}

/// CLI subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Identity management
    Identity {
        #[clap(subcommand)]
        command: IdentityCommands,
    },
    /// Vendor operations
    Vendor {
        #[clap(subcommand)]
        command: VendorCommands,
    },
    /// Buyer operations
    Buyer {
        #[clap(subcommand)]
        command: BuyerCommands,
    },
    /// Order operations
    Order {
        #[clap(subcommand)]
        command: OrderCommands,
    },
    /// Payment operations
    Payment {
        #[clap(subcommand)]
        command: PaymentCommands,
    },
    /// Dispute operations
    Dispute {
        #[clap(subcommand)]
        command: DisputeCommands,
    },
    /// Network operations
    Network {
        #[clap(subcommand)]
        command: NetworkCommands,
    },
}

/// Identity management commands
#[derive(Subcommand, Debug)]
enum IdentityCommands {
    /// Create a new identity
    Create {
        /// Identity name
        #[clap(short, long)]
        name: String,
        /// Identity type (buyer, vendor, or mediator)
        #[clap(short, long)]
        identity_type: String,
    },
    /// List all identities
    List,
    /// Show details of an identity
    Show {
        /// Identity name
        #[clap(short, long)]
        name: String,
    },
    /// Set the active identity
    SetActive {
        /// Identity name
        #[clap(short, long)]
        name: String,
    },
}

/// Vendor operations commands
#[derive(Subcommand, Debug)]
enum VendorCommands {
    /// Create a new listing
    CreateListing {
        /// Listing name
        #[clap(short, long)]
        name: String,
        /// Item name
        #[clap(short, long)]
        item_name: String,
        /// Item description
        #[clap(short, long)]
        description: String,
        /// Item price
        #[clap(short, long)]
        price: String,
        /// Item tags (comma-separated)
        #[clap(short, long)]
        tags: String,
        /// Payment methods (comma-separated)
        #[clap(short, long)]
        payment_methods: String,
    },
    /// List all listings
    ListListings,
    /// Show details of a listing
    ShowListing {
        /// Listing ID
        #[clap(short, long)]
        id: String,
    },
    /// Publish a listing to the DHT
    PublishListing {
        /// Listing ID
        #[clap(short, long)]
        id: String,
    },
    /// Accept an order
    AcceptOrder {
        /// Order ID
        #[clap(short, long)]
        id: String,
    },
    /// Reject an order
    RejectOrder {
        /// Order ID
        #[clap(short, long)]
        id: String,
        /// Reason for rejection
        #[clap(short, long)]
        reason: Option<String>,
    },
    /// Dispatch an order
    DispatchOrder {
        /// Order ID
        #[clap(short, long)]
        id: String,
        /// Tracking information
        #[clap(short, long)]
        tracking: Option<String>,
    },
    /// Mark an order as delivered
    MarkDelivered {
        /// Order ID
        #[clap(short, long)]
        id: String,
    },
}

/// Buyer operations commands
#[derive(Subcommand, Debug)]
enum BuyerCommands {
    /// Search for listings
    SearchListings {
        /// Search by tags (comma-separated)
        #[clap(short, long)]
        tags: Option<String>,
        /// Search by location (latitude,longitude,radius_km)
        #[clap(short, long)]
        location: Option<String>,
        /// Search by vendor public key
        #[clap(short, long)]
        vendor: Option<String>,
    },
    /// Create an order
    CreateOrder {
        /// Vendor listing ID
        #[clap(short, long)]
        listing_id: String,
        /// Item ID
        #[clap(short, long)]
        item_id: String,
        /// Quantity
        #[clap(short, long, default_value = "1")]
        quantity: u32,
        /// Payment method
        #[clap(short, long)]
        payment_method: String,
        /// Payment details
        #[clap(short, long)]
        payment_details: String,
    },
    /// Accept a delivery
    AcceptDelivery {
        /// Order ID
        #[clap(short, long)]
        id: String,
    },
    /// Reject a delivery
    RejectDelivery {
        /// Order ID
        #[clap(short, long)]
        id: String,
        /// Reason for rejection
        #[clap(short, long)]
        reason: Option<String>,
    },
    /// Request a return
    RequestReturn {
        /// Order ID
        #[clap(short, long)]
        id: String,
        /// Reason for return
        #[clap(short, long)]
        reason: String,
    },
    /// Rate a vendor
    RateVendor {
        /// Vendor public key
        #[clap(short, long)]
        vendor: String,
        /// Rating (1-5)
        #[clap(short, long)]
        rating: u8,
        /// Review text
        #[clap(short, long)]
        review: Option<String>,
        /// Order ID
        #[clap(short, long)]
        order_id: String,
    },
}

/// Order operations commands
#[derive(Subcommand, Debug)]
enum OrderCommands {
    /// List all orders
    List {
        /// Filter by state
        #[clap(short, long)]
        state: Option<String>,
    },
    /// Show details of an order
    Show {
        /// Order ID
        #[clap(short, long)]
        id: String,
    },
    /// Process a message for an order
    ProcessMessage {
        /// Order ID
        #[clap(short, long)]
        order_id: String,
        /// Message file path (JSON)
        #[clap(short, long)]
        message: PathBuf,
    },
}

/// Payment operations commands
#[derive(Subcommand, Debug)]
enum PaymentCommands {
    /// Create a payment request
    CreateRequest {
        /// Order ID
        #[clap(short, long)]
        order_id: String,
        /// Payment address
        #[clap(short, long)]
        address: String,
    },
    /// Verify a payment
    Verify {
        /// Payment ID
        #[clap(short, long)]
        id: String,
        /// Transaction ID
        #[clap(short, long)]
        transaction_id: String,
    },
    /// Create an escrow
    CreateEscrow {
        /// Payment ID
        #[clap(short, long)]
        id: String,
        /// Buyer public key
        #[clap(short, long)]
        buyer: String,
        /// Vendor public key
        #[clap(short, long)]
        vendor: String,
        /// Mediator public key
        #[clap(short, long)]
        mediator: String,
    },
    /// Release funds from escrow
    ReleaseEscrow {
        /// Payment ID
        #[clap(short, long)]
        id: String,
        /// Signatures (comma-separated)
        #[clap(short, long)]
        signatures: String,
    },
    /// Process a refund
    Refund {
        /// Payment ID
        #[clap(short, long)]
        id: String,
        /// Refund amount (optional)
        #[clap(short, long)]
        amount: Option<String>,
        /// Reason for refund
        #[clap(short, long)]
        reason: String,
    },
}

/// Dispute operations commands
#[derive(Subcommand, Debug)]
enum DisputeCommands {
    /// Initiate a dispute
    Initiate {
        /// Order ID
        #[clap(short, long)]
        order_id: String,
        /// Reason for dispute
        #[clap(short, long)]
        reason: String,
    },
    /// Submit evidence for a dispute
    SubmitEvidence {
        /// Dispute ID
        #[clap(short, long)]
        dispute_id: String,
        /// Evidence description
        #[clap(short, long)]
        description: String,
        /// Evidence file path
        #[clap(short, long)]
        file: Option<PathBuf>,
    },
    /// Resolve a dispute
    Resolve {
        /// Dispute ID
        #[clap(short, long)]
        dispute_id: String,
        /// Outcome (buyer, vendor, compromise)
        #[clap(short, long)]
        outcome: String,
        /// Resolution description
        #[clap(short, long)]
        description: String,
    },
    /// List all disputes
    List,
    /// Show details of a dispute
    Show {
        /// Dispute ID
        #[clap(short, long)]
        id: String,
    },
}

/// Network operations commands
#[derive(Subcommand, Debug)]
enum NetworkCommands {
    /// Start a network node
    Start {
        /// Listen address
        #[clap(short, long, default_value = "/ip4/0.0.0.0/tcp/0")]
        listen: String,
        /// Bootstrap nodes (comma-separated)
        #[clap(short, long)]
        bootstrap: Option<String>,
    },
    /// Connect to a peer
    Connect {
        /// Peer address
        #[clap(short, long)]
        address: String,
    },
    /// Send a message to a peer
    SendMessage {
        /// Peer ID
        #[clap(short, long)]
        peer: String,
        /// Message content
        #[clap(short, long)]
        message: String,
    },
    /// List connected peers
    ListPeers,
}

/// Identity information
#[derive(Serialize, Deserialize, Debug, Clone)]
struct IdentityInfo {
    /// Identity name
    name: String,
    /// Identity type (buyer, vendor, or mediator)
    identity_type: String,
    /// Secp256k1 private key (hex encoded)
    private_key: String,
    /// Secp256k1 public key (hex encoded)
    public_key: String,
    /// libp2p keypair (base64 encoded)
    libp2p_keypair: String,
    /// Created timestamp
    created: u64,
}

/// CLI state
#[derive(Serialize, Deserialize, Debug, Clone)]
struct CliState {
    /// Active identity name
    active_identity: Option<String>,
    /// Known identities
    identities: HashMap<String, IdentityInfo>,
    /// Vendor listings
    listings: HashMap<String, VendorListing>,
    /// Orders
    orders: HashMap<String, Order>,
    /// Messages
    messages: HashMap<String, Message>,
    /// Payments
    payments: HashMap<String, PaymentInfo>,
    /// Disputes
    disputes: HashMap<String, DisputeInfo>,
}

/// Payment information
#[derive(Serialize, Deserialize, Debug, Clone)]
struct PaymentInfo {
    /// Payment ID
    id: String,
    /// Order ID
    order_id: String,
    /// Payment method
    method: String,
    /// Amount
    amount: String,
    /// Payment address
    address: String,
    /// Transaction ID
    transaction_id: Option<String>,
    /// Status
    status: String,
    /// Created timestamp
    created: u64,
    /// Updated timestamp
    updated: u64,
    /// Escrow information
    escrow: Option<EscrowInfo>,
    /// Refund information
    refund: Option<RefundInfo>,
}

/// Escrow information
#[derive(Serialize, Deserialize, Debug, Clone)]
struct EscrowInfo {
    /// Escrow type
    escrow_type: String,
    /// Escrow address
    address: String,
    /// Participant keys
    participants: Vec<String>,
    /// Required signatures
    required_signatures: u32,
    /// Status
    status: String,
    /// Created timestamp
    created: u64,
    /// Release transaction ID
    release_transaction_id: Option<String>,
}

/// Refund information
#[derive(Serialize, Deserialize, Debug, Clone)]
struct RefundInfo {
    /// Refund amount
    amount: Option<String>,
    /// Transaction ID
    transaction_id: String,
    /// Reason
    reason: String,
    /// Timestamp
    timestamp: u64,
}

/// Dispute information
#[derive(Serialize, Deserialize, Debug, Clone)]
struct DisputeInfo {
    /// Dispute ID
    id: String,
    /// Order ID
    order_id: String,
    /// Buyer public key
    buyer_public_key: String,
    /// Vendor public key
    vendor_public_key: String,
    /// Mediator public key
    mediator_public_key: Option<String>,
    /// Reason
    reason: String,
    /// State
    state: String,
    /// Evidence
    evidence: Vec<EvidenceInfo>,
    /// Resolution
    resolution: Option<ResolutionInfo>,
    /// Created timestamp
    created: u64,
    /// Updated timestamp
    updated: u64,
    /// Initiated by
    initiated_by: String,
}

/// Evidence information
#[derive(Serialize, Deserialize, Debug, Clone)]
struct EvidenceInfo {
    /// Evidence ID
    id: String,
    /// Evidence type
    evidence_type: String,
    /// Description
    description: String,
    /// Submitted by
    submitted_by: String,
    /// Timestamp
    timestamp: u64,
}

/// Resolution information
#[derive(Serialize, Deserialize, Debug, Clone)]
struct ResolutionInfo {
    /// Outcome
    outcome: String,
    /// Description
    description: String,
    /// Resolved by
    resolved_by: String,
    /// Timestamp
    timestamp: u64,
}

/// Main function
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();

    // Parse command line arguments
    let cli = Cli::parse();

    // Ensure config directory exists
    let config_dir = expand_path(&cli.config_dir)?;
    fs::create_dir_all(&config_dir).await?;

    // Load or create state
    let state_path = config_dir.join("state.json");
    let mut state = if state_path.exists() {
        let state_json = fs::read_to_string(&state_path).await?;
        serde_json::from_str(&state_json)?
    } else {
        CliState {
            active_identity: None,
            identities: HashMap::new(),
            listings: HashMap::new(),
            orders: HashMap::new(),
            messages: HashMap::new(),
            payments: HashMap::new(),
            disputes: HashMap::new(),
        }
    };

    // Process command
    match &cli.command {
        Commands::Identity { command } => {
            handle_identity_command(command, &mut state, &config_dir).await?;
        }
        Commands::Vendor { command } => {
            handle_vendor_command(command, &mut state, &config_dir).await?;
        }
        Commands::Buyer { command } => {
            handle_buyer_command(command, &mut state, &config_dir).await?;
        }
        Commands::Order { command } => {
            handle_order_command(command, &mut state, &config_dir).await?;
        }
        Commands::Payment { command } => {
            handle_payment_command(command, &mut state, &config_dir).await?;
        }
        Commands::Dispute { command } => {
            handle_dispute_command(command, &mut state, &config_dir).await?;
        }
        Commands::Network { command } => {
            handle_network_command(command, &mut state, &config_dir).await?;
        }
    }

    // Save state
    let state_json = serde_json::to_string_pretty(&state)?;
    fs::write(&state_path, state_json).await?;

    Ok(())
}

/// Handle identity commands
async fn handle_identity_command(
    command: &IdentityCommands,
    state: &mut CliState,
    config_dir: &Path,
) -> Result<()> {
    match command {
        IdentityCommands::Create {
            name,
            identity_type,
        } => {
            // Check if identity already exists
            if state.identities.contains_key(name) {
                return Err(anyhow!("Identity '{}' already exists", name));
            }

            // Validate identity type
            let valid_types = ["buyer", "vendor", "mediator"];
            if !valid_types.contains(&identity_type.as_str()) {
                return Err(anyhow!(
                    "Invalid identity type. Must be one of: buyer, vendor, mediator"
                ));
            }

            // Generate Secp256k1 keypair
            let secp = Secp256k1::new();
            let keypair = Crypto::generate_identity_keypair()?;

            // Generate libp2p keypair
            let libp2p_keypair = identity::Keypair::generate_ed25519();
            let libp2p_keypair_bytes = libp2p_keypair.to_protobuf_encoding()?;
            let libp2p_keypair_base64 = base64::encode(&libp2p_keypair_bytes);

            // Create identity info
            let identity_info = IdentityInfo {
                name: name.clone(),
                identity_type: identity_type.clone(),
                private_key: hex::encode(keypair.private_key.secret_bytes()),
                public_key: hex::encode(keypair.public_key.serialize()),
                libp2p_keypair: libp2p_keypair_base64,
                created: Utc::now().timestamp() as u64,
            };

            // Add to state
            state.identities.insert(name.clone(), identity_info);

            // Set as active if no active identity
            if state.active_identity.is_none() {
                state.active_identity = Some(name.clone());
            }

            println!("Created new {} identity: {}", identity_type, name);
            println!(
                "Public key: {}",
                hex::encode(keypair.public_key.serialize())
            );
            println!("Peer ID: {}", PeerId::from(libp2p_keypair.public()));

            Ok(())
        }
        IdentityCommands::List => {
            println!("Identities:");

            if state.identities.is_empty() {
                println!("  No identities found");
                return Ok(());
            }

            for (name, info) in &state.identities {
                let active = if Some(name.as_str()) == state.active_identity.as_deref() {
                    " (active)"
                } else {
                    ""
                };

                println!("  {} - {}{}", name, info.identity_type, active);
            }

            Ok(())
        }
        IdentityCommands::Show { name } => {
            // Get identity
            let identity = state
                .identities
                .get(name)
                .ok_or_else(|| anyhow!("Identity '{}' not found", name))?;

            // Decode libp2p keypair
            let libp2p_keypair_bytes = base64::decode(&identity.libp2p_keypair)?;
            let libp2p_keypair = identity::Keypair::from_protobuf_encoding(&libp2p_keypair_bytes)?;
            let peer_id = PeerId::from(libp2p_keypair.public());

            println!("Identity: {}", name);
            println!("Type: {}", identity.identity_type);
            println!("Public key: {}", identity.public_key);
            println!("Peer ID: {}", peer_id);
            println!(
                "Created: {}",
                chrono::NaiveDateTime::from_timestamp_opt(identity.created as i64, 0).unwrap()
            );

            Ok(())
        }
        IdentityCommands::SetActive { name } => {
            // Check if identity exists
            if !state.identities.contains_key(name) {
                return Err(anyhow!("Identity '{}' not found", name));
            }

            // Set as active
            state.active_identity = Some(name.clone());

            println!("Set '{}' as the active identity", name);

            Ok(())
        }
    }
}

/// Handle vendor commands
async fn handle_vendor_command(
    command: &VendorCommands,
    state: &mut CliState,
    config_dir: &Path,
) -> Result<()> {
    // Get active identity
    let active_identity = get_active_identity(state)?;

    // Check if identity is a vendor
    if active_identity.identity_type != "vendor" {
        return Err(anyhow!("Active identity is not a vendor"));
    }

    // Create vendor API
    let vendor_api = create_vendor_api(active_identity)?;

    match command {
        VendorCommands::CreateListing {
            name,
            item_name,
            description,
            price,
            tags,
            payment_methods,
        } => {
            // Parse tags
            let tags_vec = tags
                .split(',')
                .map(|s| s.trim().to_string())
                .collect::<Vec<_>>();

            // Parse payment methods
            let payment_methods_vec = payment_methods
                .split(',')
                .map(|s| s.trim().to_string())
                .collect::<Vec<_>>();

            // Create item
            let item = Item::new(Uuid::new_v4().to_string(), item_name.clone())
                .with_description(description.clone())
                .with_price(price.clone())
                .with_availability("In Stock".to_string())
                .with_tags(tags_vec);

            // Create listing
            let listing = vendor_api.create_listing(
                vec![item],
                payment_methods_vec,
                Some(name.clone()),
                None, // No location for now
                None, // No service terms for now
            )?;

            // Add to state
            state
                .listings
                .insert(listing.vendor_identity_key_public.clone(), listing.clone());

            println!("Created new listing: {}", name);
            println!("Listing ID: {}", listing.vendor_identity_key_public);

            Ok(())
        }
        VendorCommands::ListListings => {
            println!("Vendor Listings:");

            if state.listings.is_empty() {
                println!("  No listings found");
                return Ok(());
            }

            for (id, listing) in &state.listings {
                let name = listing.vendor_name.as_deref().unwrap_or("Unnamed");
                let items_count = listing.items_offered.len();

                println!("  {} - {} ({} items)", name, id, items_count);
            }

            Ok(())
        }
        VendorCommands::ShowListing { id } => {
            // Get listing
            let listing = state
                .listings
                .get(id)
                .ok_or_else(|| anyhow!("Listing '{}' not found", id))?;

            println!(
                "Listing: {}",
                listing.vendor_name.as_deref().unwrap_or("Unnamed")
            );
            println!("ID: {}", listing.vendor_identity_key_public);
            println!("Items:");

            for item in &listing.items_offered {
                println!(
                    "  - {} ({})",
                    item.item_name,
                    item.price.as_deref().unwrap_or("No price")
                );
                if let Some(desc) = &item.description {
                    println!("    Description: {}", desc);
                }
                println!("    Tags: {}", item.tags.join(", "));
            }

            println!(
                "Payment methods: {}",
                listing.payment_methods_accepted.join(", ")
            );

            if let Some(terms) = &listing.service_terms {
                println!("Service terms: {}", terms);
            }

            Ok(())
        }
        VendorCommands::PublishListing { id } => {
            // Get listing
            let listing = state
                .listings
                .get(id)
                .ok_or_else(|| anyhow!("Listing '{}' not found", id))?;

            // Create DHT client
            let bootstrap_addresses = vec![]; // Empty for now
            let dht_client = DhtClient::new(bootstrap_addresses).await?;

            // Publish listing
            dht_client.publish_listing(listing.clone()).await?;

            println!("Published listing '{}' to the DHT", id);

            // Shutdown DHT client
            dht_client.shutdown().await?;

            Ok(())
        }
        VendorCommands::AcceptOrder { id } => {
            // Get order
            let order = state
                .orders
                .get(id)
                .ok_or_else(|| anyhow!("Order '{}' not found", id))?;

            // Accept order
            let acceptance_message = vendor_api.accept_order(order)?;

            // Add message to state
            state.messages.insert(
                acceptance_message.order_id.clone(),
                acceptance_message.clone(),
            );

            // Update order state
            let mut updated_order = order.clone();
            vendor_api.process_message(&mut updated_order, &acceptance_message)?;
            state.orders.insert(id.clone(), updated_order);

            println!("Accepted order '{}'", id);

            Ok(())
        }
        VendorCommands::RejectOrder { id, reason } => {
            // Get order
            let order = state
                .orders
                .get(id)
                .ok_or_else(|| anyhow!("Order '{}' not found", id))?;

            // Reject order
            let rejection_message = vendor_api.reject_order(order, reason.clone())?;

            // Add message to state
            state.messages.insert(
                rejection_message.order_id.clone(),
                rejection_message.clone(),
            );

            // Update order state
            let mut updated_order = order.clone();
            vendor_api.process_message(&mut updated_order, &rejection_message)?;
            state.orders.insert(id.clone(), updated_order);

            println!("Rejected order '{}'", id);
            if let Some(r) = reason {
                println!("Reason: {}", r);
            }

            Ok(())
        }
        VendorCommands::DispatchOrder { id, tracking } => {
            // Get order
            let order = state
                .orders
                .get(id)
                .ok_or_else(|| anyhow!("Order '{}' not found", id))?;

            // Dispatch order
            let dispatch_message = vendor_api.dispatch_order(order, tracking.clone())?;

            // Add message to state
            state
                .messages
                .insert(dispatch_message.order_id.clone(), dispatch_message.clone());

            // Update order state
            let mut updated_order = order.clone();
            vendor_api.process_message(&mut updated_order, &dispatch_message)?;
            state.orders.insert(id.clone(), updated_order);

            println!("Dispatched order '{}'", id);
            if let Some(t) = tracking {
                println!("Tracking: {}", t);
            }

            Ok(())
        }
        VendorCommands::MarkDelivered { id } => {
            // Get order
            let order = state
                .orders
                .get(id)
                .ok_or_else(|| anyhow!("Order '{}' not found", id))?;

            // Mark as delivered
            let delivery_message = vendor_api.mark_as_delivered(order)?;

            // Add message to state
            state
                .messages
                .insert(delivery_message.order_id.clone(), delivery_message.clone());

            // Update order state
            let mut updated_order = order.clone();
            vendor_api.process_message(&mut updated_order, &delivery_message)?;
            state.orders.insert(id.clone(), updated_order);

            println!("Marked order '{}' as delivered", id);

            Ok(())
        }
    }
}

/// Handle buyer commands
async fn handle_buyer_command(
    command: &BuyerCommands,
    state: &mut CliState,
    config_dir: &Path,
) -> Result<()> {
    // Get active identity
    let active_identity = get_active_identity(state)?;

    // Check if identity is a buyer
    if active_identity.identity_type != "buyer" {
        return Err(anyhow!("Active identity is not a buyer"));
    }

    // Create buyer API
    let buyer_api = create_buyer_api(active_identity)?;

    match command {
        BuyerCommands::SearchListings {
            tags,
            location,
            vendor,
        } => {
            // Create DHT client
            let bootstrap_addresses = vec![]; // Empty for now
            let dht_client = DhtClient::new(bootstrap_addresses).await?;

            let mut listings = Vec::new();

            // Search by tags
            if let Some(tags_str) = tags {
                let tags_vec = tags_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect::<Vec<_>>();

                let tag_listings = dht_client.search_by_tags(tags_vec).await?;
                listings.extend(tag_listings);
            }

            // Search by location
            if let Some(loc_str) = location {
                let parts: Vec<&str> = loc_str.split(',').collect();
                if parts.len() != 3 {
                    return Err(anyhow!(
                        "Invalid location format. Use 'latitude,longitude,radius_km'"
                    ));
                }

                let latitude = parts[0].parse::<f64>()?;
                let longitude = parts[1].parse::<f64>()?;
                let radius = parts[2].parse::<f64>()?;

                let loc_listings = dht_client
                    .search_by_location(latitude, longitude, radius)
                    .await?;
                listings.extend(loc_listings);
            }

            // Search by vendor
            if let Some(vendor_key) = vendor {
                if let Some(listing) = dht_client.get_listing(vendor_key.clone()).await? {
                    listings.push(listing);
                }
            }

            // Deduplicate listings
            let mut unique_listings = HashMap::new();
            for listing in listings {
                unique_listings.insert(listing.vendor_identity_key_public.clone(), listing);
            }

            // Display results
            println!("Found {} listings:", unique_listings.len());

            for (id, listing) in unique_listings {
                let name = listing.vendor_name.as_deref().unwrap_or("Unnamed");
                let items_count = listing.items_offered.len();

                println!("  {} - {} ({} items)", name, id, items_count);
                println!("    Items:");

                for item in &listing.items_offered {
                    println!(
                        "      - {} ({})",
                        item.item_name,
                        item.price.as_deref().unwrap_or("No price")
                    );
                }

                println!(
                    "    Payment methods: {}",
                    listing.payment_methods_accepted.join(", ")
                );

                // Add to state
                state.listings.insert(id, listing);
            }

            // Shutdown DHT client
            dht_client.shutdown().await?;

            Ok(())
        }
        BuyerCommands::CreateOrder {
            listing_id,
            item_id,
            quantity,
            payment_method,
            payment_details,
        } => {
            // Get listing
            let listing = state
                .listings
                .get(listing_id)
                .ok_or_else(|| anyhow!("Listing '{}' not found", listing_id))?;

            // Find item
            let item = listing
                .items_offered
                .iter()
                .find(|i| i.item_id == *item_id)
                .ok_or_else(|| anyhow!("Item '{}' not found in listing", item_id))?;

            // Create order item
            let order_item = OrderItem::new(item.item_id.clone(), *quantity);

            // Calculate total amount
            let price = item
                .price
                .as_ref()
                .ok_or_else(|| anyhow!("Item has no price"))?
                .parse::<f64>()?;
            let total_amount = (price * (*quantity as f64)).to_string();

            // Create order
            let order = buyer_api.create_order(
                listing,
                vec![order_item],
                total_amount,
                payment_method.clone(),
                payment_details.clone(),
                None, // No location for now
            )?;

            // Add to state
            state.orders.insert(order.order_id.clone(), order.clone());

            println!("Created new order: {}", order.order_id);
            println!("Total amount: {}", order.total_amount);
            println!("Payment method: {}", order.payment_method);

            Ok(())
        }
        BuyerCommands::AcceptDelivery { id } => {
            // Get order
            let order = state
                .orders
                .get(id)
                .ok_or_else(|| anyhow!("Order '{}' not found", id))?;

            // Accept delivery
            let acceptance_message = buyer_api.accept_delivery(order)?;

            // Add message to state
            state.messages.insert(
                acceptance_message.order_id.clone(),
                acceptance_message.clone(),
            );

            // Update order state
            let mut updated_order = order.clone();
            buyer_api.process_message(&mut updated_order, &acceptance_message)?;
            state.orders.insert(id.clone(), updated_order);

            println!("Accepted delivery for order '{}'", id);

            Ok(())
        }
        BuyerCommands::RejectDelivery { id, reason } => {
            // Get order
            let order = state
                .orders
                .get(id)
                .ok_or_else(|| anyhow!("Order '{}' not found", id))?;

            // Reject delivery
            let rejection_message = buyer_api.reject_delivery(order, reason.clone())?;

            // Add message to state
            state.messages.insert(
                rejection_message.order_id.clone(),
                rejection_message.clone(),
            );

            // Update order state
            let mut updated_order = order.clone();
            buyer_api.process_message(&mut updated_order, &rejection_message)?;
            state.orders.insert(id.clone(), updated_order);

            println!("Rejected delivery for order '{}'", id);
            if let Some(r) = reason {
                println!("Reason: {}", r);
            }

            Ok(())
        }
        BuyerCommands::RequestReturn { id, reason } => {
            // Get order
            let order = state
                .orders
                .get(id)
                .ok_or_else(|| anyhow!("Order '{}' not found", id))?;

            // Request return
            let return_message = buyer_api.request_return(order, reason.clone())?;

            // Add message to state
            state
                .messages
                .insert(return_message.order_id.clone(), return_message.clone());

            // Update order state
            let mut updated_order = order.clone();
            buyer_api.process_message(&mut updated_order, &return_message)?;
            state.orders.insert(id.clone(), updated_order);

            println!("Requested return for order '{}'", id);
            println!("Reason: {}", reason);

            Ok(())
        }
        BuyerCommands::RateVendor {
            vendor,
            rating,
            review,
            order_id,
        } => {
            // Get order
            let order = state
                .orders
                .get(order_id)
                .ok_or_else(|| anyhow!("Order '{}' not found", order_id))?;

            // Create DHT client
            let bootstrap_addresses = vec![]; // Empty for now
            let dht_client = DhtClient::new(bootstrap_addresses).await?;

            // Create reputation client
            let mut reputation_client =
                my_p2p_order_sdk::core::reputation::ReputationClient::new(dht_client);

            // Set buyer keys
            let private_key = SecretKey::from_slice(&hex::decode(&active_identity.private_key)?)?;
            let public_key = PublicKey::from_slice(&hex::decode(&active_identity.public_key)?)?;
            reputation_client.set_buyer_keys(private_key, public_key);

            // Submit rating
            reputation_client
                .submit_rating(vendor.clone(), *rating, review.clone(), &[order.clone()])
                .await?;

            println!("Submitted rating for vendor '{}'", vendor);
            println!("Rating: {}/5", rating);
            if let Some(r) = review {
                println!("Review: {}", r);
            }

            Ok(())
        }
    }
}

/// Handle order commands
async fn handle_order_command(
    command: &OrderCommands,
    state: &mut CliState,
    config_dir: &Path,
) -> Result<()> {
    match command {
        OrderCommands::List { state: order_state } => {
            println!("Orders:");

            if state.orders.is_empty() {
                println!("  No orders found");
                return Ok(());
            }

            for (id, order) in &state.orders {
                // Filter by state if specified
                if let Some(state_filter) = order_state {
                    if order.current_state != *state_filter {
                        continue;
                    }
                }

                println!("  {} - State: {}", id, order.current_state);
                println!("    Buyer: {}", order.buyer_public_key);
                println!("    Vendor: {}", order.vendor_public_key);
                println!("    Total: {}", order.total_amount);
                println!("    Payment: {}", order.payment_method);
                println!("    Items: {} item(s)", order.order_items.len());
            }

            Ok(())
        }
        OrderCommands::Show { id } => {
            // Get order
            let order = state
                .orders
                .get(id)
                .ok_or_else(|| anyhow!("Order '{}' not found", id))?;

            println!("Order: {}", order.order_id);
            println!("State: {}", order.current_state);
            println!("Buyer: {}", order.buyer_public_key);
            println!("Vendor: {}", order.vendor_public_key);
            println!("Total: {}", order.total_amount);
            println!("Payment method: {}", order.payment_method);
            println!("Payment details: {}", order.payment_details);
            println!(
                "Created: {}",
                chrono::NaiveDateTime::from_timestamp_opt(order.created_timestamp as i64, 0)
                    .unwrap()
            );

            println!("Items:");
            for item in &order.order_items {
                println!("  - {} (Quantity: {})", item.item_id, item.quantity);
            }

            // Show related messages
            let messages: Vec<_> = state
                .messages
                .values()
                .filter(|m| m.order_id == *id)
                .collect();

            if !messages.is_empty() {
                println!("Messages:");
                for message in messages {
                    println!("  - Type: {}", message.message_type);
                    if let Some(status) = &message.status {
                        println!("    Status: {}", status);
                    }
                    println!(
                        "    Timestamp: {}",
                        chrono::NaiveDateTime::from_timestamp_opt(message.timestamp as i64, 0)
                            .unwrap()
                    );
                }
            }

            Ok(())
        }
        OrderCommands::ProcessMessage { order_id, message } => {
            // Get order
            let order = state
                .orders
                .get(order_id)
                .ok_or_else(|| anyhow!("Order '{}' not found", order_id))?;

            // Read message file
            let message_json = fs::read_to_string(message).await?;
            let message: Message = serde_json::from_str(&message_json)?;

            // Get active identity
            let active_identity = get_active_identity(state)?;

            // Process message based on identity type
            let mut updated_order = order.clone();

            if active_identity.identity_type == "buyer" {
                let buyer_api = create_buyer_api(active_identity)?;
                buyer_api.process_message(&mut updated_order, &message)?;
            } else if active_identity.identity_type == "vendor" {
                let vendor_api = create_vendor_api(active_identity)?;
                vendor_api.process_message(&mut updated_order, &message)?;
            } else {
                return Err(anyhow!(
                    "Active identity type '{}' cannot process order messages",
                    active_identity.identity_type
                ));
            }

            // Update order in state
            state.orders.insert(order_id.clone(), updated_order.clone());

            // Add message to state
            state
                .messages
                .insert(message.order_id.clone(), message.clone());

            println!("Processed message for order '{}'", order_id);
            println!("New order state: {}", updated_order.current_state);

            Ok(())
        }
    }
}

/// Handle payment commands
async fn handle_payment_command(
    command: &PaymentCommands,
    state: &mut CliState,
    config_dir: &Path,
) -> Result<()> {
    // Get active identity
    let active_identity = get_active_identity(state)?;

    // Create payment manager
    let mut payment_manager = PaymentManager::new();
    let private_key = SecretKey::from_slice(&hex::decode(&active_identity.private_key)?)?;
    let public_key = PublicKey::from_slice(&hex::decode(&active_identity.public_key)?)?;
    payment_manager.set_keys(private_key, public_key);

    match command {
        PaymentCommands::CreateRequest { order_id, address } => {
            // Get order
            let order = state
                .orders
                .get(order_id)
                .ok_or_else(|| anyhow!("Order '{}' not found", order_id))?;

            // Create payment request
            let payment = payment_manager.create_payment_request(order, address.clone())?;

            // Convert to PaymentInfo
            let payment_info = PaymentInfo {
                id: payment.payment_id.clone(),
                order_id: payment.order_id.clone(),
                method: payment.method.as_str(),
                amount: payment.amount.clone(),
                address: payment.payment_address.clone(),
                transaction_id: payment.transaction_id.clone(),
                status: payment.status.as_str().to_string(),
                created: payment.created_timestamp,
                updated: payment.updated_timestamp,
                escrow: None,
                refund: None,
            };

            // Add to state
            state
                .payments
                .insert(payment.payment_id.clone(), payment_info);

            println!("Created payment request for order '{}'", order_id);
            println!("Payment ID: {}", payment.payment_id);
            println!("Payment address: {}", payment.payment_address);
            println!("Amount: {}", payment.amount);
            println!("Method: {}", payment.method.as_str());

            Ok(())
        }
        PaymentCommands::Verify { id, transaction_id } => {
            // Get payment
            let payment_info = state
                .payments
                .get(id)
                .ok_or_else(|| anyhow!("Payment '{}' not found", id))?;

            // Update transaction ID
            let mut updated_info = payment_info.clone();
            updated_info.transaction_id = Some(transaction_id.clone());

            // Verify payment
            let payment_method = PaymentMethod::from_str(&payment_info.method)
                .ok_or_else(|| anyhow!("Invalid payment method: {}", payment_info.method))?;

            let status = payment_manager.verify_payment(id, &payment_method).await?;

            // Update status
            updated_info.status = status.as_str().to_string();
            updated_info.updated = Utc::now().timestamp() as u64;

            // Update in state
            state.payments.insert(id.clone(), updated_info.clone());

            println!("Verified payment '{}'", id);
            println!("Transaction ID: {}", transaction_id);
            println!("Status: {}", updated_info.status);

            Ok(())
        }
        PaymentCommands::CreateEscrow {
            id,
            buyer,
            vendor,
            mediator,
        } => {
            // Get payment
            let payment_info = state
                .payments
                .get(id)
                .ok_or_else(|| anyhow!("Payment '{}' not found", id))?;

            // Create escrow
            let payment_method = PaymentMethod::from_str(&payment_info.method)
                .ok_or_else(|| anyhow!("Invalid payment method: {}", payment_info.method))?;

            let escrow = payment_manager
                .create_escrow(id, &payment_method, buyer, vendor, mediator)
                .await?;

            // Convert to EscrowInfo
            let escrow_info = EscrowInfo {
                escrow_type: match escrow.escrow_type {
                    EscrowType::Multisig => "multisig".to_string(),
                    EscrowType::SmartContract => "smart_contract".to_string(),
                    EscrowType::ThirdParty => "third_party".to_string(),
                },
                address: escrow.escrow_address.clone(),
                participants: escrow.participant_keys.clone(),
                required_signatures: escrow.required_signatures,
                status: escrow.status.as_str().to_string(),
                created: escrow.created_timestamp,
                release_transaction_id: escrow.release_transaction_id.clone(),
            };

            // Update payment info
            let mut updated_info = payment_info.clone();
            updated_info.escrow = Some(escrow_info);
            updated_info.status = "in_escrow".to_string();
            updated_info.updated = Utc::now().timestamp() as u64;

            // Update in state
            state.payments.insert(id.clone(), updated_info);

            println!("Created escrow for payment '{}'", id);
            println!("Escrow address: {}", escrow.escrow_address);
            println!("Escrow type: {}", escrow.escrow_type.as_str());
            println!(
                "Required signatures: {}/{}",
                escrow.required_signatures,
                escrow.participant_keys.len()
            );

            Ok(())
        }
        PaymentCommands::ReleaseEscrow { id, signatures } => {
            // Get payment
            let payment_info = state
                .payments
                .get(id)
                .ok_or_else(|| anyhow!("Payment '{}' not found", id))?;

            // Check if payment is in escrow
            if payment_info.escrow.is_none() {
                return Err(anyhow!("Payment '{}' is not in escrow", id));
            }

            // Parse signatures
            let signatures_vec = signatures
                .split(',')
                .map(|s| s.trim().to_string())
                .collect::<Vec<_>>();

            // Release from escrow
            let payment_method = PaymentMethod::from_str(&payment_info.method)
                .ok_or_else(|| anyhow!("Invalid payment method: {}", payment_info.method))?;

            let tx_id = payment_manager
                .release_from_escrow(id, &payment_method, signatures_vec)
                .await?;

            // Update payment info
            let mut updated_info = payment_info.clone();
            if let Some(escrow) = &mut updated_info.escrow {
                escrow.status = "escrow_released".to_string();
                escrow.release_transaction_id = Some(tx_id.clone());
            }
            updated_info.status = "completed".to_string();
            updated_info.updated = Utc::now().timestamp() as u64;

            // Update in state
            state.payments.insert(id.clone(), updated_info);

            println!("Released funds from escrow for payment '{}'", id);
            println!("Transaction ID: {}", tx_id);

            Ok(())
        }
        PaymentCommands::Refund { id, amount, reason } => {
            // Get payment
            let payment_info = state
                .payments
                .get(id)
                .ok_or_else(|| anyhow!("Payment '{}' not found", id))?;

            // Process refund
            let payment_method = PaymentMethod::from_str(&payment_info.method)
                .ok_or_else(|| anyhow!("Invalid payment method: {}", payment_info.method))?;

            let refund = payment_manager
                .process_refund(id, &payment_method, amount.clone(), reason.clone())
                .await?;

            // Convert to RefundInfo
            let refund_info = RefundInfo {
                amount: refund.amount.clone(),
                transaction_id: refund.transaction_id.clone(),
                reason: refund.reason.clone(),
                timestamp: refund.timestamp,
            };

            // Update payment info
            let mut updated_info = payment_info.clone();
            updated_info.refund = Some(refund_info);
            updated_info.status =
                if amount.is_some() && amount.as_ref() == Some(&payment_info.amount) {
                    "refunded".to_string()
                } else {
                    "partially_refunded".to_string()
                };
            updated_info.updated = Utc::now().timestamp() as u64;

            // Update in state
            state.payments.insert(id.clone(), updated_info);

            println!("Processed refund for payment '{}'", id);
            println!("Transaction ID: {}", refund.transaction_id);
            if let Some(amt) = &refund.amount {
                println!("Amount: {}", amt);
            } else {
                println!("Amount: Full refund");
            }
            println!("Reason: {}", refund.reason);

            Ok(())
        }
    }
}

/// Handle dispute commands
async fn handle_dispute_command(
    command: &DisputeCommands,
    state: &mut CliState,
    config_dir: &Path,
) -> Result<()> {
    // Get active identity
    let active_identity = get_active_identity(state)?;

    // Determine party type
    let party_type = match active_identity.identity_type.as_str() {
        "buyer" => DisputeParty::Buyer,
        "vendor" => DisputeParty::Vendor,
        "mediator" => DisputeParty::Mediator,
        _ => return Err(anyhow!("Invalid identity type for dispute handling")),
    };

    // Create dispute client
    let mut dispute_client = DisputeClient::new(party_type.clone());
    let private_key = SecretKey::from_slice(&hex::decode(&active_identity.private_key)?)?;
    let public_key = PublicKey::from_slice(&hex::decode(&active_identity.public_key)?)?;
    dispute_client.set_keys(private_key, public_key);

    match command {
        DisputeCommands::Initiate { order_id, reason } => {
            // Get order
            let order = state
                .orders
                .get(order_id)
                .ok_or_else(|| anyhow!("Order '{}' not found", order_id))?;

            // Initiate dispute
            let (dispute, message) = dispute_client.initiate_dispute(order, reason.clone())?;

            // Convert to DisputeInfo
            let dispute_info = DisputeInfo {
                id: dispute.id.clone(),
                order_id: dispute.order_id.clone(),
                buyer_public_key: dispute.buyer_public_key.clone(),
                vendor_public_key: dispute.vendor_public_key.clone(),
                mediator_public_key: dispute.mediator_public_key.clone(),
                reason: dispute.reason.clone(),
                state: dispute.state.as_str().to_string(),
                evidence: Vec::new(),
                resolution: None,
                created: dispute.created_timestamp,
                updated: dispute.updated_timestamp,
                initiated_by: match dispute.initiated_by {
                    DisputeParty::Buyer => "buyer".to_string(),
                    DisputeParty::Vendor => "vendor".to_string(),
                    DisputeParty::Mediator => "mediator".to_string(),
                },
            };

            // Add to state
            state.disputes.insert(dispute.id.clone(), dispute_info);
            state.messages.insert(message.order_id.clone(), message);

            println!("Initiated dispute for order '{}'", order_id);
            println!("Dispute ID: {}", dispute.id);
            println!("Reason: {}", dispute.reason);

            Ok(())
        }
        DisputeCommands::SubmitEvidence {
            dispute_id,
            description,
            file,
        } => {
            // Get dispute
            let dispute_info = state
                .disputes
                .get(dispute_id)
                .ok_or_else(|| anyhow!("Dispute '{}' not found", dispute_id))?;

            // Create evidence type
            let evidence_type = if let Some(file_path) = file {
                let content = fs::read(&file_path).await?;
                let file_name = file_path
                    .file_name()
                    .ok_or_else(|| anyhow!("Invalid file path"))?
                    .to_string_lossy();

                if file_name.ends_with(".jpg") || file_name.ends_with(".png") {
                    EvidenceType::Image(base64::encode(&content))
                } else if file_name.ends_with(".pdf") || file_name.ends_with(".doc") {
                    EvidenceType::Document(base64::encode(&content))
                } else {
                    EvidenceType::Text(String::from_utf8_lossy(&content).to_string())
                }
            } else {
                EvidenceType::Text(description.clone())
            };

            // Submit evidence
            let (evidence, message) =
                dispute_client.submit_evidence(dispute_id, evidence_type, description.clone())?;

            // Convert to EvidenceInfo
            let evidence_info = EvidenceInfo {
                id: evidence.id.clone(),
                evidence_type: match evidence.evidence_type {
                    EvidenceType::Text(_) => "text".to_string(),
                    EvidenceType::Image(_) => "image".to_string(),
                    EvidenceType::Document(_) => "document".to_string(),
                    EvidenceType::MessageHistory(_) => "message_history".to_string(),
                    EvidenceType::OrderDetails(_) => "order_details".to_string(),
                },
                description: evidence.description.clone(),
                submitted_by: match evidence.submitted_by {
                    DisputeParty::Buyer => "buyer".to_string(),
                    DisputeParty::Vendor => "vendor".to_string(),
                    DisputeParty::Mediator => "mediator".to_string(),
                },
                timestamp: evidence.timestamp,
            };

            // Update dispute info
            let mut updated_info = dispute_info.clone();
            updated_info.evidence.push(evidence_info);
            updated_info.state = "evidence_submitted".to_string();
            updated_info.updated = Utc::now().timestamp() as u64;

            // Update in state
            state.disputes.insert(dispute_id.clone(), updated_info);
            state.messages.insert(message.order_id.clone(), message);

            println!("Submitted evidence for dispute '{}'", dispute_id);
            println!("Evidence ID: {}", evidence.id);
            println!("Description: {}", evidence.description);

            Ok(())
        }
        DisputeCommands::Resolve {
            dispute_id,
            outcome,
            description,
        } => {
            // Get dispute
            let dispute_info = state
                .disputes
                .get(dispute_id)
                .ok_or_else(|| anyhow!("Dispute '{}' not found", dispute_id))?;

            // Determine outcome
            let dispute_state = match outcome.as_str() {
                "buyer" => DisputeState::ResolvedForBuyer,
                "vendor" => DisputeState::ResolvedForVendor,
                "compromise" => DisputeState::ResolvedWithCompromise,
                _ => {
                    return Err(anyhow!(
                        "Invalid outcome. Must be one of: buyer, vendor, compromise"
                    ))
                }
            };

            // Resolve dispute
            let (resolution, message) = dispute_client.resolve_dispute(
                dispute_id,
                dispute_state.clone(),
                description.clone(),
            )?;

            // Convert to ResolutionInfo
            let resolution_info = ResolutionInfo {
                outcome: resolution.outcome.as_str().to_string(),
                description: resolution.description.clone(),
                resolved_by: match resolution.resolved_by {
                    DisputeParty::Buyer => "buyer".to_string(),
                    DisputeParty::Vendor => "vendor".to_string(),
                    DisputeParty::Mediator => "mediator".to_string(),
                },
                timestamp: resolution.timestamp,
            };

            // Update dispute info
            let mut updated_info = dispute_info.clone();
            updated_info.resolution = Some(resolution_info);
            updated_info.state = resolution.outcome.as_str().to_string();
            updated_info.updated = Utc::now().timestamp() as u64;

            // Update in state
            state.disputes.insert(dispute_id.clone(), updated_info);
            state.messages.insert(message.order_id.clone(), message);

            println!("Resolved dispute '{}'", dispute_id);
            println!("Outcome: {}", resolution.outcome.as_str());
            println!("Description: {}", resolution.description);

            Ok(())
        }
        DisputeCommands::List => {
            println!("Disputes:");

            if state.disputes.is_empty() {
                println!("  No disputes found");
                return Ok(());
            }

            for (id, dispute) in &state.disputes {
                println!("  {} - State: {}", id, dispute.state);
                println!("    Order: {}", dispute.order_id);
                println!("    Reason: {}", dispute.reason);
                println!("    Initiated by: {}", dispute.initiated_by);
                println!("    Evidence: {} item(s)", dispute.evidence.len());
                if let Some(resolution) = &dispute.resolution {
                    println!(
                        "    Resolution: {} (by {})",
                        resolution.outcome, resolution.resolved_by
                    );
                }
            }

            Ok(())
        }
        DisputeCommands::Show { id } => {
            // Get dispute
            let dispute = state
                .disputes
                .get(id)
                .ok_or_else(|| anyhow!("Dispute '{}' not found", id))?;

            println!("Dispute: {}", anyhow!("Dispute '{}' not found", id))?;

            println!("Dispute: {}", id);
            println!("State: {}", dispute.state);
            println!("Order: {}", dispute.order_id);
            println!("Buyer: {}", dispute.buyer_public_key);
            println!("Vendor: {}", dispute.vendor_public_key);
            if let Some(mediator) = &dispute.mediator_public_key {
                println!("Mediator: {}", mediator);
            }
            println!("Reason: {}", dispute.reason);
            println!("Initiated by: {}", dispute.initiated_by);
            println!(
                "Created: {}",
                chrono::NaiveDateTime::from_timestamp_opt(dispute.created as i64, 0).unwrap()
            );
            println!(
                "Updated: {}",
                chrono::NaiveDateTime::from_timestamp_opt(dispute.updated as i64, 0).unwrap()
            );

            if !dispute.evidence.is_empty() {
                println!("Evidence:");
                for evidence in &dispute.evidence {
                    println!("  - ID: {}", evidence.id);
                    println!("    Type: {}", evidence.evidence_type);
                    println!("    Description: {}", evidence.description);
                    println!("    Submitted by: {}", evidence.submitted_by);
                    println!(
                        "    Timestamp: {}",
                        chrono::NaiveDateTime::from_timestamp_opt(evidence.timestamp as i64, 0)
                            .unwrap()
                    );
                }
            }

            if let Some(resolution) = &dispute.resolution {
                println!("Resolution:");
                println!("  Outcome: {}", resolution.outcome);
                println!("  Description: {}", resolution.description);
                println!("  Resolved by: {}", resolution.resolved_by);
                println!(
                    "  Timestamp: {}",
                    chrono::NaiveDateTime::from_timestamp_opt(resolution.timestamp as i64, 0)
                        .unwrap()
                );
            }

            Ok(())
        }
    }
}

/// Handle network commands
async fn handle_network_command(
    command: &NetworkCommands,
    state: &mut CliState,
    config_dir: &Path,
) -> Result<()> {
    // Get active identity
    let active_identity = get_active_identity(state)?;

    // Decode libp2p keypair
    let libp2p_keypair_bytes = base64::decode(&active_identity.libp2p_keypair)?;
    let local_keypair = identity::Keypair::from_protobuf_encoding(&libp2p_keypair_bytes)?;
    let local_peer_id = PeerId::from(local_keypair.public());

    match command {
        NetworkCommands::Start { listen, bootstrap } => {
            // Create transport
            let transport = create_transport(&local_keypair, None)?;

            // Create peer manager
            let peer_manager = PeerManager::new();

            // Create protocol configuration
            let protocol_config = ProtocolConfig::default();

            // Create protocol behaviour
            let protocol_behaviour = ProtocolBehaviour::new(protocol_config);

            // Parse bootstrap nodes
            let mut bootstrap_nodes = Vec::new();
            if let Some(bootstrap_str) = bootstrap {
                for node in bootstrap_str.split(',') {
                    let parts: Vec<&str> = node.split('@').collect();
                    if parts.len() != 2 {
                        return Err(anyhow!(
                            "Invalid bootstrap node format. Use 'peer_id@address'"
                        ));
                    }

                    let peer_id = PeerId::from_str(parts[0])?;
                    let addr: Multiaddr = parts[1].parse()?;

                    bootstrap_nodes.push((peer_id, addr));
                }
            }

            // Create discovery configuration
            let discovery_config = DiscoveryConfig {
                enable_mdns: true,
                enable_kademlia: true,
                bootstrap_nodes,
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

            // Create a swarm
            let swarm_config = libp2p::swarm::Config::with_tokio_executor();
            let mut swarm = libp2p::swarm::Swarm::new(
                transport,
                combined_behaviour,
                local_peer_id,
                swarm_config,
            );

            // Listen on the specified address
            let listen_addr: Multiaddr = listen.parse()?;
            swarm.listen_on(listen_addr)?;

            // Bootstrap the discovery
            swarm.behaviour_mut().discovery.bootstrap()?;

            println!("Started network node");
            println!("Local peer ID: {}", local_peer_id);

            // Event loop
            let mut listening = false;
            while let Some(event) = swarm.next().await {
                match event {
                    libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                        println!("Listening on {}", address);
                        listening = true;
                    }
                    libp2p::swarm::SwarmEvent::Behaviour(event) => {
                        // Handle events if needed
                    }
                    _ => {}
                }

                // Break after we're listening
                if listening {
                    break;
                }
            }

            println!("Network node is running. Press Ctrl+C to stop.");

            // Keep running until interrupted
            tokio::signal::ctrl_c().await?;
            println!("Shutting down network node...");

            Ok(())
        }
        NetworkCommands::Connect { address } => {
            // Parse address
            let addr: Multiaddr = address.parse()?;

            // Create transport
            let transport = create_transport(&local_keypair, None)?;

            // Create a minimal swarm just for connecting
            let swarm_config = libp2p::swarm::Config::with_tokio_executor();
            let mut swarm = libp2p::swarm::Swarm::new(
                transport,
                libp2p::swarm::dummy::Behaviour,
                local_peer_id,
                swarm_config,
            );

            // Connect to the address
            swarm.dial(addr.clone())?;

            println!("Connecting to {}...", addr);

            // Wait for connection
            let mut connected = false;
            while let Some(event) = swarm.next().await {
                match event {
                    libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("Connected to peer: {}", peer_id);
                        connected = true;
                        break;
                    }
                    libp2p::swarm::SwarmEvent::OutgoingConnectionError { error, .. } => {
                        return Err(anyhow!("Connection error: {}", error));
                    }
                    _ => {}
                }
            }

            if connected {
                println!("Successfully connected to {}", addr);
            } else {
                println!("Failed to connect to {}", addr);
            }

            Ok(())
        }
        NetworkCommands::SendMessage { peer, message } => {
            // Parse peer ID
            let peer_id = PeerId::from_str(peer)?;

            // Create transport
            let transport = create_transport(&local_keypair, None)?;

            // Create protocol configuration
            let protocol_config = ProtocolConfig::default();

            // Create protocol behaviour
            let mut protocol_behaviour = ProtocolBehaviour::new(protocol_config);

            // Create a swarm
            let mut swarm = libp2p::swarm::Swarm::new(
                transport,
                protocol_behaviour,
                local_peer_id,
                libp2p::swarm::Config::with_tokio_executor(),
            );

            // Create network message
            let network_message = NetworkMessage::direct_message(
                local_peer_id,
                peer_id,
                message.as_bytes().to_vec(),
                "text/plain".to_string(),
            );

            // Send the message
            swarm
                .behaviour_mut()
                .send_message(peer_id, network_message.clone());

            println!("Sending message to {}...", peer_id);

            // Wait for message to be sent
            let mut sent = false;
            while let Some(event) = swarm.next().await {
                match event {
                    libp2p::swarm::SwarmEvent::Behaviour(event) => match event {
                        ProtocolEvent::MessageSent { message_id, to } => {
                            if to == peer_id && message_id == network_message.id {
                                println!("Message sent successfully");
                                sent = true;
                                break;
                            }
                        }
                        ProtocolEvent::MessageSendFailed {
                            message_id,
                            to,
                            error,
                        } => {
                            if to == peer_id && message_id == network_message.id {
                                return Err(anyhow!("Failed to send message: {}", error));
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }

            if sent {
                println!("Message sent to {}", peer_id);
            } else {
                println!("Failed to send message to {}", peer_id);
            }

            Ok(())
        }
        NetworkCommands::ListPeers => {
            // Create transport
            let transport = create_transport(&local_keypair, None)?;

            // Create peer manager
            let peer_manager = PeerManager::new();

            // Create protocol configuration
            let protocol_config = ProtocolConfig::default();

            // Create protocol behaviour
            let protocol_behaviour = ProtocolBehaviour::new(protocol_config);

            // Create discovery configuration
            let discovery_config = DiscoveryConfig {
                enable_mdns: true,
                enable_kademlia: true,
                bootstrap_nodes: Vec::new(),
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

            // Create a swarm
            let mut swarm = libp2p::swarm::Swarm::new(
                transport,
                combined_behaviour,
                local_peer_id,
                libp2p::swarm::Config::with_tokio_executor(),
            );

            // Listen on a random port
            swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

            // Bootstrap the discovery
            swarm.behaviour_mut().discovery.bootstrap()?;

            println!("Discovering peers...");

            // Wait for discovery
            let start_time = std::time::Instant::now();
            while start_time.elapsed() < Duration::from_secs(10) {
                swarm.next().await;

                // Check discovered peers
                let peers = swarm.behaviour().discovery.discovered_count();
                if peers > 0 {
                    break;
                }
            }

            // Get connected peers
            let connected_peers = swarm.behaviour().discovery.peer_manager.connected_peers();

            println!("Connected peers: {}", connected_peers.len());
            for peer in connected_peers {
                println!("  - {}", peer.peer_id);
                if !peer.addresses.is_empty() {
                    println!("    Addresses:");
                    for addr in &peer.addresses {
                        println!("      {}", addr);
                    }
                }
            }

            // Get discovered peers
            let discovered_count = swarm.behaviour().discovery.discovered_count();
            println!("Total discovered peers: {}", discovered_count);

            Ok(())
        }
    }
}

/// Helper function to get the active identity
fn get_active_identity(state: &CliState) -> Result<&IdentityInfo> {
    let active_name = state
        .active_identity
        .as_ref()
        .ok_or_else(|| anyhow!("No active identity set. Use 'identity set-active' to set one."))?;

    state
        .identities
        .get(active_name)
        .ok_or_else(|| anyhow!("Active identity '{}' not found", active_name))
}

/// Helper function to create a buyer API
fn create_buyer_api(identity: &IdentityInfo) -> Result<BuyerApi> {
    // Parse keys
    let private_key = SecretKey::from_slice(&hex::decode(&identity.private_key)?)?;
    let public_key = PublicKey::from_slice(&hex::decode(&identity.public_key)?)?;

    // Create buyer API
    Ok(BuyerApi::new(private_key, public_key))
}

/// Helper function to create a vendor API
fn create_vendor_api(identity: &IdentityInfo) -> Result<VendorApi> {
    // Parse keys
    let private_key = SecretKey::from_slice(&hex::decode(&identity.private_key)?)?;
    let public_key = PublicKey::from_slice(&hex::decode(&identity.public_key)?)?;

    // Create vendor API
    Ok(VendorApi::new(private_key, public_key))
}

/// Helper function to expand a path
fn expand_path(path: &Path) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();

    if path_str.starts_with('~') {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;

        let remainder = path_str.strip_prefix("~/").unwrap_or("");
        Ok(home.join(remainder))
    } else {
        Ok(path.to_path_buf())
    }
}
