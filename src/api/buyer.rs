//! Buyer-specific API functions

use crate::core::crypto::Crypto;
use crate::core::order::OrderManager;
use crate::models::{Location, Message, Order, OrderItem, VendorListing};
use crate::Result;
use chrono::Utc;
use secp256k1::{PublicKey, SecretKey};
use serde_json::json;
use uuid::Uuid;

/// API for buyers to interact with the P2P order protocol
pub struct BuyerApi {
    /// The buyer's identity private key
    private_key: SecretKey,
    /// The buyer's identity public key
    public_key: PublicKey,
    /// Order manager for handling order state transitions
    order_manager: OrderManager,
}

impl BuyerApi {
    /// Creates a new BuyerApi with the given identity keys
    pub fn new(private_key: SecretKey, public_key: PublicKey) -> Self {
        Self {
            private_key,
            public_key,
            order_manager: OrderManager::new(),
        }
    }

    /// Creates a new BuyerApi with a freshly generated identity key pair
    pub fn new_with_generated_keys() -> Result<Self> {
        let keypair = Crypto::generate_identity_keypair()?;
        Ok(Self::new(keypair.private_key, keypair.public_key))
    }

    /// Creates a new order for a vendor
    pub fn create_order(
        &self,
        vendor_listing: &VendorListing,
        order_items: Vec<OrderItem>,
        total_amount: String,
        payment_method: String,
        payment_details: String,
        buyer_location: Option<Location>,
    ) -> Result<Order> {
        // Generate a unique order ID
        let order_id = Uuid::new_v4().to_string();

        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        // Create the order without a signature first
        let mut order = Order::new(
            order_id,
            Crypto::encode_base64(&self.public_key.serialize()),
            vendor_listing.vendor_identity_key_public.clone(),
            order_items,
            total_amount,
            timestamp,
            payment_method,
            payment_details,
            String::new(), // Empty signature for now
        );

        // Add the buyer location if provided
        if let Some(location) = buyer_location {
            order = order.with_buyer_location(location);
        }

        // Serialize the order for signing
        let order_bytes = order.serialize_for_signing()?;

        // Sign the order
        let signature = Crypto::sign(&self.private_key, &order_bytes)?;

        // Set the signature
        order.signature = Crypto::encode_base64(&signature);

        Ok(order)
    }

    /// Accepts a delivery
    pub fn accept_delivery(&self, order: &Order) -> Result<Message> {
        self.create_delivery_response(order, "delivery_accepted")
    }

    /// Rejects a delivery
    pub fn reject_delivery(&self, order: &Order, reason: Option<String>) -> Result<Message> {
        let mut message = self.create_delivery_response(order, "delivery_rejected")?;

        // Add the reason to the payload if provided
        if let Some(reason_text) = reason {
            message.payload = Some(json!({
                "reason": reason_text
            }));
        }

        Ok(message)
    }

    /// Requests a return
    pub fn request_return(&self, order: &Order, reason: String) -> Result<Message> {
        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        // Create the message without a signature first
        let mut message = Message::new(
            "return_request".to_string(),
            order.order_id.clone(),
            timestamp,
            String::new(), // Empty signature for now
        )
        .with_status("return_requested".to_string())
        .with_payload(json!({
            "reason": reason
        }));

        // Serialize the message for signing
        let message_bytes = message.serialize_for_signing()?;

        // Sign the message
        let signature = Crypto::sign(&self.private_key, &message_bytes)?;

        // Set the signature
        message.signature = Crypto::encode_base64(&signature);

        Ok(message)
    }

    /// Initiates a dispute
    pub fn initiate_dispute(
        &self,
        order: &Order,
        reason: String,
        evidence: Option<String>,
    ) -> Result<Message> {
        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        // Create the payload with the reason and optional evidence
        let mut payload = json!({
            "reason": reason
        });

        if let Some(evidence_text) = evidence {
            payload["evidence"] = json!(evidence_text);
        }

        // Create the message without a signature first
        let mut message = Message::new(
            "dispute_initiation".to_string(),
            order.order_id.clone(),
            timestamp,
            String::new(), // Empty signature for now
        )
        .with_status("disputed".to_string())
        .with_payload(payload);

        // Serialize the message for signing
        let message_bytes = message.serialize_for_signing()?;

        // Sign the message
        let signature = Crypto::sign(&self.private_key, &message_bytes)?;

        // Set the signature
        message.signature = Crypto::encode_base64(&signature);

        Ok(message)
    }

    /// Helper method to create a delivery response message
    fn create_delivery_response(&self, order: &Order, status: &str) -> Result<Message> {
        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        // Create the message without a signature first
        let mut message = Message::new(
            "delivery_response".to_string(),
            order.order_id.clone(),
            timestamp,
            String::new(), // Empty signature for now
        )
        .with_status(status.to_string());

        // Serialize the message for signing
        let message_bytes = message.serialize_for_signing()?;

        // Sign the message
        let signature = Crypto::sign(&self.private_key, &message_bytes)?;

        // Set the signature
        message.signature = Crypto::encode_base64(&signature);

        Ok(message)
    }

    /// Processes a received message and updates the order state
    pub fn process_message(&self, order: &mut Order, message: &Message) -> Result<()> {
        self.order_manager.process_message(order, message)
    }
}
