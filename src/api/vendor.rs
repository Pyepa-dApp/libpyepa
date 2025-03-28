//! Vendor-specific API functions

use crate::core::crypto::Crypto;
use crate::core::order::OrderManager;
use crate::models::{Item, Location, Message, Order, VendorListing};
use crate::Result;
use chrono::Utc;
use secp256k1::{PublicKey, SecretKey};
use serde_json::json;

/// API for vendors to interact with the P2P order protocol
pub struct VendorApi {
    /// The vendor's identity private key
    private_key: SecretKey,
    /// The vendor's identity public key
    public_key: PublicKey,
    /// Order manager for handling order state transitions
    order_manager: OrderManager,
}

impl VendorApi {
    /// Creates a new VendorApi with the given identity keys
    pub fn new(private_key: SecretKey, public_key: PublicKey) -> Self {
        Self {
            private_key,
            public_key,
            order_manager: OrderManager::new(),
        }
    }

    /// Creates a new VendorApi with a freshly generated identity key pair
    pub fn new_with_generated_keys() -> Result<Self> {
        let keypair = Crypto::generate_identity_keypair()?;
        Ok(Self::new(keypair.private_key, keypair.public_key))
    }

    /// Creates a new vendor listing
    pub fn create_listing(
        &self,
        items: Vec<Item>,
        payment_methods: Vec<String>,
        vendor_name: Option<String>,
        location: Option<Location>,
        service_terms: Option<String>,
    ) -> Result<VendorListing> {
        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        // Create the listing without a signature first
        let mut listing = VendorListing::new(
            Crypto::encode_base64(&self.public_key.serialize()),
            items,
            payment_methods,
            timestamp,
            String::new(), // Empty signature for now
        );

        // Add optional fields if provided
        if let Some(name) = vendor_name {
            listing = listing.with_vendor_name(name);
        }

        if let Some(loc) = location {
            listing = listing.with_location(loc);
        }

        if let Some(terms) = service_terms {
            listing = listing.with_service_terms(terms);
        }

        // Serialize the listing for signing
        let listing_bytes = listing.serialize_for_signing()?;

        // Sign the listing
        let signature = Crypto::sign(&self.private_key, &listing_bytes)?;

        // Set the signature
        listing.signature = Crypto::encode_base64(&signature);

        Ok(listing)
    }

    /// Accepts an order
    pub fn accept_order(&self, order: &Order) -> Result<Message> {
        self.create_order_response(order, "accepted")
    }

    /// Rejects an order
    pub fn reject_order(&self, order: &Order, reason: Option<String>) -> Result<Message> {
        let mut message = self.create_order_response(order, "rejected")?;

        // Add the reason to the payload if provided
        if let Some(reason_text) = reason {
            message.payload = Some(json!({
                "reason": reason_text
            }));
        }

        Ok(message)
    }

    /// Dispatches an order
    pub fn dispatch_order(&self, order: &Order, tracking_info: Option<String>) -> Result<Message> {
        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        // Create the message without a signature first
        let mut message = Message::new(
            "dispatch_notification".to_string(),
            order.order_id.clone(),
            timestamp,
            String::new(), // Empty signature for now
        )
        .with_status("dispatched".to_string());

        // Add tracking information if provided
        if let Some(tracking) = tracking_info {
            message.payload = Some(json!({
                "tracking_information": tracking,
                "dispatch_timestamp": timestamp
            }));
        } else {
            message.payload = Some(json!({
                "dispatch_timestamp": timestamp
            }));
        }

        // Serialize the message for signing
        let message_bytes = message.serialize_for_signing()?;

        // Sign the message
        let signature = Crypto::sign(&self.private_key, &message_bytes)?;

        // Set the signature
        message.signature = Crypto::encode_base64(&signature);

        Ok(message)
    }

    /// Marks an order as delivered
    pub fn mark_as_delivered(&self, order: &Order) -> Result<Message> {
        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        // Create the message without a signature first
        let mut message = Message::new(
            "delivery_notification".to_string(),
            order.order_id.clone(),
            timestamp,
            String::new(), // Empty signature for now
        )
        .with_status("delivered".to_string());

        message.payload = Some(json!({
            "delivery_timestamp": timestamp
        }));

        // Serialize the message for signing
        let message_bytes = message.serialize_for_signing()?;

        // Sign the message
        let signature = Crypto::sign(&self.private_key, &message_bytes)?;

        // Set the signature
        message.signature = Crypto::encode_base64(&signature);

        Ok(message)
    }

    /// Responds to a return request
    pub fn respond_to_return(
        &self,
        order: &Order,
        accept: bool,
        reason: Option<String>,
    ) -> Result<Message> {
        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        let status = if accept {
            "return_accepted"
        } else {
            "return_rejected"
        };

        // Create the message without a signature first
        let mut message = Message::new(
            "return_response".to_string(),
            order.order_id.clone(),
            timestamp,
            String::new(), // Empty signature for now
        )
        .with_status(status.to_string());

        // Add the reason to the payload if provided
        if let Some(reason_text) = reason {
            message.payload = Some(json!({
                "reason": reason_text
            }));
        }

        // Serialize the message for signing
        let message_bytes = message.serialize_for_signing()?;

        // Sign the message
        let signature = Crypto::sign(&self.private_key, &message_bytes)?;

        // Set the signature
        message.signature = Crypto::encode_base64(&signature);

        Ok(message)
    }

    /// Helper method to create an order response message
    fn create_order_response(&self, order: &Order, status: &str) -> Result<Message> {
        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        // Create the message without a signature first
        let mut message = Message::new(
            "order_acceptance".to_string(),
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
