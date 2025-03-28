use crate::models::{Location, OrderItem};
use serde::{Deserialize, Serialize};

/// Represents an order in the system
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Order {
    /// Unique identifier for the order
    pub order_id: String,
    /// Public key of the buyer (Base64 or hex encoded)
    pub buyer_public_key: String,
    /// Public key of the vendor (Base64 or hex encoded)
    pub vendor_public_key: String,
    /// Items in the order
    pub order_items: Vec<OrderItem>,
    /// Total amount of the order (as a string to support various currencies and formats)
    pub total_amount: String,
    /// Optional location of the buyer
    pub buyer_location: Option<Location>,
    /// Unix timestamp when the order was created
    pub created_timestamp: u64,
    /// Current state of the order (e.g., "created", "accepted", "rejected", etc.)
    pub current_state: String,
    /// Payment method for the order
    pub payment_method: String,
    /// Payment details for the order
    pub payment_details: String,
    /// Signature of the buyer (Base64 or hex encoded)
    pub signature: String,
}

impl Order {
    /// Creates a new Order with required fields
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        order_id: String,
        buyer_public_key: String,
        vendor_public_key: String,
        order_items: Vec<OrderItem>,
        total_amount: String,
        created_timestamp: u64,
        payment_method: String,
        payment_details: String,
        signature: String,
    ) -> Self {
        Self {
            order_id,
            buyer_public_key,
            vendor_public_key,
            order_items,
            total_amount,
            buyer_location: None,
            created_timestamp,
            current_state: "created".to_string(),
            payment_method,
            payment_details,
            signature,
        }
    }

    /// Sets the buyer location
    pub fn with_buyer_location(mut self, location: Location) -> Self {
        self.buyer_location = Some(location);
        self
    }

    /// Updates the current state of the order
    pub fn update_state(&mut self, new_state: &str) {
        self.current_state = new_state.to_string();
    }

    /// Serializes the order to JSON, excluding the signature field
    pub fn serialize_for_signing(&self) -> Result<Vec<u8>, serde_json::Error> {
        // Create a copy without the signature
        let mut order_copy = self.clone();
        order_copy.signature = String::new();

        serde_json::to_vec(&order_copy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_order_creation_and_state_update() {
        let order_item = OrderItem::new("item-123".to_string(), 2);
        let location = Location::new(40.7128, -74.0060);

        let mut order = Order::new(
            "order-123".to_string(),
            "buyer_key_123".to_string(),
            "vendor_key_456".to_string(),
            vec![order_item],
            "20.99".to_string(),
            1632150000,
            "BTC".to_string(),
            "payment_details_123".to_string(),
            "signature_123".to_string(),
        )
        .with_buyer_location(location);

        assert_eq!(order.order_id, "order-123");
        assert_eq!(order.current_state, "created");

        order.update_state("accepted");
        assert_eq!(order.current_state, "accepted");
    }

    #[test]
    fn test_serialize_for_signing() {
        let order_item = OrderItem::new("item-123".to_string(), 2);

        let order = Order::new(
            "order-123".to_string(),
            "buyer_key_123".to_string(),
            "vendor_key_456".to_string(),
            vec![order_item],
            "20.99".to_string(),
            1632150000,
            "BTC".to_string(),
            "payment_details_123".to_string(),
            "signature_123".to_string(),
        );

        let serialized = order.serialize_for_signing().unwrap();
        let deserialized: Order = serde_json::from_slice(&serialized).unwrap();

        assert_eq!(deserialized.order_id, order.order_id);
        assert_eq!(deserialized.signature, ""); // Signature should be empty in the serialized version
    }
}
