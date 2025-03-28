use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Represents a message exchanged between a buyer and a vendor
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    /// Type of the message (e.g., "order_acceptance", "dispatch_notification", etc.)
    pub message_type: String,
    /// ID of the order this message relates to
    pub order_id: String,
    /// Optional status of the order (e.g., "accepted", "rejected", "dispatched", etc.)
    pub status: Option<String>,
    /// Unix timestamp when the message was created
    pub timestamp: u64,
    /// Optional additional data as a JSON value
    pub payload: Option<Value>,
    /// Signature of the sender (Base64 or hex encoded)
    pub signature: String,
}

impl Message {
    /// Creates a new Message with required fields
    pub fn new(message_type: String, order_id: String, timestamp: u64, signature: String) -> Self {
        Self {
            message_type,
            order_id,
            status: None,
            timestamp,
            payload: None,
            signature,
        }
    }

    /// Sets the status of the message
    pub fn with_status(mut self, status: String) -> Self {
        self.status = Some(status);
        self
    }

    /// Sets the payload of the message
    pub fn with_payload(mut self, payload: Value) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Serializes the message to JSON, excluding the signature field
    pub fn serialize_for_signing(&self) -> Result<Vec<u8>, serde_json::Error> {
        // Create a copy without the signature
        let mut message_copy = self.clone();
        message_copy.signature = String::new();

        serde_json::to_vec(&message_copy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_message_builder() {
        let message = Message::new(
            "order_acceptance".to_string(),
            "order-123".to_string(),
            1632150000,
            "signature_123".to_string(),
        )
        .with_status("accepted".to_string())
        .with_payload(json!({
            "note": "Thank you for your order!",
            "estimated_delivery": "2023-09-25"
        }));

        assert_eq!(message.message_type, "order_acceptance");
        assert_eq!(message.order_id, "order-123");
        assert_eq!(message.status, Some("accepted".to_string()));
        assert_eq!(message.timestamp, 1632150000);
        assert!(message.payload.is_some());
        assert_eq!(message.signature, "signature_123");
    }

    #[test]
    fn test_serialize_for_signing() {
        let message = Message::new(
            "order_acceptance".to_string(),
            "order-123".to_string(),
            1632150000,
            "signature_123".to_string(),
        );

        let serialized = message.serialize_for_signing().unwrap();
        let deserialized: Message = serde_json::from_slice(&serialized).unwrap();

        assert_eq!(deserialized.message_type, message.message_type);
        assert_eq!(deserialized.signature, ""); // Signature should be empty in the serialized version
    }
}
