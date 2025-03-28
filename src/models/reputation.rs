use serde::{Deserialize, Serialize};

/// Represents a reputation rating and review for a vendor
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Reputation {
    /// Public key of the vendor being rated (Base64 or hex encoded)
    pub vendor_public_key: String,
    /// Public key of the buyer who left the rating (Base64 or hex encoded)
    pub buyer_public_key: String,
    /// Rating value (1-5)
    pub rating: u8,
    /// Optional review text
    pub review: Option<String>,
    /// Unix timestamp when the rating was created
    pub timestamp: u64,
    /// Signature of the buyer (Base64 or hex encoded)
    pub signature: String,
}

impl Reputation {
    /// Creates a new Reputation with required fields
    pub fn new(
        vendor_public_key: String,
        buyer_public_key: String,
        rating: u8,
        timestamp: u64,
        signature: String,
    ) -> Self {
        // Ensure rating is between 1 and 5
        let clamped_rating = rating.clamp(1, 5);

        Self {
            vendor_public_key,
            buyer_public_key,
            rating: clamped_rating,
            review: None,
            timestamp,
            signature,
        }
    }

    /// Sets the review text
    pub fn with_review(mut self, review: String) -> Self {
        self.review = Some(review);
        self
    }

    /// Serializes the reputation to JSON, excluding the signature field
    pub fn serialize_for_signing(&self) -> Result<Vec<u8>, serde_json::Error> {
        // Create a copy without the signature
        let mut reputation_copy = self.clone();
        reputation_copy.signature = String::new();

        serde_json::to_vec(&reputation_copy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reputation_builder() {
        let reputation = Reputation::new(
            "vendor_key_456".to_string(),
            "buyer_key_123".to_string(),
            5,
            1632150000,
            "signature_123".to_string(),
        )
        .with_review("Great service and fast delivery!".to_string());

        assert_eq!(reputation.vendor_public_key, "vendor_key_456");
        assert_eq!(reputation.buyer_public_key, "buyer_key_123");
        assert_eq!(reputation.rating, 5);
        assert_eq!(
            reputation.review,
            Some("Great service and fast delivery!".to_string())
        );
        assert_eq!(reputation.timestamp, 1632150000);
        assert_eq!(reputation.signature, "signature_123");
    }

    #[test]
    fn test_rating_clamping() {
        let reputation = Reputation::new(
            "vendor_key_456".to_string(),
            "buyer_key_123".to_string(),
            10, // This should be clamped to 5
            1632150000,
            "signature_123".to_string(),
        );

        assert_eq!(reputation.rating, 5);
    }

    #[test]
    fn test_serialize_for_signing() {
        let reputation = Reputation::new(
            "vendor_key_456".to_string(),
            "buyer_key_123".to_string(),
            4,
            1632150000,
            "signature_123".to_string(),
        );

        let serialized = reputation.serialize_for_signing().unwrap();
        let deserialized: Reputation = serde_json::from_slice(&serialized).unwrap();

        assert_eq!(deserialized.vendor_public_key, reputation.vendor_public_key);
        assert_eq!(deserialized.signature, ""); // Signature should be empty in the serialized version
    }
}
