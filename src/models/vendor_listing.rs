use crate::models::{Item, Location};
use serde::{Deserialize, Serialize};

/// Represents a vendor's listing in the marketplace
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VendorListing {
    /// The vendor's public identity key (Base64 or hex encoded)
    pub vendor_identity_key_public: String,
    /// Optional name of the vendor
    pub vendor_name: Option<String>,
    /// Optional location of the vendor
    pub location: Option<Location>,
    /// Items offered by the vendor
    pub items_offered: Vec<Item>,
    /// Payment methods accepted by the vendor
    pub payment_methods_accepted: Vec<String>,
    /// Optional terms of service
    pub service_terms: Option<String>,
    /// Unix timestamp when the listing was created
    pub timestamp: u64,
    /// Signature of the vendor (Base64 or hex encoded)
    pub signature: String,
}

impl VendorListing {
    /// Creates a new VendorListing with required fields
    pub fn new(
        vendor_identity_key_public: String,
        items_offered: Vec<Item>,
        payment_methods_accepted: Vec<String>,
        timestamp: u64,
        signature: String,
    ) -> Self {
        Self {
            vendor_identity_key_public,
            vendor_name: None,
            location: None,
            items_offered,
            payment_methods_accepted,
            service_terms: None,
            timestamp,
            signature,
        }
    }

    /// Sets the vendor name
    pub fn with_vendor_name(mut self, vendor_name: String) -> Self {
        self.vendor_name = Some(vendor_name);
        self
    }

    /// Sets the vendor location
    pub fn with_location(mut self, location: Location) -> Self {
        self.location = Some(location);
        self
    }

    /// Sets the service terms
    pub fn with_service_terms(mut self, service_terms: String) -> Self {
        self.service_terms = Some(service_terms);
        self
    }

    /// Serializes the listing to JSON, excluding the signature field
    pub fn serialize_for_signing(&self) -> Result<Vec<u8>, serde_json::Error> {
        // Create a copy without the signature
        let mut listing_copy = self.clone();
        listing_copy.signature = String::new();

        serde_json::to_vec(&listing_copy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vendor_listing_builder() {
        let item = Item::new("item-123".to_string(), "Test Item".to_string());
        let location = Location::new(40.7128, -74.0060);

        let listing = VendorListing::new(
            "public_key_123".to_string(),
            vec![item],
            vec!["BTC".to_string(), "ETH".to_string()],
            1632150000,
            "signature_123".to_string(),
        )
        .with_vendor_name("Test Vendor".to_string())
        .with_location(location)
        .with_service_terms("Terms and conditions apply".to_string());

        assert_eq!(listing.vendor_identity_key_public, "public_key_123");
        assert_eq!(listing.vendor_name, Some("Test Vendor".to_string()));
        assert!(listing.location.is_some());
        assert_eq!(listing.items_offered.len(), 1);
        assert_eq!(
            listing.payment_methods_accepted,
            vec!["BTC".to_string(), "ETH".to_string()]
        );
        assert_eq!(
            listing.service_terms,
            Some("Terms and conditions apply".to_string())
        );
        assert_eq!(listing.timestamp, 1632150000);
        assert_eq!(listing.signature, "signature_123");
    }

    #[test]
    fn test_serialize_for_signing() {
        let item = Item::new("item-123".to_string(), "Test Item".to_string());

        let listing = VendorListing::new(
            "public_key_123".to_string(),
            vec![item],
            vec!["BTC".to_string()],
            1632150000,
            "signature_123".to_string(),
        );

        let serialized = listing.serialize_for_signing().unwrap();
        let deserialized: VendorListing = serde_json::from_slice(&serialized).unwrap();

        assert_eq!(
            deserialized.vendor_identity_key_public,
            listing.vendor_identity_key_public
        );
        assert_eq!(deserialized.signature, ""); // Signature should be empty in the serialized version
    }
}
