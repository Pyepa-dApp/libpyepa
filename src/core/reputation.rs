//! Reputation system for building trust between buyers and vendors

use crate::core::crypto::Crypto;
use crate::core::dht::DhtClient;
use crate::core::error::Error;
use crate::models::{Order, Reputation};
use crate::Result;

use chrono::Utc;
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Minimum number of completed transactions required before a buyer can leave a rating
const MIN_TRANSACTIONS_FOR_RATING: usize = 1;

/// Maximum age of a transaction that can be rated (in days)
const MAX_TRANSACTION_AGE_DAYS: i64 = 30;

/// Reputation summary for a vendor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationSummary {
    /// Vendor's public key
    pub vendor_public_key: String,
    /// Average rating (1-5)
    pub average_rating: f64,
    /// Total number of ratings
    pub total_ratings: usize,
    /// Distribution of ratings (1-5)
    pub rating_distribution: HashMap<u8, usize>,
    /// Recent reviews (limited to a reasonable number)
    pub recent_reviews: Vec<Reputation>,
}

/// Reputation manager for handling vendor ratings and reviews
pub struct ReputationManager {
    /// DHT client for storing and retrieving reputation data
    dht_client: DhtClient,
    /// Buyer's private key for signing ratings
    buyer_private_key: Option<SecretKey>,
    /// Buyer's public key
    buyer_public_key: Option<PublicKey>,
}

impl ReputationManager {
    /// Creates a new ReputationManager with the given DHT client
    pub fn new(dht_client: DhtClient) -> Self {
        Self {
            dht_client,
            buyer_private_key: None,
            buyer_public_key: None,
        }
    }

    /// Sets the buyer's keys for signing ratings
    pub fn set_buyer_keys(&mut self, private_key: SecretKey, public_key: PublicKey) {
        self.buyer_private_key = Some(private_key);
        self.buyer_public_key = Some(public_key);
    }

    /// Submits a rating and optional review for a vendor
    pub async fn submit_rating(
        &self,
        vendor_public_key: String,
        rating: u8,
        review: Option<String>,
        completed_orders: &[Order],
    ) -> Result<()> {
        // Ensure the buyer's keys are set
        let private_key = self
            .buyer_private_key
            .as_ref()
            .ok_or_else(|| Error::Authentication("Buyer private key not set".into()))?;
        let public_key = self
            .buyer_public_key
            .as_ref()
            .ok_or_else(|| Error::Authentication("Buyer public key not set".into()))?;

        // Verify that the buyer has completed at least one transaction with this vendor
        let buyer_public_key_str = Crypto::encode_base64(&public_key.serialize());
        let completed_transactions = completed_orders
            .iter()
            .filter(|order| {
                order.vendor_public_key == vendor_public_key
                    && order.buyer_public_key == buyer_public_key_str
                    && order.current_state == "completed"
            })
            .collect::<Vec<_>>();

        if completed_transactions.len() < MIN_TRANSACTIONS_FOR_RATING {
            return Err(Error::InvalidState(format!(
                "Buyer must complete at least {} transactions with the vendor before rating",
                MIN_TRANSACTIONS_FOR_RATING
            )));
        }

        // Check if the most recent transaction is not too old
        let most_recent_transaction = completed_transactions
            .iter()
            .max_by_key(|order| order.created_timestamp)
            .ok_or_else(|| Error::InvalidState("No completed transactions found".into()))?;

        let transaction_time =
            chrono::DateTime::from_timestamp(most_recent_transaction.created_timestamp as i64, 0)
                .ok_or_else(|| Error::InvalidData("Invalid timestamp".into()))?;
        let now = Utc::now();
        let days_since_transaction = (now - transaction_time).num_days();

        if days_since_transaction > MAX_TRANSACTION_AGE_DAYS {
            return Err(Error::InvalidState(format!(
                "Transaction is too old to rate (max age: {} days)",
                MAX_TRANSACTION_AGE_DAYS
            )));
        }

        // Create the reputation object
        let timestamp = Utc::now().timestamp() as u64;

        // Create the reputation without a signature first
        let mut reputation = Reputation::new(
            vendor_public_key.clone(),
            buyer_public_key_str,
            rating,
            timestamp,
            String::new(), // Empty signature for now
        );

        // Add the review if provided
        if let Some(review_text) = review {
            reputation = reputation.with_review(review_text);
        }

        // Serialize the reputation for signing
        let reputation_bytes = reputation.serialize_for_signing()?;

        // Sign the reputation
        let signature = Crypto::sign(private_key, &reputation_bytes)?;

        // Set the signature
        reputation.signature = Crypto::encode_base64(&signature);

        // Store the reputation in the DHT
        self.store_reputation(reputation).await
    }

    /// Retrieves the reputation summary for a vendor
    pub async fn get_vendor_reputation(
        &self,
        vendor_public_key: &str,
    ) -> Result<ReputationSummary> {
        // Retrieve all ratings for this vendor from the DHT
        let ratings = self.retrieve_vendor_ratings(vendor_public_key).await?;

        if ratings.is_empty() {
            // Return an empty summary if no ratings are found
            return Ok(ReputationSummary {
                vendor_public_key: vendor_public_key.to_string(),
                average_rating: 0.0,
                total_ratings: 0,
                rating_distribution: HashMap::new(),
                recent_reviews: Vec::new(),
            });
        }

        // Calculate the average rating
        let total_rating: u32 = ratings.iter().map(|r| r.rating as u32).sum();
        let average_rating = total_rating as f64 / ratings.len() as f64;

        // Calculate the rating distribution
        let mut rating_distribution = HashMap::new();
        for rating in &ratings {
            *rating_distribution.entry(rating.rating).or_insert(0) += 1;
        }

        // Sort ratings by timestamp (newest first) and take the most recent ones
        let mut sorted_ratings = ratings.clone();
        sorted_ratings.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        let recent_reviews = sorted_ratings.into_iter().take(10).collect();

        Ok(ReputationSummary {
            vendor_public_key: vendor_public_key.to_string(),
            average_rating,
            total_ratings: ratings.len(),
            rating_distribution,
            recent_reviews,
        })
    }

    /// Verifies the authenticity of a rating
    pub fn verify_rating(&self, reputation: &Reputation) -> Result<bool> {
        // Parse the buyer's public key
        let buyer_public_key_bytes = Crypto::decode_base64(&reputation.buyer_public_key)?;
        let buyer_public_key = PublicKey::from_slice(&buyer_public_key_bytes)
            .map_err(|e| Error::Crypto(format!("Invalid buyer public key: {}", e)))?;

        // Parse the signature
        let signature = Crypto::decode_base64(&reputation.signature)?;

        // Create a copy of the reputation without the signature for verification
        let mut reputation_copy = reputation.clone();
        reputation_copy.signature = String::new();

        // Serialize the reputation for verification
        let reputation_bytes = reputation_copy.serialize_for_signing()?;

        // Verify the signature
        Crypto::verify(&buyer_public_key, &reputation_bytes, &signature)
    }

    /// Stores a reputation rating in the DHT
    async fn store_reputation(&self, reputation: Reputation) -> Result<()> {
        // Create a key for this specific rating
        // Format: reputation:{vendor_public_key}:{buyer_public_key}:{timestamp}
        let rating_key = format!(
            "reputation:{}:{}:{}",
            reputation.vendor_public_key, reputation.buyer_public_key, reputation.timestamp
        );

        // Also create a key for all ratings for this vendor
        // Format: reputation_vendor:{vendor_public_key}
        let vendor_key = format!("reputation_vendor:{}", reputation.vendor_public_key);

        // Serialize the reputation
        let reputation_json = serde_json::to_vec(&reputation)?;

        // Store the reputation in the DHT under both keys
        // This is a simplified approach - in a real implementation, you'd handle this more robustly

        // For now, we'll just simulate storing in the DHT
        // In a real implementation, you'd use the DHT client to store the data
        println!("Storing reputation under key: {}", rating_key);
        println!("Storing reputation under vendor key: {}", vendor_key);

        // In a real implementation, you'd do something like:
        // self.dht_client.put(rating_key, reputation_json.clone()).await?;
        // self.dht_client.put(vendor_key, reputation_json).await?;

        Ok(())
    }

    /// Retrieves all ratings for a vendor from the DHT
    async fn retrieve_vendor_ratings(&self, vendor_public_key: &str) -> Result<Vec<Reputation>> {
        // Create the key for all ratings for this vendor
        let vendor_key = format!("reputation_vendor:{}", vendor_public_key);

        // In a real implementation, you'd retrieve the data from the DHT
        // For now, we'll return a simulated result

        // Simulated ratings for testing
        let mut ratings = Vec::new();

        // In a real implementation, you'd do something like:
        // let data = self.dht_client.get(vendor_key).await?;
        // for item in data {
        //     let reputation = serde_json::from_slice::<Reputation>(&item)?;
        //     if self.verify_rating(&reputation)? {
        //         ratings.push(reputation);
        //     }
        // }

        Ok(ratings)
    }
}

/// Reputation client for interacting with the reputation system
pub struct ReputationClient {
    /// The reputation manager
    manager: ReputationManager,
}

impl ReputationClient {
    /// Creates a new ReputationClient with the given DHT client
    pub fn new(dht_client: DhtClient) -> Self {
        Self {
            manager: ReputationManager::new(dht_client),
        }
    }

    /// Sets the buyer's keys for signing ratings
    pub fn set_buyer_keys(&mut self, private_key: SecretKey, public_key: PublicKey) {
        self.manager.set_buyer_keys(private_key, public_key);
    }

    /// Submits a rating and optional review for a vendor
    pub async fn submit_rating(
        &self,
        vendor_public_key: String,
        rating: u8,
        review: Option<String>,
        completed_orders: &[Order],
    ) -> Result<()> {
        self.manager
            .submit_rating(vendor_public_key, rating, review, completed_orders)
            .await
    }

    /// Retrieves the reputation summary for a vendor
    pub async fn get_vendor_reputation(
        &self,
        vendor_public_key: &str,
    ) -> Result<ReputationSummary> {
        self.manager.get_vendor_reputation(vendor_public_key).await
    }

    /// Verifies the authenticity of a rating
    pub fn verify_rating(&self, reputation: &Reputation) -> Result<bool> {
        self.manager.verify_rating(reputation)
    }
}

/// Enhanced reputation system with Sybil attack resistance
pub struct EnhancedReputationSystem {
    /// The reputation client
    client: ReputationClient,
    /// Minimum account age required to leave a rating (in days)
    min_account_age_days: u64,
    /// Minimum number of transactions required to leave a rating
    min_transactions: usize,
}

impl EnhancedReputationSystem {
    /// Creates a new EnhancedReputationSystem with the given DHT client
    pub fn new(dht_client: DhtClient) -> Self {
        Self {
            client: ReputationClient::new(dht_client),
            min_account_age_days: 7,
            min_transactions: 3,
        }
    }

    /// Sets the minimum account age required to leave a rating
    pub fn set_min_account_age(&mut self, days: u64) {
        self.min_account_age_days = days;
    }

    /// Sets the minimum number of transactions required to leave a rating
    pub fn set_min_transactions(&mut self, transactions: usize) {
        self.min_transactions = transactions;
    }

    /// Sets the buyer's keys for signing ratings
    pub fn set_buyer_keys(&mut self, private_key: SecretKey, public_key: PublicKey) {
        self.client.set_buyer_keys(private_key, public_key);
    }

    /// Submits a rating with enhanced Sybil attack resistance
    pub async fn submit_rating(
        &self,
        vendor_public_key: String,
        rating: u8,
        review: Option<String>,
        completed_orders: &[Order],
        buyer_account_creation_time: u64,
    ) -> Result<()> {
        // Check account age
        let now = Utc::now().timestamp() as u64;
        let account_age_days = (now - buyer_account_creation_time) / (24 * 60 * 60);

        if account_age_days < self.min_account_age_days {
            return Err(Error::InvalidState(format!(
                "Buyer account must be at least {} days old to leave a rating",
                self.min_account_age_days
            )));
        }

        // Check transaction count
        let buyer_public_key = self
            .client
            .manager
            .buyer_public_key
            .as_ref()
            .ok_or_else(|| Error::Authentication("Buyer public key not set".into()))?;
        let buyer_public_key_str = Crypto::encode_base64(&buyer_public_key.serialize());

        let transaction_count = completed_orders
            .iter()
            .filter(|order| {
                order.buyer_public_key == buyer_public_key_str && order.current_state == "completed"
            })
            .count();

        if transaction_count < self.min_transactions {
            return Err(Error::InvalidState(format!(
                "Buyer must have completed at least {} transactions to leave a rating",
                self.min_transactions
            )));
        }

        // Submit the rating
        self.client
            .submit_rating(vendor_public_key, rating, review, completed_orders)
            .await
    }

    /// Retrieves the reputation summary for a vendor
    pub async fn get_vendor_reputation(
        &self,
        vendor_public_key: &str,
    ) -> Result<ReputationSummary> {
        self.client.get_vendor_reputation(vendor_public_key).await
    }

    /// Calculates a weighted reputation score that gives more weight to buyers with more transactions
    pub async fn get_weighted_reputation(
        &self,
        vendor_public_key: &str,
        all_orders: &[Order],
    ) -> Result<f64> {
        let summary = self.client.get_vendor_reputation(vendor_public_key).await?;

        if summary.total_ratings == 0 {
            return Ok(0.0);
        }

        // Group orders by buyer
        let mut buyer_transaction_counts = HashMap::new();
        for order in all_orders {
            if order.vendor_public_key == vendor_public_key && order.current_state == "completed" {
                *buyer_transaction_counts
                    .entry(order.buyer_public_key.clone())
                    .or_insert(0) += 1;
            }
        }

        // Calculate weighted score
        let mut weighted_sum = 0.0;
        let mut weight_sum = 0.0;

        for rating in &summary.recent_reviews {
            let buyer_transactions = buyer_transaction_counts
                .get(&rating.buyer_public_key)
                .unwrap_or(&0);
            let weight = 1.0 + ((*buyer_transactions as f64) / 10.0); // More transactions = more weight

            weighted_sum += (rating.rating as f64) * weight;
            weight_sum += weight;
        }

        if weight_sum > 0.0 {
            Ok(weighted_sum / weight_sum)
        } else {
            Ok(summary.average_rating)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::Crypto;
    use crate::models::{Location, OrderItem};
    use chrono::Duration;

    // Helper function to create a test order
    fn create_test_order(
        order_id: &str,
        buyer_key: &str,
        vendor_key: &str,
        state: &str,
        timestamp: u64,
    ) -> Order {
        Order {
            order_id: order_id.to_string(),
            buyer_public_key: buyer_key.to_string(),
            vendor_public_key: vendor_key.to_string(),
            order_items: vec![OrderItem::new("item-123".to_string(), 2)],
            total_amount: "20.99".to_string(),
            buyer_location: Some(Location::new(40.7128, -74.0060)),
            created_timestamp: timestamp,
            current_state: state.to_string(),
            payment_method: "BTC".to_string(),
            payment_details: "payment_details_123".to_string(),
            signature: "signature_123".to_string(),
        }
    }

    #[tokio::test]
    async fn test_reputation_verification() {
        // Create a keypair for testing
        let keypair = Crypto::generate_identity_keypair().unwrap();
        let public_key_str = Crypto::encode_base64(&keypair.public_key.serialize());

        // Create a reputation object
        let mut reputation = Reputation::new(
            "vendor_key_123".to_string(),
            public_key_str.clone(),
            5,
            Utc::now().timestamp() as u64,
            String::new(),
        )
        .with_review("Great service!".to_string());

        // Sign the reputation
        let reputation_bytes = reputation.serialize_for_signing().unwrap();
        let signature = Crypto::sign(&keypair.private_key, &reputation_bytes).unwrap();
        reputation.signature = Crypto::encode_base64(&signature);

        // Create a reputation manager for testing
        // In a real test, you'd use a mock DHT client
        let bootstrap_addresses = vec![];
        let dht_client = DhtClient::new(bootstrap_addresses).await.unwrap();
        let reputation_manager = ReputationManager::new(dht_client);

        // Verify the reputation
        let is_valid = reputation_manager.verify_rating(&reputation).unwrap();
        assert!(is_valid);

        // Tamper with the reputation and verify it fails
        let mut tampered_reputation = reputation.clone();
        tampered_reputation.rating = 1; // Change the rating

        let is_valid = reputation_manager
            .verify_rating(&tampered_reputation)
            .unwrap();
        assert!(!is_valid);
    }

    #[tokio::test]
    async fn test_submit_rating_requirements() {
        // Create a keypair for testing
        let keypair = Crypto::generate_identity_keypair().unwrap();
        let public_key_str = Crypto::encode_base64(&keypair.public_key.serialize());

        // Create a reputation client for testing
        let bootstrap_addresses = vec![];
        let dht_client = DhtClient::new(bootstrap_addresses).await.unwrap();
        let mut reputation_client = ReputationClient::new(dht_client);
        reputation_client.set_buyer_keys(keypair.private_key, keypair.public_key);

        // Create test orders
        let now = Utc::now().timestamp() as u64;
        let one_day_ago = (Utc::now() - Duration::days(1)).timestamp() as u64;
        let vendor_key = "vendor_key_456";

        let completed_order = create_test_order(
            "order-123",
            &public_key_str,
            vendor_key,
            "completed",
            one_day_ago,
        );

        let pending_order = create_test_order(
            "order-456",
            &public_key_str,
            vendor_key,
            "dispatched", // Not completed
            one_day_ago,
        );

        // Test with no completed orders
        let result = reputation_client
            .submit_rating(
                vendor_key.to_string(),
                5,
                Some("Great service!".to_string()),
                &[pending_order.clone()],
            )
            .await;

        assert!(result.is_err());

        // Test with a completed order
        let result = reputation_client
            .submit_rating(
                vendor_key.to_string(),
                5,
                Some("Great service!".to_string()),
                &[completed_order.clone()],
            )
            .await;

        // This should succeed in our test environment
        // In a real test, you'd mock the DHT client to verify the storage
        assert!(result.is_ok());
    }
}
