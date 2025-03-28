//! Dispute resolution framework for handling conflicts between buyers and vendors

use crate::core::crypto::Crypto;
use crate::core::error::Error;
use crate::core::types::OrderState;
use crate::models::{Message, Order};
use crate::Result;

use chrono::Utc;
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;

/// Dispute state enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisputeState {
    /// Dispute has been opened
    Opened,
    /// Evidence has been submitted
    EvidenceSubmitted,
    /// Dispute is under review by a mediator
    UnderReview,
    /// Dispute has been resolved in favor of the buyer
    ResolvedForBuyer,
    /// Dispute has been resolved in favor of the vendor
    ResolvedForVendor,
    /// Dispute has been resolved with a compromise
    ResolvedWithCompromise,
    /// Dispute has been cancelled
    Cancelled,
}

impl DisputeState {
    /// Converts the enum to a string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            DisputeState::Opened => "opened",
            DisputeState::EvidenceSubmitted => "evidence_submitted",
            DisputeState::UnderReview => "under_review",
            DisputeState::ResolvedForBuyer => "resolved_for_buyer",
            DisputeState::ResolvedForVendor => "resolved_for_vendor",
            DisputeState::ResolvedWithCompromise => "resolved_with_compromise",
            DisputeState::Cancelled => "cancelled",
        }
    }

    /// Converts a string to a DisputeState enum
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "opened" => Some(DisputeState::Opened),
            "evidence_submitted" => Some(DisputeState::EvidenceSubmitted),
            "under_review" => Some(DisputeState::UnderReview),
            "resolved_for_buyer" => Some(DisputeState::ResolvedForBuyer),
            "resolved_for_vendor" => Some(DisputeState::ResolvedForVendor),
            "resolved_with_compromise" => Some(DisputeState::ResolvedWithCompromise),
            "cancelled" => Some(DisputeState::Cancelled),
            _ => None,
        }
    }
}

/// Party involved in a dispute
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisputeParty {
    /// The buyer
    Buyer,
    /// The vendor
    Vendor,
    /// A third-party mediator
    Mediator,
}

impl DisputeParty {
    /// Converts the enum to a string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            DisputeParty::Buyer => "buyer",
            DisputeParty::Vendor => "vendor",
            DisputeParty::Mediator => "mediator",
        }
    }

    /// Converts a string to a DisputeParty enum
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "buyer" => Some(DisputeParty::Buyer),
            "vendor" => Some(DisputeParty::Vendor),
            "mediator" => Some(DisputeParty::Mediator),
            _ => None,
        }
    }
}

/// Evidence type for disputes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceType {
    /// Text description
    Text(String),
    /// Image (Base64 encoded)
    Image(String),
    /// Document (Base64 encoded)
    Document(String),
    /// Message history
    MessageHistory(Vec<Message>),
    /// Order details
    OrderDetails(Order),
}

/// Evidence submitted in a dispute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Unique identifier for the evidence
    pub id: String,
    /// Type of evidence
    pub evidence_type: EvidenceType,
    /// Description of the evidence
    pub description: String,
    /// Party that submitted the evidence
    pub submitted_by: DisputeParty,
    /// Timestamp when the evidence was submitted
    pub timestamp: u64,
    /// Signature of the submitter
    pub signature: String,
}

impl Evidence {
    /// Creates a new Evidence with the given parameters
    pub fn new(
        evidence_type: EvidenceType,
        description: String,
        submitted_by: DisputeParty,
        timestamp: u64,
        signature: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            evidence_type,
            description,
            submitted_by,
            timestamp,
            signature,
        }
    }

    /// Serializes the evidence to JSON, excluding the signature field
    pub fn serialize_for_signing(&self) -> Result<Vec<u8>> {
        // Create a copy without the signature
        let mut evidence_copy = self.clone();
        evidence_copy.signature = String::new();

        serde_json::to_vec(&evidence_copy).map_err(Error::Serialization)
    }
}

/// Resolution for a dispute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resolution {
    /// Outcome of the dispute
    pub outcome: DisputeState,
    /// Description of the resolution
    pub description: String,
    /// Party that resolved the dispute
    pub resolved_by: DisputeParty,
    /// Timestamp when the resolution was made
    pub timestamp: u64,
    /// Signature of the resolver
    pub signature: String,
}

impl Resolution {
    /// Creates a new Resolution with the given parameters
    pub fn new(
        outcome: DisputeState,
        description: String,
        resolved_by: DisputeParty,
        timestamp: u64,
        signature: String,
    ) -> Self {
        Self {
            outcome,
            description,
            resolved_by,
            timestamp,
            signature,
        }
    }

    /// Serializes the resolution to JSON, excluding the signature field
    pub fn serialize_for_signing(&self) -> Result<Vec<u8>> {
        // Create a copy without the signature
        let mut resolution_copy = self.clone();
        resolution_copy.signature = String::new();

        serde_json::to_vec(&resolution_copy).map_err(Error::Serialization)
    }
}

/// Dispute in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dispute {
    /// Unique identifier for the dispute
    pub id: String,
    /// ID of the order this dispute relates to
    pub order_id: String,
    /// Public key of the buyer
    pub buyer_public_key: String,
    /// Public key of the vendor
    pub vendor_public_key: String,
    /// Optional public key of the mediator
    pub mediator_public_key: Option<String>,
    /// Reason for the dispute
    pub reason: String,
    /// Current state of the dispute
    pub state: DisputeState,
    /// Evidence submitted in the dispute
    pub evidence: Vec<Evidence>,
    /// Resolution of the dispute (if resolved)
    pub resolution: Option<Resolution>,
    /// Timestamp when the dispute was created
    pub created_timestamp: u64,
    /// Timestamp when the dispute was last updated
    pub updated_timestamp: u64,
    /// Party that initiated the dispute
    pub initiated_by: DisputeParty,
    /// Signature of the initiator
    pub signature: String,
}

impl Dispute {
    /// Creates a new Dispute with the given parameters
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        order_id: String,
        buyer_public_key: String,
        vendor_public_key: String,
        reason: String,
        initiated_by: DisputeParty,
        timestamp: u64,
        signature: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            order_id,
            buyer_public_key,
            vendor_public_key,
            mediator_public_key: None,
            reason,
            state: DisputeState::Opened,
            evidence: Vec::new(),
            resolution: None,
            created_timestamp: timestamp,
            updated_timestamp: timestamp,
            initiated_by,
            signature,
        }
    }

    /// Adds a mediator to the dispute
    pub fn with_mediator(mut self, mediator_public_key: String) -> Self {
        self.mediator_public_key = Some(mediator_public_key);
        self
    }

    /// Serializes the dispute to JSON, excluding the signature field
    pub fn serialize_for_signing(&self) -> Result<Vec<u8>> {
        // Create a copy without the signature
        let mut dispute_copy = self.clone();
        dispute_copy.signature = String::new();

        serde_json::to_vec(&dispute_copy).map_err(Error::Serialization)
    }

    /// Updates the state of the dispute
    pub fn update_state(&mut self, new_state: DisputeState, timestamp: u64) {
        self.state = new_state;
        self.updated_timestamp = timestamp;
    }

    /// Adds evidence to the dispute
    pub fn add_evidence(&mut self, evidence: Evidence, timestamp: u64) {
        self.evidence.push(evidence);
        self.updated_timestamp = timestamp;

        // Update the state if this is the first evidence
        if self.evidence.len() == 1 {
            self.state = DisputeState::EvidenceSubmitted;
        }
    }

    /// Sets the resolution of the dispute
    pub fn set_resolution(&mut self, resolution: Resolution, timestamp: u64) {
        self.resolution = Some(resolution);
        self.updated_timestamp = timestamp;

        // Update the state based on the resolution outcome
        if let Some(res) = &self.resolution {
            self.state = res.outcome.clone();
        }
    }
}

/// Dispute manager for handling dispute creation and resolution
pub struct DisputeManager {
    /// Private key for signing dispute messages
    private_key: Option<SecretKey>,
    /// Public key
    public_key: Option<PublicKey>,
    /// Party type (buyer, vendor, or mediator)
    party_type: DisputeParty,
    /// Cache of disputes
    disputes: HashMap<String, Dispute>,
}

impl DisputeManager {
    /// Creates a new DisputeManager for the given party type
    pub fn new(party_type: DisputeParty) -> Self {
        Self {
            private_key: None,
            public_key: None,
            party_type,
            disputes: HashMap::new(),
        }
    }

    /// Sets the keys for signing dispute messages
    pub fn set_keys(&mut self, private_key: SecretKey, public_key: PublicKey) {
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
    }

    /// Initiates a new dispute for an order
    pub fn initiate_dispute(&mut self, order: &Order, reason: String) -> Result<Dispute> {
        // Ensure the private key is set
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| Error::Authentication("Private key not set".into()))?;

        // Ensure the party type is either buyer or vendor
        if self.party_type != DisputeParty::Buyer && self.party_type != DisputeParty::Vendor {
            return Err(Error::InvalidState(
                "Only buyers and vendors can initiate disputes".into(),
            ));
        }

        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        // Create the dispute without a signature first
        let mut dispute = Dispute::new(
            order.order_id.clone(),
            order.buyer_public_key.clone(),
            order.vendor_public_key.clone(),
            reason,
            self.party_type.clone(),
            timestamp,
            String::new(), // Empty signature for now
        );

        // Serialize the dispute for signing
        let dispute_bytes = dispute.serialize_for_signing()?;

        // Sign the dispute
        let signature = Crypto::sign(private_key, &dispute_bytes)?;

        // Set the signature
        dispute.signature = Crypto::encode_base64(&signature);

        // Add the dispute to the cache
        self.disputes.insert(dispute.id.clone(), dispute.clone());

        Ok(dispute)
    }

    /// Submits evidence for a dispute
    pub fn submit_evidence(
        &mut self,
        dispute_id: &str,
        evidence_type: EvidenceType,
        description: String,
    ) -> Result<Evidence> {
        // Ensure the private key is set
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| Error::Authentication("Private key not set".into()))?;

        // Get the dispute
        let dispute = self
            .disputes
            .get_mut(dispute_id)
            .ok_or_else(|| Error::InvalidData(format!("Dispute not found: {}", dispute_id)))?;

        // Ensure the dispute is in a state that allows evidence submission
        if dispute.state != DisputeState::Opened && dispute.state != DisputeState::EvidenceSubmitted
        {
            return Err(Error::InvalidState(format!(
                "Cannot submit evidence in state: {}",
                dispute.state.as_str()
            )));
        }

        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        // Create the evidence without a signature first
        let mut evidence = Evidence::new(
            evidence_type,
            description,
            self.party_type.clone(),
            timestamp,
            String::new(), // Empty signature for now
        );

        // Serialize the evidence for signing
        let evidence_bytes = evidence.serialize_for_signing()?;

        // Sign the evidence
        let signature = Crypto::sign(private_key, &evidence_bytes)?;

        // Set the signature
        evidence.signature = Crypto::encode_base64(&signature);

        // Add the evidence to the dispute
        dispute.add_evidence(evidence.clone(), timestamp);

        Ok(evidence)
    }

    /// Resolves a dispute (for mediators or direct resolution)
    pub fn resolve_dispute(
        &mut self,
        dispute_id: &str,
        outcome: DisputeState,
        description: String,
    ) -> Result<Resolution> {
        // Ensure the private key is set
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| Error::Authentication("Private key not set".into()))?;

        // Get the dispute
        let dispute = self
            .disputes
            .get_mut(dispute_id)
            .ok_or_else(|| Error::InvalidData(format!("Dispute not found: {}", dispute_id)))?;

        // Check if the party is authorized to resolve the dispute
        match self.party_type {
            DisputeParty::Mediator => {
                // Ensure this mediator is assigned to the dispute
                if let Some(mediator_key) = &dispute.mediator_public_key {
                    let public_key = self
                        .public_key
                        .as_ref()
                        .ok_or_else(|| Error::Authentication("Public key not set".into()))?;
                    let public_key_str = Crypto::encode_base64(&public_key.serialize());

                    if *mediator_key != public_key_str {
                        return Err(Error::Authentication(
                            "Not authorized to resolve this dispute".into(),
                        ));
                    }
                } else {
                    return Err(Error::InvalidState(
                        "No mediator assigned to this dispute".into(),
                    ));
                }
            }
            DisputeParty::Buyer | DisputeParty::Vendor => {
                // For direct resolution, both parties must agree
                // This is simplified - in a real implementation, you'd check for agreement
                // For now, we'll allow either party to resolve
            }
        }

        // Ensure the dispute is in a state that allows resolution
        if dispute.state == DisputeState::ResolvedForBuyer
            || dispute.state == DisputeState::ResolvedForVendor
            || dispute.state == DisputeState::ResolvedWithCompromise
            || dispute.state == DisputeState::Cancelled
        {
            return Err(Error::InvalidState(format!(
                "Dispute already resolved: {}",
                dispute.state.as_str()
            )));
        }

        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        // Create the resolution without a signature first
        let mut resolution = Resolution::new(
            outcome,
            description,
            self.party_type.clone(),
            timestamp,
            String::new(), // Empty signature for now
        );

        // Serialize the resolution for signing
        let resolution_bytes = resolution.serialize_for_signing()?;

        // Sign the resolution
        let signature = Crypto::sign(private_key, &resolution_bytes)?;

        // Set the signature
        resolution.signature = Crypto::encode_base64(&signature);

        // Set the resolution in the dispute
        dispute.set_resolution(resolution.clone(), timestamp);

        Ok(resolution)
    }

    /// Assigns a mediator to a dispute
    pub fn assign_mediator(&mut self, dispute_id: &str, mediator_public_key: String) -> Result<()> {
        // Get the dispute
        let dispute = self
            .disputes
            .get_mut(dispute_id)
            .ok_or_else(|| Error::InvalidData(format!("Dispute not found: {}", dispute_id)))?;

        // Ensure the dispute doesn't already have a mediator
        if dispute.mediator_public_key.is_some() {
            return Err(Error::InvalidState(
                "Dispute already has a mediator assigned".into(),
            ));
        }

        // Assign the mediator
        dispute.mediator_public_key = Some(mediator_public_key);
        dispute.update_state(DisputeState::UnderReview, Utc::now().timestamp() as u64);

        Ok(())
    }

    /// Gets a dispute by ID
    pub fn get_dispute(&self, dispute_id: &str) -> Option<&Dispute> {
        self.disputes.get(dispute_id)
    }

    /// Gets all disputes
    pub fn get_all_disputes(&self) -> Vec<&Dispute> {
        self.disputes.values().collect()
    }

    /// Gets disputes for a specific order
    pub fn get_disputes_for_order(&self, order_id: &str) -> Vec<&Dispute> {
        self.disputes
            .values()
            .filter(|d| d.order_id == order_id)
            .collect()
    }

    /// Verifies the authenticity of a dispute
    pub fn verify_dispute(&self, dispute: &Dispute) -> Result<bool> {
        // Parse the initiator's public key
        let public_key_str = match dispute.initiated_by {
            DisputeParty::Buyer => &dispute.buyer_public_key,
            DisputeParty::Vendor => &dispute.vendor_public_key,
            DisputeParty::Mediator => dispute
                .mediator_public_key
                .as_ref()
                .ok_or_else(|| Error::InvalidData("Mediator public key not found".into()))?,
        };

        let public_key_bytes = Crypto::decode_base64(public_key_str)?;
        let public_key = PublicKey::from_slice(&public_key_bytes)
            .map_err(|e| Error::Crypto(format!("Invalid public key: {}", e)))?;

        // Parse the signature
        let signature = Crypto::decode_base64(&dispute.signature)?;

        // Create a copy of the dispute without the signature for verification
        let mut dispute_copy = dispute.clone();
        dispute_copy.signature = String::new();

        // Serialize the dispute for verification
        let dispute_bytes = dispute_copy.serialize_for_signing()?;

        // Verify the signature
        Crypto::verify(&public_key, &dispute_bytes, &signature)
    }

    /// Verifies the authenticity of evidence
    pub fn verify_evidence(&self, evidence: &Evidence, dispute: &Dispute) -> Result<bool> {
        // Determine the public key based on who submitted the evidence
        let public_key_str = match evidence.submitted_by {
            DisputeParty::Buyer => &dispute.buyer_public_key,
            DisputeParty::Vendor => &dispute.vendor_public_key,
            DisputeParty::Mediator => dispute
                .mediator_public_key
                .as_ref()
                .ok_or_else(|| Error::InvalidData("Mediator public key not found".into()))?,
        };

        let public_key_bytes = Crypto::decode_base64(public_key_str)?;
        let public_key = PublicKey::from_slice(&public_key_bytes)
            .map_err(|e| Error::Crypto(format!("Invalid public key: {}", e)))?;

        // Parse the signature
        let signature = Crypto::decode_base64(&evidence.signature)?;

        // Create a copy of the evidence without the signature for verification
        let mut evidence_copy = evidence.clone();
        evidence_copy.signature = String::new();

        // Serialize the evidence for verification
        let evidence_bytes = evidence_copy.serialize_for_signing()?;

        // Verify the signature
        Crypto::verify(&public_key, &evidence_bytes, &signature)
    }

    /// Verifies the authenticity of a resolution
    pub fn verify_resolution(&self, resolution: &Resolution, dispute: &Dispute) -> Result<bool> {
        // Determine the public key based on who resolved the dispute
        let public_key_str = match resolution.resolved_by {
            DisputeParty::Buyer => &dispute.buyer_public_key,
            DisputeParty::Vendor => &dispute.vendor_public_key,
            DisputeParty::Mediator => dispute
                .mediator_public_key
                .as_ref()
                .ok_or_else(|| Error::InvalidData("Mediator public key not found".into()))?,
        };

        let public_key_bytes = Crypto::decode_base64(public_key_str)?;
        let public_key = PublicKey::from_slice(&public_key_bytes)
            .map_err(|e| Error::Crypto(format!("Invalid public key: {}", e)))?;

        // Parse the signature
        let signature = Crypto::decode_base64(&resolution.signature)?;

        // Create a copy of the resolution without the signature for verification
        let mut resolution_copy = resolution.clone();
        resolution_copy.signature = String::new();

        // Serialize the resolution for verification
        let resolution_bytes = resolution_copy.serialize_for_signing()?;

        // Verify the signature
        Crypto::verify(&public_key, &resolution_bytes, &signature)
    }

    /// Creates a dispute message for the order state machine
    pub fn create_dispute_message(&self, dispute: &Dispute) -> Result<Message> {
        // Ensure the private key is set
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| Error::Authentication("Private key not set".into()))?;

        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        // Create the payload with dispute details
        let payload = json!({
            "dispute_id": dispute.id,
            "reason": dispute.reason,
            "initiated_by": dispute.initiated_by.as_str(),
            "state": dispute.state.as_str(),
        });

        // Create the message without a signature first
        let mut message = Message::new(
            "dispute_initiation".to_string(),
            dispute.order_id.clone(),
            timestamp,
            String::new(), // Empty signature for now
        )
        .with_status("disputed".to_string())
        .with_payload(payload);

        // Serialize the message for signing
        let message_bytes = message.serialize_for_signing()?;

        // Sign the message
        let signature = Crypto::sign(private_key, &message_bytes)?;

        // Set the signature
        message.signature = Crypto::encode_base64(&signature);

        Ok(message)
    }

    /// Creates an evidence message for the order state machine
    pub fn create_evidence_message(
        &self,
        dispute: &Dispute,
        evidence: &Evidence,
    ) -> Result<Message> {
        // Ensure the private key is set
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| Error::Authentication("Private key not set".into()))?;

        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        // Create the payload with evidence details
        let payload = json!({
            "dispute_id": dispute.id,
            "evidence_id": evidence.id,
            "description": evidence.description,
            "submitted_by": evidence.submitted_by.as_str(),
        });

        // Create the message without a signature first
        let mut message = Message::new(
            "dispute_evidence".to_string(),
            dispute.order_id.clone(),
            timestamp,
            String::new(), // Empty signature for now
        )
        .with_status("evidence_submitted".to_string())
        .with_payload(payload);

        // Serialize the message for signing
        let message_bytes = message.serialize_for_signing()?;

        // Sign the message
        let signature = Crypto::sign(private_key, &message_bytes)?;

        // Set the signature
        message.signature = Crypto::encode_base64(&signature);

        Ok(message)
    }

    /// Creates a resolution message for the order state machine
    pub fn create_resolution_message(&self, dispute: &Dispute) -> Result<Message> {
        // Ensure the private key is set
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| Error::Authentication("Private key not set".into()))?;

        // Ensure the dispute has a resolution
        let resolution = dispute
            .resolution
            .as_ref()
            .ok_or_else(|| Error::InvalidState("Dispute has no resolution".into()))?;

        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        // Create the payload with resolution details
        let payload = json!({
            "dispute_id": dispute.id,
            "outcome": resolution.outcome.as_str(),
            "description": resolution.description,
            "resolved_by": resolution.resolved_by.as_str(),
        });

        // Create the message without a signature first
        let mut message = Message::new(
            "dispute_resolution".to_string(),
            dispute.order_id.clone(),
            timestamp,
            String::new(), // Empty signature for now
        )
        .with_status(resolution.outcome.as_str().to_string())
        .with_payload(payload);

        // Serialize the message for signing
        let message_bytes = message.serialize_for_signing()?;

        // Sign the message
        let signature = Crypto::sign(private_key, &message_bytes)?;

        // Set the signature
        message.signature = Crypto::encode_base64(&signature);

        Ok(message)
    }

    /// Processes a dispute message from the order state machine
    pub fn process_dispute_message(
        &mut self,
        message: &Message,
        order: &Order,
    ) -> Result<Option<Dispute>> {
        // Ensure the message is a dispute-related message
        if message.message_type != "dispute_initiation"
            && message.message_type != "dispute_evidence"
            && message.message_type != "dispute_resolution"
        {
            return Ok(None);
        }

        // Parse the payload
        let payload = message
            .payload
            .as_ref()
            .ok_or_else(|| Error::InvalidData("Message has no payload".into()))?;

        match message.message_type.as_str() {
            "dispute_initiation" => {
                // Extract dispute details from the payload
                let dispute_id = payload["dispute_id"]
                    .as_str()
                    .ok_or_else(|| Error::InvalidData("Missing dispute_id in payload".into()))?;
                let reason = payload["reason"]
                    .as_str()
                    .ok_or_else(|| Error::InvalidData("Missing reason in payload".into()))?;
                let initiated_by_str = payload["initiated_by"]
                    .as_str()
                    .ok_or_else(|| Error::InvalidData("Missing initiated_by in payload".into()))?;
                let state_str = payload["state"]
                    .as_str()
                    .ok_or_else(|| Error::InvalidData("Missing state in payload".into()))?;

                let initiated_by = DisputeParty::from_str(initiated_by_str).ok_or_else(|| {
                    Error::InvalidData(format!("Invalid dispute party: {}", initiated_by_str))
                })?;
                let state = DisputeState::from_str(state_str).ok_or_else(|| {
                    Error::InvalidData(format!("Invalid dispute state: {}", state_str))
                })?;

                // Create a new dispute
                let mut dispute = Dispute::new(
                    order.order_id.clone(),
                    order.buyer_public_key.clone(),
                    order.vendor_public_key.clone(),
                    reason.to_string(),
                    initiated_by,
                    message.timestamp,
                    message.signature.clone(),
                );

                // Set the ID to match the one in the message
                dispute.id = dispute_id.to_string();

                // Add the dispute to the cache
                self.disputes.insert(dispute.id.clone(), dispute.clone());

                Ok(Some(dispute))
            }
            "dispute_evidence" => {
                // Extract evidence details from the payload
                let dispute_id = payload["dispute_id"]
                    .as_str()
                    .ok_or_else(|| Error::InvalidData("Missing dispute_id in payload".into()))?;

                // Get the dispute
                let dispute = self.disputes.get_mut(dispute_id).ok_or_else(|| {
                    Error::InvalidData(format!("Dispute not found: {}", dispute_id))
                })?;

                // Extract more evidence details
                let evidence_id = payload["evidence_id"]
                    .as_str()
                    .ok_or_else(|| Error::InvalidData("Missing evidence_id in payload".into()))?;
                let description = payload["description"]
                    .as_str()
                    .ok_or_else(|| Error::InvalidData("Missing description in payload".into()))?;
                let submitted_by_str = payload["submitted_by"]
                    .as_str()
                    .ok_or_else(|| Error::InvalidData("Missing submitted_by in payload".into()))?;

                let submitted_by = DisputeParty::from_str(submitted_by_str).ok_or_else(|| {
                    Error::InvalidData(format!("Invalid dispute party: {}", submitted_by_str))
                })?;

                // Create a simplified evidence object (in a real implementation, you'd extract the actual evidence)
                let evidence = Evidence::new(
                    EvidenceType::Text("Evidence from message".to_string()),
                    description.to_string(),
                    submitted_by,
                    message.timestamp,
                    message.signature.clone(),
                );

                // Add the evidence to the dispute
                dispute.add_evidence(evidence, message.timestamp);

                Ok(Some(dispute.clone()))
            }
            "dispute_resolution" => {
                // Extract resolution details from the payload
                let dispute_id = payload["dispute_id"]
                    .as_str()
                    .ok_or_else(|| Error::InvalidData("Missing dispute_id in payload".into()))?;
                let outcome_str = payload["outcome"]
                    .as_str()
                    .ok_or_else(|| Error::InvalidData("Missing outcome in payload".into()))?;
                let description = payload["description"]
                    .as_str()
                    .ok_or_else(|| Error::InvalidData("Missing description in payload".into()))?;
                let resolved_by_str = payload["resolved_by"]
                    .as_str()
                    .ok_or_else(|| Error::InvalidData("Missing resolved_by in payload".into()))?;

                let outcome = DisputeState::from_str(outcome_str).ok_or_else(|| {
                    Error::InvalidData(format!("Invalid dispute state: {}", outcome_str))
                })?;
                let resolved_by = DisputeParty::from_str(resolved_by_str).ok_or_else(|| {
                    Error::InvalidData(format!("Invalid dispute party: {}", resolved_by_str))
                })?;

                // Get the dispute
                let dispute = self.disputes.get_mut(dispute_id).ok_or_else(|| {
                    Error::InvalidData(format!("Dispute not found: {}", dispute_id))
                })?;

                // Create a resolution
                let resolution = Resolution::new(
                    outcome,
                    description.to_string(),
                    resolved_by,
                    message.timestamp,
                    message.signature.clone(),
                );

                // Set the resolution in the dispute
                dispute.set_resolution(resolution, message.timestamp);

                Ok(Some(dispute.clone()))
            }
            _ => Ok(None),
        }
    }
}

/// Dispute client for interacting with the dispute resolution system
pub struct DisputeClient {
    /// The dispute manager
    manager: DisputeManager,
}

impl DisputeClient {
    /// Creates a new DisputeClient for the given party type
    pub fn new(party_type: DisputeParty) -> Self {
        Self {
            manager: DisputeManager::new(party_type),
        }
    }

    /// Sets the keys for signing dispute messages
    pub fn set_keys(&mut self, private_key: SecretKey, public_key: PublicKey) {
        self.manager.set_keys(private_key, public_key);
    }

    /// Initiates a new dispute for an order
    pub fn initiate_dispute(
        &mut self,
        order: &Order,
        reason: String,
    ) -> Result<(Dispute, Message)> {
        let dispute = self.manager.initiate_dispute(order, reason)?;
        let message = self.manager.create_dispute_message(&dispute)?;

        Ok((dispute, message))
    }

    /// Submits evidence for a dispute
    pub fn submit_evidence(
        &mut self,
        dispute_id: &str,
        evidence_type: EvidenceType,
        description: String,
    ) -> Result<(Evidence, Message)> {
        let evidence = self
            .manager
            .submit_evidence(dispute_id, evidence_type, description)?;

        let dispute = self
            .manager
            .get_dispute(dispute_id)
            .ok_or_else(|| Error::InvalidData(format!("Dispute not found: {}", dispute_id)))?;

        let message = self.manager.create_evidence_message(dispute, &evidence)?;

        Ok((evidence, message))
    }

    /// Resolves a dispute
    pub fn resolve_dispute(
        &mut self,
        dispute_id: &str,
        outcome: DisputeState,
        description: String,
    ) -> Result<(Resolution, Message)> {
        let resolution = self
            .manager
            .resolve_dispute(dispute_id, outcome, description)?;

        let dispute = self
            .manager
            .get_dispute(dispute_id)
            .ok_or_else(|| Error::InvalidData(format!("Dispute not found: {}", dispute_id)))?;

        let message = self.manager.create_resolution_message(dispute)?;

        Ok((resolution, message))
    }

    /// Assigns a mediator to a dispute
    pub fn assign_mediator(&mut self, dispute_id: &str, mediator_public_key: String) -> Result<()> {
        self.manager
            .assign_mediator(dispute_id, mediator_public_key)
    }

    /// Gets a dispute by ID
    pub fn get_dispute(&self, dispute_id: &str) -> Option<&Dispute> {
        self.manager.get_dispute(dispute_id)
    }

    /// Gets all disputes
    pub fn get_all_disputes(&self) -> Vec<&Dispute> {
        self.manager.get_all_disputes()
    }

    /// Gets disputes for a specific order
    pub fn get_disputes_for_order(&self, order_id: &str) -> Vec<&Dispute> {
        self.manager.get_disputes_for_order(order_id)
    }

    /// Processes a dispute message
    pub fn process_dispute_message(
        &mut self,
        message: &Message,
        order: &Order,
    ) -> Result<Option<Dispute>> {
        self.manager.process_dispute_message(message, order)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::Crypto;
    use crate::models::{Location, OrderItem};

    // Helper function to create a test order
    fn create_test_order(order_id: &str, buyer_key: &str, vendor_key: &str, state: &str) -> Order {
        Order {
            order_id: order_id.to_string(),
            buyer_public_key: buyer_key.to_string(),
            vendor_public_key: vendor_key.to_string(),
            order_items: vec![OrderItem::new("item-123".to_string(), 2)],
            total_amount: "20.99".to_string(),
            buyer_location: Some(Location::new(40.7128, -74.0060)),
            created_timestamp: Utc::now().timestamp() as u64,
            current_state: state.to_string(),
            payment_method: "BTC".to_string(),
            payment_details: "payment_details_123".to_string(),
            signature: "signature_123".to_string(),
        }
    }

    #[test]
    fn test_dispute_lifecycle() {
        // Create keypairs for testing
        let buyer_keypair = Crypto::generate_identity_keypair().unwrap();
        let vendor_keypair = Crypto::generate_identity_keypair().unwrap();
        let mediator_keypair = Crypto::generate_identity_keypair().unwrap();

        let buyer_public_key = Crypto::encode_base64(&buyer_keypair.public_key.serialize());
        let vendor_public_key = Crypto::encode_base64(&vendor_keypair.public_key.serialize());
        let mediator_public_key = Crypto::encode_base64(&mediator_keypair.public_key.serialize());

        // Create a test order
        let order = create_test_order(
            "order-123",
            &buyer_public_key,
            &vendor_public_key,
            "delivered",
        );

        // Create dispute clients for each party
        let mut buyer_client = DisputeClient::new(DisputeParty::Buyer);
        let mut vendor_client = DisputeClient::new(DisputeParty::Vendor);
        let mut mediator_client = DisputeClient::new(DisputeParty::Mediator);

        buyer_client.set_keys(buyer_keypair.private_key, buyer_keypair.public_key);
        vendor_client.set_keys(vendor_keypair.private_key, vendor_keypair.public_key);
        mediator_client.set_keys(mediator_keypair.private_key, mediator_keypair.public_key);

        // Buyer initiates a dispute
        let (dispute, message) = buyer_client
            .initiate_dispute(&order, "Item received was damaged".to_string())
            .unwrap();

        // Vendor processes the dispute message
        let processed_dispute = vendor_client
            .process_dispute_message(&message, &order)
            .unwrap()
            .unwrap();

        assert_eq!(processed_dispute.id, dispute.id);
        assert_eq!(processed_dispute.reason, "Item received was damaged");
        assert_eq!(processed_dispute.state, DisputeState::Opened);

        // Vendor submits evidence
        let (evidence, evidence_message) = vendor_client
            .submit_evidence(
                &dispute.id,
                EvidenceType::Text("The item was properly packaged and insured".to_string()),
                "Shipping confirmation and insurance details".to_string(),
            )
            .unwrap();

        // Buyer processes the evidence message
        let updated_dispute = buyer_client
            .process_dispute_message(&evidence_message, &order)
            .unwrap()
            .unwrap();

        assert_eq!(updated_dispute.state, DisputeState::EvidenceSubmitted);
        assert_eq!(updated_dispute.evidence.len(), 1);

        // Buyer assigns a mediator
        buyer_client
            .assign_mediator(&dispute.id, mediator_public_key.clone())
            .unwrap();

        // Mediator resolves the dispute
        let (resolution, resolution_message) = mediator_client
            .resolve_dispute(
                &dispute.id,
                DisputeState::ResolvedWithCompromise,
                "Partial refund of 50% recommended".to_string(),
            )
            .unwrap();

        // Buyer processes the resolution message
        let final_dispute = buyer_client
            .process_dispute_message(&resolution_message, &order)
            .unwrap()
            .unwrap();

        assert_eq!(final_dispute.state, DisputeState::ResolvedWithCompromise);
        assert!(final_dispute.resolution.is_some());
        assert_eq!(
            final_dispute.resolution.as_ref().unwrap().description,
            "Partial refund of 50% recommended"
        );
    }
}
