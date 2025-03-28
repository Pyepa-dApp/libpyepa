//! Payment processing system with support for Bitcoin and USDC

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
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// Payment method enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentMethod {
    /// Bitcoin payment
    Bitcoin,
    /// USDC payment (on various chains)
    USDC(USDCChain),
    /// Other cryptocurrency
    OtherCrypto(String),
}

impl PaymentMethod {
    /// Converts the enum to a string representation
    pub fn as_str(&self) -> String {
        match self {
            PaymentMethod::Bitcoin => "BTC".to_string(),
            PaymentMethod::USDC(chain) => format!("USDC_{}", chain.as_str()),
            PaymentMethod::OtherCrypto(name) => name.clone(),
        }
    }

    /// Converts a string to a PaymentMethod enum
    pub fn from_str(s: &str) -> Option<Self> {
        if s == "BTC" {
            Some(PaymentMethod::Bitcoin)
        } else if s.starts_with("USDC_") {
            let chain_str = s.strip_prefix("USDC_")?;
            let chain = USDCChain::from_str(chain_str)?;
            Some(PaymentMethod::USDC(chain))
        } else {
            Some(PaymentMethod::OtherCrypto(s.to_string()))
        }
    }
}

/// USDC blockchain enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum USDCChain {
    /// Ethereum
    Ethereum,
    /// Solana
    Solana,
    /// Polygon
    Polygon,
    /// Arbitrum
    Arbitrum,
    /// Optimism
    Optimism,
    /// Base
    Base,
    /// Avalanche
    Avalanche,
}

impl USDCChain {
    /// Converts the enum to a string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            USDCChain::Ethereum => "ETH",
            USDCChain::Solana => "SOL",
            USDCChain::Polygon => "MATIC",
            USDCChain::Arbitrum => "ARB",
            USDCChain::Optimism => "OP",
            USDCChain::Base => "BASE",
            USDCChain::Avalanche => "AVAX",
        }
    }

    /// Converts a string to a USDCChain enum
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "ETH" => Some(USDCChain::Ethereum),
            "SOL" => Some(USDCChain::Solana),
            "MATIC" => Some(USDCChain::Polygon),
            "ARB" => Some(USDCChain::Arbitrum),
            "OP" => Some(USDCChain::Optimism),
            "BASE" => Some(USDCChain::Base),
            "AVAX" => Some(USDCChain::Avalanche),
            _ => None,
        }
    }
}

/// Payment status enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentStatus {
    /// Payment is pending
    Pending,
    /// Payment is confirmed (enough confirmations)
    Confirmed,
    /// Payment is completed (order fulfilled)
    Completed,
    /// Payment is refunded
    Refunded,
    /// Payment is partially refunded
    PartiallyRefunded,
    /// Payment is in escrow
    InEscrow,
    /// Payment is released from escrow
    EscrowReleased,
    /// Payment failed
    Failed,
}

impl PaymentStatus {
    /// Converts the enum to a string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            PaymentStatus::Pending => "pending",
            PaymentStatus::Confirmed => "confirmed",
            PaymentStatus::Completed => "completed",
            PaymentStatus::Refunded => "refunded",
            PaymentStatus::PartiallyRefunded => "partially_refunded",
            PaymentStatus::InEscrow => "in_escrow",
            PaymentStatus::EscrowReleased => "escrow_released",
            PaymentStatus::Failed => "failed",
        }
    }

    /// Converts a string to a PaymentStatus enum
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(PaymentStatus::Pending),
            "confirmed" => Some(PaymentStatus::Confirmed),
            "completed" => Some(PaymentStatus::Completed),
            "refunded" => Some(PaymentStatus::Refunded),
            "partially_refunded" => Some(PaymentStatus::PartiallyRefunded),
            "in_escrow" => Some(PaymentStatus::InEscrow),
            "escrow_released" => Some(PaymentStatus::EscrowReleased),
            "failed" => Some(PaymentStatus::Failed),
            _ => None,
        }
    }
}

/// Escrow type enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscrowType {
    /// Multisignature escrow (typically for Bitcoin)
    Multisig,
    /// Smart contract escrow (for USDC and other tokens)
    SmartContract,
    /// Third-party escrow service
    ThirdParty,
}

impl EscrowType {
    /// Converts the enum to a string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            EscrowType::Multisig => "multisig",
            EscrowType::SmartContract => "smart_contract",
            EscrowType::ThirdParty => "third_party",
        }
    }

    /// Converts a string to an EscrowType enum
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "multisig" => Some(EscrowType::Multisig),
            "smart_contract" => Some(EscrowType::SmartContract),
            "third_party" => Some(EscrowType::ThirdParty),
            _ => None,
        }
    }
}

/// Payment details for an order
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentDetails {
    /// Unique identifier for the payment
    pub payment_id: String,
    /// Order ID this payment is for
    pub order_id: String,
    /// Payment method
    pub method: PaymentMethod,
    /// Amount in the payment currency
    pub amount: String,
    /// Optional exchange rate to USD at time of payment
    pub exchange_rate_usd: Option<f64>,
    /// Payment address (recipient's cryptocurrency address)
    pub payment_address: String,
    /// Optional transaction ID on the blockchain
    pub transaction_id: Option<String>,
    /// Current status of the payment
    pub status: PaymentStatus,
    /// Timestamp when the payment was created
    pub created_timestamp: u64,
    /// Timestamp when the payment was last updated
    pub updated_timestamp: u64,
    /// Optional escrow details
    pub escrow: Option<EscrowDetails>,
    /// Optional refund details
    pub refund: Option<RefundDetails>,
    /// Signature of the creator
    pub signature: String,
}

impl PaymentDetails {
    /// Creates a new PaymentDetails with the given parameters
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        order_id: String,
        method: PaymentMethod,
        amount: String,
        payment_address: String,
        status: PaymentStatus,
        timestamp: u64,
        signature: String,
    ) -> Self {
        Self {
            payment_id: Uuid::new_v4().to_string(),
            order_id,
            method,
            amount,
            exchange_rate_usd: None,
            payment_address,
            transaction_id: None,
            status,
            created_timestamp: timestamp,
            updated_timestamp: timestamp,
            escrow: None,
            refund: None,
            signature,
        }
    }

    /// Sets the exchange rate to USD
    pub fn with_exchange_rate(mut self, rate: f64) -> Self {
        self.exchange_rate_usd = Some(rate);
        self
    }

    /// Sets the transaction ID
    pub fn with_transaction_id(mut self, tx_id: String) -> Self {
        self.transaction_id = Some(tx_id);
        self
    }

    /// Sets the escrow details
    pub fn with_escrow(mut self, escrow: EscrowDetails) -> Self {
        self.escrow = Some(escrow);
        self
    }

    /// Updates the payment status
    pub fn update_status(&mut self, new_status: PaymentStatus, timestamp: u64) {
        self.status = new_status;
        self.updated_timestamp = timestamp;
    }

    /// Sets the refund details
    pub fn set_refund(&mut self, refund: RefundDetails, timestamp: u64) {
        self.refund = Some(refund);
        self.updated_timestamp = timestamp;

        // Update the status based on the refund amount
        if let Some(ref_amount) = &refund.amount {
            if ref_amount == &self.amount {
                self.status = PaymentStatus::Refunded;
            } else {
                self.status = PaymentStatus::PartiallyRefunded;
            }
        }
    }

    /// Serializes the payment details to JSON, excluding the signature field
    pub fn serialize_for_signing(&self) -> Result<Vec<u8>> {
        // Create a copy without the signature
        let mut payment_copy = self.clone();
        payment_copy.signature = String::new();

        serde_json::to_vec(&payment_copy).map_err(Error::Serialization)
    }
}

/// Escrow details for a payment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowDetails {
    /// Type of escrow
    pub escrow_type: EscrowType,
    /// Escrow address or identifier
    pub escrow_address: String,
    /// Public keys of all parties involved in the escrow
    pub participant_keys: Vec<String>,
    /// Required signatures to release funds
    pub required_signatures: u32,
    /// Current status of the escrow
    pub status: PaymentStatus,
    /// Timestamp when the escrow was created
    pub created_timestamp: u64,
    /// Optional release transaction ID
    pub release_transaction_id: Option<String>,
}

impl EscrowDetails {
    /// Creates a new EscrowDetails with the given parameters
    pub fn new(
        escrow_type: EscrowType,
        escrow_address: String,
        participant_keys: Vec<String>,
        required_signatures: u32,
        timestamp: u64,
    ) -> Self {
        Self {
            escrow_type,
            escrow_address,
            participant_keys,
            required_signatures,
            status: PaymentStatus::InEscrow,
            created_timestamp: timestamp,
            release_transaction_id: None,
        }
    }

    /// Sets the release transaction ID
    pub fn with_release_transaction(mut self, tx_id: String) -> Self {
        self.release_transaction_id = Some(tx_id);
        self.status = PaymentStatus::EscrowReleased;
        self
    }
}

/// Refund details for a payment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundDetails {
    /// Optional refund amount (if different from original payment)
    pub amount: Option<String>,
    /// Refund transaction ID
    pub transaction_id: String,
    /// Reason for the refund
    pub reason: String,
    /// Timestamp when the refund was processed
    pub timestamp: u64,
}

impl RefundDetails {
    /// Creates a new RefundDetails with the given parameters
    pub fn new(transaction_id: String, reason: String, timestamp: u64) -> Self {
        Self {
            amount: None,
            transaction_id,
            reason,
            timestamp,
        }
    }

    /// Sets the refund amount
    pub fn with_amount(mut self, amount: String) -> Self {
        self.amount = Some(amount);
        self
    }
}

/// Bitcoin payment processor
pub struct BitcoinPaymentProcessor {
    /// Minimum confirmations required for a payment to be considered confirmed
    min_confirmations: u32,
    /// Cache of payment details
    payments: HashMap<String, PaymentDetails>,
}

impl BitcoinPaymentProcessor {
    /// Creates a new BitcoinPaymentProcessor
    pub fn new(min_confirmations: u32) -> Self {
        Self {
            min_confirmations,
            payments: HashMap::new(),
        }
    }

    /// Creates a payment request for an order
    pub fn create_payment_request(
        &mut self,
        order: &Order,
        payment_address: String,
        private_key: &SecretKey,
    ) -> Result<PaymentDetails> {
        // Ensure the payment method is Bitcoin
        if order.payment_method != "BTC" {
            return Err(Error::InvalidData(format!(
                "Expected BTC payment method, got {}",
                order.payment_method
            )));
        }

        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        // Create the payment details without a signature first
        let mut payment = PaymentDetails::new(
            order.order_id.clone(),
            PaymentMethod::Bitcoin,
            order.total_amount.clone(),
            payment_address,
            PaymentStatus::Pending,
            timestamp,
            String::new(), // Empty signature for now
        );

        // Serialize the payment details for signing
        let payment_bytes = payment.serialize_for_signing()?;

        // Sign the payment details
        let signature = Crypto::sign(private_key, &payment_bytes)?;

        // Set the signature
        payment.signature = Crypto::encode_base64(&signature);

        // Add the payment to the cache
        self.payments
            .insert(payment.payment_id.clone(), payment.clone());

        Ok(payment)
    }

    /// Verifies a Bitcoin payment
    pub async fn verify_payment(&mut self, payment_id: &str) -> Result<PaymentStatus> {
        // Get the payment details
        let payment = self
            .payments
            .get_mut(payment_id)
            .ok_or_else(|| Error::InvalidData(format!("Payment not found: {}", payment_id)))?;

        // Ensure the payment method is Bitcoin
        if !matches!(payment.method, PaymentMethod::Bitcoin) {
            return Err(Error::InvalidData("Not a Bitcoin payment".into()));
        }

        // Ensure there's a transaction ID
        let tx_id = payment
            .transaction_id
            .as_ref()
            .ok_or_else(|| Error::InvalidData("No transaction ID provided".into()))?;

        // In a real implementation, you would:
        // 1. Connect to a Bitcoin node or API
        // 2. Check the transaction exists and is valid
        // 3. Verify the amount matches
        // 4. Check the number of confirmations

        // For this example, we'll simulate a successful verification
        let confirmations = self.get_bitcoin_confirmations(tx_id).await?;

        let new_status = if confirmations >= self.min_confirmations {
            PaymentStatus::Confirmed
        } else {
            PaymentStatus::Pending
        };

        // Update the payment status
        payment.update_status(new_status.clone(), Utc::now().timestamp() as u64);

        Ok(new_status)
    }

    /// Gets the number of confirmations for a Bitcoin transaction
    async fn get_bitcoin_confirmations(&self, tx_id: &str) -> Result<u32> {
        // In a real implementation, you would:
        // 1. Connect to a Bitcoin node or API
        // 2. Get the transaction details
        // 3. Calculate the number of confirmations

        // For this example, we'll simulate a response
        // In a real implementation, you might use a library like bitcoincore-rpc

        // Simulate a successful response with 6 confirmations
        Ok(6)
    }

    /// Creates a Bitcoin multisig escrow
    pub fn create_multisig_escrow(
        &mut self,
        payment_id: &str,
        buyer_key: &str,
        vendor_key: &str,
        mediator_key: &str,
        private_key: &SecretKey,
    ) -> Result<EscrowDetails> {
        // Get the payment details
        let payment = self
            .payments
            .get_mut(payment_id)
            .ok_or_else(|| Error::InvalidData(format!("Payment not found: {}", payment_id)))?;

        // Ensure the payment method is Bitcoin
        if !matches!(payment.method, PaymentMethod::Bitcoin) {
            return Err(Error::InvalidData("Not a Bitcoin payment".into()));
        }

        // In a real implementation, you would:
        // 1. Create a Bitcoin multisig address (e.g., 2-of-3)
        // 2. Generate the redeem script
        // 3. Return the escrow details

        // For this example, we'll simulate creating a multisig address
        let escrow_address = format!("3MultiSig{}", Uuid::new_v4().to_simple());

        // Create the escrow details
        let escrow = EscrowDetails::new(
            EscrowType::Multisig,
            escrow_address,
            vec![
                buyer_key.to_string(),
                vendor_key.to_string(),
                mediator_key.to_string(),
            ],
            2, // 2-of-3 multisig
            Utc::now().timestamp() as u64,
        );

        // Update the payment with the escrow details
        payment.escrow = Some(escrow.clone());
        payment.update_status(PaymentStatus::InEscrow, Utc::now().timestamp() as u64);

        Ok(escrow)
    }

    /// Releases funds from a Bitcoin multisig escrow
    pub async fn release_from_escrow(
        &mut self,
        payment_id: &str,
        signatures: Vec<String>,
        private_key: &SecretKey,
    ) -> Result<String> {
        // Get the payment details
        let payment = self
            .payments
            .get_mut(payment_id)
            .ok_or_else(|| Error::InvalidData(format!("Payment not found: {}", payment_id)))?;

        // Ensure the payment is in escrow
        let escrow = payment
            .escrow
            .as_mut()
            .ok_or_else(|| Error::InvalidData("Payment is not in escrow".into()))?;

        // Ensure the escrow type is multisig
        if escrow.escrow_type != EscrowType::Multisig {
            return Err(Error::InvalidData("Not a multisig escrow".into()));
        }

        // Ensure there are enough signatures
        if signatures.len() < escrow.required_signatures as usize {
            return Err(Error::InvalidData(format!(
                "Not enough signatures: got {}, need {}",
                signatures.len(),
                escrow.required_signatures
            )));
        }

        // In a real implementation, you would:
        // 1. Verify the signatures
        // 2. Create and broadcast the transaction
        // 3. Return the transaction ID

        // For this example, we'll simulate a successful transaction
        let tx_id = format!("tx_{}", Uuid::new_v4().to_simple());

        // Update the escrow with the release transaction
        escrow.release_transaction_id = Some(tx_id.clone());
        escrow.status = PaymentStatus::EscrowReleased;

        // Update the payment status
        payment.update_status(PaymentStatus::Completed, Utc::now().timestamp() as u64);

        Ok(tx_id)
    }

    /// Processes a refund for a Bitcoin payment
    pub async fn process_refund(
        &mut self,
        payment_id: &str,
        refund_amount: Option<String>,
        reason: String,
        private_key: &SecretKey,
    ) -> Result<RefundDetails> {
        // Get the payment details
        let payment = self
            .payments
            .get_mut(payment_id)
            .ok_or_else(|| Error::InvalidData(format!("Payment not found: {}", payment_id)))?;

        // Ensure the payment method is Bitcoin
        if !matches!(payment.method, PaymentMethod::Bitcoin) {
            return Err(Error::InvalidData("Not a Bitcoin payment".into()));
        }

        // Ensure the payment is confirmed
        if payment.status != PaymentStatus::Confirmed && payment.status != PaymentStatus::Completed
        {
            return Err(Error::InvalidState(format!(
                "Payment must be confirmed or completed to refund, current status: {}",
                payment.status.as_str()
            )));
        }

        // In a real implementation, you would:
        // 1. Create and broadcast a refund transaction
        // 2. Return the refund details

        // For this example, we'll simulate a successful refund
        let tx_id = format!("refund_{}", Uuid::new_v4().to_simple());
        let timestamp = Utc::now().timestamp() as u64;

        // Create the refund details
        let mut refund = RefundDetails::new(tx_id, reason, timestamp);

        // Add the refund amount if provided
        if let Some(amount) = refund_amount {
            refund = refund.with_amount(amount);
        }

        // Update the payment with the refund details
        payment.set_refund(refund.clone(), timestamp);

        Ok(refund)
    }
}

/// USDC payment processor
pub struct USDCPaymentProcessor {
    /// Minimum confirmations required for a payment to be considered confirmed
    min_confirmations: u32,
    /// Cache of payment details
    payments: HashMap<String, PaymentDetails>,
}

impl USDCPaymentProcessor {
    /// Creates a new USDCPaymentProcessor
    pub fn new(min_confirmations: u32) -> Self {
        Self {
            min_confirmations,
            payments: HashMap::new(),
        }
    }

    /// Creates a payment request for an order
    pub fn create_payment_request(
        &mut self,
        order: &Order,
        payment_address: String,
        chain: USDCChain,
        private_key: &SecretKey,
    ) -> Result<PaymentDetails> {
        // Ensure the payment method is USDC
        if !order.payment_method.starts_with("USDC_") {
            return Err(Error::InvalidData(format!(
                "Expected USDC payment method, got {}",
                order.payment_method
            )));
        }

        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        // Create the payment details without a signature first
        let mut payment = PaymentDetails::new(
            order.order_id.clone(),
            PaymentMethod::USDC(chain),
            order.total_amount.clone(),
            payment_address,
            PaymentStatus::Pending,
            timestamp,
            String::new(), // Empty signature for now
        );

        // Serialize the payment details for signing
        let payment_bytes = payment.serialize_for_signing()?;

        // Sign the payment details
        let signature = Crypto::sign(private_key, &payment_bytes)?;

        // Set the signature
        payment.signature = Crypto::encode_base64(&signature);

        // Add the payment to the cache
        self.payments
            .insert(payment.payment_id.clone(), payment.clone());

        Ok(payment)
    }

    /// Verifies a USDC payment
    pub async fn verify_payment(&mut self, payment_id: &str) -> Result<PaymentStatus> {
        // Get the payment details
        let payment = self
            .payments
            .get_mut(payment_id)
            .ok_or_else(|| Error::InvalidData(format!("Payment not found: {}", payment_id)))?;

        // Ensure the payment method is USDC
        if !matches!(payment.method, PaymentMethod::USDC(_)) {
            return Err(Error::InvalidData("Not a USDC payment".into()));
        }

        // Ensure there's a transaction ID
        let tx_id = payment
            .transaction_id
            .as_ref()
            .ok_or_else(|| Error::InvalidData("No transaction ID provided".into()))?;

        // Get the chain from the payment method
        let chain = match &payment.method {
            PaymentMethod::USDC(c) => c,
            _ => unreachable!(),
        };

        // In a real implementation, you would:
        // 1. Connect to the appropriate blockchain API
        // 2. Check the transaction exists and is valid
        // 3. Verify the amount matches
        // 4. Check the number of confirmations

        // For this example, we'll simulate a successful verification
        let confirmations = self.get_usdc_confirmations(tx_id, chain).await?;

        let new_status = if confirmations >= self.min_confirmations {
            PaymentStatus::Confirmed
        } else {
            PaymentStatus::Pending
        };

        // Update the payment status
        payment.update_status(new_status.clone(), Utc::now().timestamp() as u64);

        Ok(new_status)
    }

    /// Gets the number of confirmations for a USDC transaction
    async fn get_usdc_confirmations(&self, tx_id: &str, chain: &USDCChain) -> Result<u32> {
        // In a real implementation, you would:
        // 1. Connect to the appropriate blockchain API
        // 2. Get the transaction details
        // 3. Calculate the number of confirmations

        // For this example, we'll simulate a response
        // In a real implementation, you might use a library like ethers-rs for Ethereum-based chains

        // Simulate different confirmation times based on the chain
        let confirmations = match chain {
            USDCChain::Ethereum => 12,  // Ethereum is slower
            USDCChain::Solana => 32,    // Solana is very fast
            USDCChain::Polygon => 20,   // Polygon is fast
            USDCChain::Arbitrum => 15,  // Arbitrum is fast
            USDCChain::Optimism => 15,  // Optimism is fast
            USDCChain::Base => 15,      // Base is fast
            USDCChain::Avalanche => 18, // Avalanche is fast
        };

        Ok(confirmations)
    }

    /// Creates a smart contract escrow for USDC
    pub async fn create_smart_contract_escrow(
        &mut self,
        payment_id: &str,
        buyer_key: &str,
        vendor_key: &str,
        mediator_key: &str,
        private_key: &SecretKey,
    ) -> Result<EscrowDetails> {
        // Get the payment details
        let payment = self
            .payments
            .get_mut(payment_id)
            .ok_or_else(|| Error::InvalidData(format!("Payment not found: {}", payment_id)))?;

        // Ensure the payment method is USDC
        if !matches!(payment.method, PaymentMethod::USDC(_)) {
            return Err(Error::InvalidData("Not a USDC payment".into()));
        }

        // Get the chain from the payment method
        let chain = match &payment.method {
            PaymentMethod::USDC(c) => c,
            _ => unreachable!(),
        };

        // In a real implementation, you would:
        // 1. Deploy or use an existing escrow smart contract
        // 2. Set up the escrow with the buyer, vendor, and mediator keys
        // 3. Return the escrow details

        // For this example, we'll simulate creating a smart contract escrow
        let escrow_address = format!("0xEscrow{}", Uuid::new_v4().to_simple());

        // Create the escrow details
        let escrow = EscrowDetails::new(
            EscrowType::SmartContract,
            escrow_address,
            vec![
                buyer_key.to_string(),
                vendor_key.to_string(),
                mediator_key.to_string(),
            ],
            2, // 2-of-3 multisig equivalent
            Utc::now().timestamp() as u64,
        );

        // Update the payment with the escrow details
        payment.escrow = Some(escrow.clone());
        payment.update_status(PaymentStatus::InEscrow, Utc::now().timestamp() as u64);

        Ok(escrow)
    }

    /// Releases funds from a USDC smart contract escrow
    pub async fn release_from_escrow(
        &mut self,
        payment_id: &str,
        signatures: Vec<String>,
        private_key: &SecretKey,
    ) -> Result<String> {
        // Get the payment details
        let payment = self
            .payments
            .get_mut(payment_id)
            .ok_or_else(|| Error::InvalidData(format!("Payment not found: {}", payment_id)))?;

        // Ensure the payment is in escrow
        let escrow = payment
            .escrow
            .as_mut()
            .ok_or_else(|| Error::InvalidData("Payment is not in escrow".into()))?;

        // Ensure the escrow type is smart contract
        if escrow.escrow_type != EscrowType::SmartContract {
            return Err(Error::InvalidData("Not a smart contract escrow".into()));
        }

        // Ensure there are enough signatures
        if signatures.len() < escrow.required_signatures as usize {
            return Err(Error::InvalidData(format!(
                "Not enough signatures: got {}, need {}",
                signatures.len(),
                escrow.required_signatures
            )));
        }

        // In a real implementation, you would:
        // 1. Connect to the appropriate blockchain
        // 2. Call the smart contract's release function with the signatures
        // 3. Return the transaction ID

        // For this example, we'll simulate a successful transaction
        let tx_id = format!("0x{}", Uuid::new_v4().to_simple());

        // Update the escrow with the release transaction
        escrow.release_transaction_id = Some(tx_id.clone());
        escrow.status = PaymentStatus::EscrowReleased;

        // Update the payment status
        payment.update_status(PaymentStatus::Completed, Utc::now().timestamp() as u64);

        Ok(tx_id)
    }

    /// Processes a refund for a USDC payment
    pub async fn process_refund(
        &mut self,
        payment_id: &str,
        refund_amount: Option<String>,
        reason: String,
        private_key: &SecretKey,
    ) -> Result<RefundDetails> {
        // Get the payment details
        let payment = self
            .payments
            .get_mut(payment_id)
            .ok_or_else(|| Error::InvalidData(format!("Payment not found: {}", payment_id)))?;

        // Ensure the payment method is USDC
        if !matches!(payment.method, PaymentMethod::USDC(_)) {
            return Err(Error::InvalidData("Not a USDC payment".into()));
        }

        // Ensure the payment is confirmed
        if payment.status != PaymentStatus::Confirmed && payment.status != PaymentStatus::Completed
        {
            return Err(Error::InvalidState(format!(
                "Payment must be confirmed or completed to refund, current status: {}",
                payment.status.as_str()
            )));
        }

        // In a real implementation, you would:
        // 1. Create and send a USDC transfer transaction
        // 2. Return the refund details

        // For this example, we'll simulate a successful refund
        let tx_id = format!("0x{}", Uuid::new_v4().to_simple());
        let timestamp = Utc::now().timestamp() as u64;

        // Create the refund details
        let mut refund = RefundDetails::new(tx_id, reason, timestamp);

        // Add the refund amount if provided
        if let Some(amount) = refund_amount {
            refund = refund.with_amount(amount);
        }

        // Update the payment with the refund details
        payment.set_refund(refund.clone(), timestamp);

        Ok(refund)
    }
}

/// Payment manager for handling payments in the P2P order protocol
pub struct PaymentManager {
    /// Bitcoin payment processor
    bitcoin_processor: BitcoinPaymentProcessor,
    /// USDC payment processor
    usdc_processor: USDCPaymentProcessor,
    /// Private key for signing payment messages
    private_key: Option<SecretKey>,
    /// Public key
    public_key: Option<PublicKey>,
}

impl PaymentManager {
    /// Creates a new PaymentManager
    pub fn new() -> Self {
        Self {
            bitcoin_processor: BitcoinPaymentProcessor::new(3), // 3 confirmations for Bitcoin
            usdc_processor: USDCPaymentProcessor::new(1),       // 1 confirmation for USDC
            private_key: None,
            public_key: None,
        }
    }

    /// Sets the keys for signing payment messages
    pub fn set_keys(&mut self, private_key: SecretKey, public_key: PublicKey) {
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
    }

    /// Creates a payment request for an order
    pub fn create_payment_request(
        &mut self,
        order: &Order,
        payment_address: String,
    ) -> Result<PaymentDetails> {
        // Ensure the private key is set
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| Error::Authentication("Private key not set".into()))?;

        // Determine the payment method
        if order.payment_method == "BTC" {
            self.bitcoin_processor
                .create_payment_request(order, payment_address, private_key)
        } else if order.payment_method.starts_with("USDC_") {
            let chain_str = order.payment_method.strip_prefix("USDC_").ok_or_else(|| {
                Error::InvalidData(format!(
                    "Invalid USDC payment method: {}",
                    order.payment_method
                ))
            })?;

            let chain = USDCChain::from_str(chain_str)
                .ok_or_else(|| Error::InvalidData(format!("Invalid USDC chain: {}", chain_str)))?;

            self.usdc_processor
                .create_payment_request(order, payment_address, chain, private_key)
        } else {
            Err(Error::InvalidData(format!(
                "Unsupported payment method: {}",
                order.payment_method
            )))
        }
    }

    /// Verifies a payment
    pub async fn verify_payment(
        &mut self,
        payment_id: &str,
        payment_method: &PaymentMethod,
    ) -> Result<PaymentStatus> {
        match payment_method {
            PaymentMethod::Bitcoin => self.bitcoin_processor.verify_payment(payment_id).await,
            PaymentMethod::USDC(_) => self.usdc_processor.verify_payment(payment_id).await,
            PaymentMethod::OtherCrypto(_) => {
                Err(Error::InvalidData("Unsupported payment method".into()))
            }
        }
    }

    /// Creates an escrow for a payment
    pub async fn create_escrow(
        &mut self,
        payment_id: &str,
        payment_method: &PaymentMethod,
        buyer_key: &str,
        vendor_key: &str,
        mediator_key: &str,
    ) -> Result<EscrowDetails> {
        // Ensure the private key is set
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| Error::Authentication("Private key not set".into()))?;

        match payment_method {
            PaymentMethod::Bitcoin => self.bitcoin_processor.create_multisig_escrow(
                payment_id,
                buyer_key,
                vendor_key,
                mediator_key,
                private_key,
            ),
            PaymentMethod::USDC(_) => {
                self.usdc_processor
                    .create_smart_contract_escrow(
                        payment_id,
                        buyer_key,
                        vendor_key,
                        mediator_key,
                        private_key,
                    )
                    .await
            }
            PaymentMethod::OtherCrypto(_) => Err(Error::InvalidData(
                "Unsupported payment method for escrow".into(),
            )),
        }
    }

    /// Releases funds from an escrow
    pub async fn release_from_escrow(
        &mut self,
        payment_id: &str,
        payment_method: &PaymentMethod,
        signatures: Vec<String>,
    ) -> Result<String> {
        // Ensure the private key is set
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| Error::Authentication("Private key not set".into()))?;

        match payment_method {
            PaymentMethod::Bitcoin => {
                self.bitcoin_processor
                    .release_from_escrow(payment_id, signatures, private_key)
                    .await
            }
            PaymentMethod::USDC(_) => {
                self.usdc_processor
                    .release_from_escrow(payment_id, signatures, private_key)
                    .await
            }
            PaymentMethod::OtherCrypto(_) => Err(Error::InvalidData(
                "Unsupported payment method for escrow".into(),
            )),
        }
    }

    /// Processes a refund
    pub async fn process_refund(
        &mut self,
        payment_id: &str,
        payment_method: &PaymentMethod,
        refund_amount: Option<String>,
        reason: String,
    ) -> Result<RefundDetails> {
        // Ensure the private key is set
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| Error::Authentication("Private key not set".into()))?;

        match payment_method {
            PaymentMethod::Bitcoin => {
                self.bitcoin_processor
                    .process_refund(payment_id, refund_amount, reason, private_key)
                    .await
            }
            PaymentMethod::USDC(_) => {
                self.usdc_processor
                    .process_refund(payment_id, refund_amount, reason, private_key)
                    .await
            }
            PaymentMethod::OtherCrypto(_) => Err(Error::InvalidData(
                "Unsupported payment method for refund".into(),
            )),
        }
    }

    /// Creates a payment message for the order state machine
    pub fn create_payment_message(
        &self,
        payment: &PaymentDetails,
        message_type: &str,
    ) -> Result<Message> {
        // Ensure the private key is set
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| Error::Authentication("Private key not set".into()))?;

        // Get the current timestamp
        let timestamp = Utc::now().timestamp() as u64;

        // Create the payload with payment details
        let payload = json!({
            "payment_id": payment.payment_id,
            "method": payment.method.as_str(),
            "amount": payment.amount,
            "status": payment.status.as_str(),
            "transaction_id": payment.transaction_id,
        });

        // Create the message without a signature first
        let mut message = Message::new(
            message_type.to_string(),
            payment.order_id.clone(),
            timestamp,
            String::new(), // Empty signature for now
        )
        .with_status(payment.status.as_str().to_string())
        .with_payload(payload);

        // Serialize the message for signing
        let message_bytes = message.serialize_for_signing()?;

        // Sign the message
        let signature = Crypto::sign(private_key, &message_bytes)?;

        // Set the signature
        message.signature = Crypto::encode_base64(&signature);

        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::Crypto;
    use crate::models::{Location, OrderItem};

    // Helper function to create a test order
    fn create_test_order(
        order_id: &str,
        buyer_key: &str,
        vendor_key: &str,
        payment_method: &str,
        amount: &str,
    ) -> Order {
        Order {
            order_id: order_id.to_string(),
            buyer_public_key: buyer_key.to_string(),
            vendor_public_key: vendor_key.to_string(),
            order_items: vec![OrderItem::new("item-123".to_string(), 2)],
            total_amount: amount.to_string(),
            buyer_location: Some(Location::new(40.7128, -74.0060)),
            created_timestamp: Utc::now().timestamp() as u64,
            current_state: "created".to_string(),
            payment_method: payment_method.to_string(),
            payment_details: "payment_details_123".to_string(),
            signature: "signature_123".to_string(),
        }
    }

    #[tokio::test]
    async fn test_bitcoin_payment_flow() {
        // Create keypairs for testing
        let buyer_keypair = Crypto::generate_identity_keypair().unwrap();
        let vendor_keypair = Crypto::generate_identity_keypair().unwrap();

        let buyer_public_key = Crypto::encode_base64(&buyer_keypair.public_key.serialize());
        let vendor_public_key = Crypto::encode_base64(&vendor_keypair.public_key.serialize());

        // Create a test order
        let order = create_test_order(
            "order-123",
            &buyer_public_key,
            &vendor_public_key,
            "BTC",
            "0.001",
        );

        // Create a payment manager
        let mut payment_manager = PaymentManager::new();
        payment_manager.set_keys(buyer_keypair.private_key, buyer_keypair.public_key);

        // Create a payment request
        let payment = payment_manager
            .create_payment_request(
                &order,
                "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh".to_string(),
            )
            .unwrap();

        assert_eq!(payment.method.as_str(), "BTC");
        assert_eq!(payment.amount, "0.001");
        assert_eq!(payment.status, PaymentStatus::Pending);

        // Simulate setting a transaction ID
        let bitcoin_processor = &mut payment_manager.bitcoin_processor;
        let mut payment_details = bitcoin_processor
            .payments
            .get_mut(&payment.payment_id)
            .unwrap();
        payment_details.transaction_id = Some("txid_123".to_string());

        // Verify the payment
        let status = payment_manager
            .verify_payment(&payment.payment_id, &PaymentMethod::Bitcoin)
            .await
            .unwrap();

        assert_eq!(status, PaymentStatus::Confirmed);

        // Create a payment message
        let message = payment_manager
            .create_payment_message(&payment_details, "payment_confirmation")
            .unwrap();

        assert_eq!(message.message_type, "payment_confirmation");
        assert!(message.payload.is_some());
    }

    #[tokio::test]
    async fn test_usdc_payment_flow() {
        // Create keypairs for testing
        let buyer_keypair = Crypto::generate_identity_keypair().unwrap();
        let vendor_keypair = Crypto::generate_identity_keypair().unwrap();

        let buyer_public_key = Crypto::encode_base64(&buyer_keypair.public_key.serialize());
        let vendor_public_key = Crypto::encode_base64(&vendor_keypair.public_key.serialize());

        // Create a test order
        let order = create_test_order(
            "order-456",
            &buyer_public_key,
            &vendor_public_key,
            "USDC_ETH",
            "100.00",
        );

        // Create a payment manager
        let mut payment_manager = PaymentManager::new();
        payment_manager.set_keys(vendor_keypair.private_key, vendor_keypair.public_key);

        // Create a payment request
        let payment = payment_manager
            .create_payment_request(
                &order,
                "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".to_string(),
            )
            .unwrap();

        assert!(matches!(
            payment.method,
            PaymentMethod::USDC(USDCChain::Ethereum)
        ));
        assert_eq!(payment.amount, "100.00");
        assert_eq!(payment.status, PaymentStatus::Pending);

        // Simulate setting a transaction ID
        let usdc_processor = &mut payment_manager.usdc_processor;
        let mut payment_details = usdc_processor
            .payments
            .get_mut(&payment.payment_id)
            .unwrap();
        payment_details.transaction_id = Some("0xabcdef123456".to_string());

        // Verify the payment
        let status = payment_manager
            .verify_payment(
                &payment.payment_id,
                &PaymentMethod::USDC(USDCChain::Ethereum),
            )
            .await
            .unwrap();

        assert_eq!(status, PaymentStatus::Confirmed);
    }
}
