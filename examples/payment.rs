//! Example usage of the payment system with Bitcoin and USDC

use chrono::Utc;
use my_p2p_order_sdk::{
    core::{
        crypto::Crypto,
        payment::{EscrowType, PaymentManager, PaymentMethod, PaymentStatus, USDCChain},
    },
    models::{Location, Order, OrderItem},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Initializing payment system example...");

    // Generate keys for the parties
    let buyer_keypair = Crypto::generate_identity_keypair()?;
    let vendor_keypair = Crypto::generate_identity_keypair()?;
    let mediator_keypair = Crypto::generate_identity_keypair()?;

    let buyer_public_key = Crypto::encode_base64(&buyer_keypair.public_key.serialize());
    let vendor_public_key = Crypto::encode_base64(&vendor_keypair.public_key.serialize());
    let mediator_public_key = Crypto::encode_base64(&mediator_keypair.public_key.serialize());

    println!("Generated keys for all parties");

    // Create payment manager for the buyer
    let mut buyer_payment_manager = PaymentManager::new();
    buyer_payment_manager.set_keys(buyer_keypair.private_key, buyer_keypair.public_key);

    // Create payment manager for the vendor
    let mut vendor_payment_manager = PaymentManager::new();
    vendor_payment_manager.set_keys(vendor_keypair.private_key, vendor_keypair.public_key);

    println!("Initialized payment managers for buyer and vendor");

    // Example 1: Bitcoin Payment
    println!("\n=== Bitcoin Payment Example ===");

    // Create a test order for Bitcoin
    let btc_order = create_test_order(
        "order-btc-123",
        &buyer_public_key,
        &vendor_public_key,
        "BTC",
        "0.001", // 0.001 BTC
    );

    println!("Created Bitcoin order with ID: {}", btc_order.order_id);

    // Vendor creates a payment request
    println!("Vendor creates payment request...");
    let btc_payment = vendor_payment_manager.create_payment_request(
        &btc_order,
        "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh".to_string(), // Example Bitcoin address
    )?;

    println!(
        "Payment request created with ID: {}",
        btc_payment.payment_id
    );
    println!("Bitcoin payment address: {}", btc_payment.payment_address);
    println!("Amount: {} BTC", btc_payment.amount);

    // Buyer simulates making the payment
    println!("\nBuyer makes the Bitcoin payment...");

    // In a real implementation, the buyer would:
    // 1. Create a Bitcoin transaction
    // 2. Broadcast it to the network
    // 3. Get the transaction ID

    // Simulate setting the transaction ID
    let btc_processor = &mut vendor_payment_manager.bitcoin_processor;
    let mut btc_payment_details = btc_processor
        .payments
        .get_mut(&btc_payment.payment_id)
        .unwrap();
    btc_payment_details.transaction_id = Some("txid_123456789".to_string());

    println!(
        "Payment sent with transaction ID: {}",
        btc_payment_details.transaction_id.as_ref().unwrap()
    );

    // Vendor verifies the payment
    println!("\nVendor verifies the Bitcoin payment...");
    let btc_status = vendor_payment_manager
        .verify_payment(&btc_payment.payment_id, &PaymentMethod::Bitcoin)
        .await?;

    println!("Payment status: {}", btc_status.as_str());

    // Create a payment confirmation message
    let btc_message = vendor_payment_manager
        .create_payment_message(&btc_payment_details, "payment_confirmation")?;

    println!("Payment confirmation message created");
    println!("Message type: {}", btc_message.message_type);
    println!("Message status: {}", btc_message.status.as_ref().unwrap());

    // Example 2: USDC Payment with Escrow
    println!("\n=== USDC Payment with Escrow Example ===");

    // Create a test order for USDC
    let usdc_order = create_test_order(
        "order-usdc-456",
        &buyer_public_key,
        &vendor_public_key,
        "USDC_ETH", // USDC on Ethereum
        "100.00",   // 100 USDC
    );

    println!("Created USDC order with ID: {}", usdc_order.order_id);

    // Vendor creates a payment request
    println!("Vendor creates payment request...");
    let usdc_payment = vendor_payment_manager.create_payment_request(
        &usdc_order,
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".to_string(), // Example Ethereum address
    )?;

    println!(
        "Payment request created with ID: {}",
        usdc_payment.payment_id
    );
    println!("USDC payment address: {}", usdc_payment.payment_address);
    println!("Amount: {} USDC", usdc_payment.amount);

    // Buyer suggests using an escrow
    println!("\nBuyer suggests using an escrow for the USDC payment...");

    // Create an escrow
    let escrow = vendor_payment_manager
        .create_escrow(
            &usdc_payment.payment_id,
            &PaymentMethod::USDC(USDCChain::Ethereum),
            &buyer_public_key,
            &vendor_public_key,
            &mediator_public_key,
        )
        .await?;

    println!("Escrow created with address: {}", escrow.escrow_address);
    println!("Escrow type: {}", escrow.escrow_type.as_str());
    println!("Required signatures: {}", escrow.required_signatures);

    // Buyer simulates making the payment to the escrow
    println!("\nBuyer makes the USDC payment to the escrow...");

    // In a real implementation, the buyer would:
    // 1. Create a USDC transaction to the escrow address
    // 2. Submit it to the Ethereum network
    // 3. Get the transaction ID

    // Simulate setting the transaction ID
    let usdc_processor = &mut vendor_payment_manager.usdc_processor;
    let mut usdc_payment_details = usdc_processor
        .payments
        .get_mut(&usdc_payment.payment_id)
        .unwrap();
    usdc_payment_details.transaction_id = Some("0xabcdef123456789".to_string());

    println!(
        "Payment sent to escrow with transaction ID: {}",
        usdc_payment_details.transaction_id.as_ref().unwrap()
    );

    // Vendor verifies the payment
    println!("\nVendor verifies the USDC payment...");
    let usdc_status = vendor_payment_manager
        .verify_payment(
            &usdc_payment.payment_id,
            &PaymentMethod::USDC(USDCChain::Ethereum),
        )
        .await?;

    println!("Payment status: {}", usdc_status.as_str());

    // After order fulfillment, release from escrow
    println!("\nOrder fulfilled, releasing funds from escrow...");

    // In a real implementation, both buyer and vendor would sign
    let signatures = vec![
        "buyer_signature".to_string(),
        "vendor_signature".to_string(),
    ];

    let release_tx = vendor_payment_manager
        .release_from_escrow(
            &usdc_payment.payment_id,
            &PaymentMethod::USDC(USDCChain::Ethereum),
            signatures,
        )
        .await?;

    println!(
        "Funds released from escrow with transaction ID: {}",
        release_tx
    );
    println!("Payment status: {}", usdc_payment_details.status.as_str());

    // Example 3: Refund Process
    println!("\n=== Refund Process Example ===");

    // Create another test order for Bitcoin
    let refund_order = create_test_order(
        "order-refund-789",
        &buyer_public_key,
        &vendor_public_key,
        "BTC",
        "0.002", // 0.002 BTC
    );

    println!(
        "Created order for refund example with ID: {}",
        refund_order.order_id
    );

    // Vendor creates a payment request
    println!("Vendor creates payment request...");
    let refund_payment = vendor_payment_manager.create_payment_request(
        &refund_order,
        "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh".to_string(),
    )?;

    // Simulate payment and confirmation
    let btc_processor = &mut vendor_payment_manager.bitcoin_processor;
    let mut refund_payment_details = btc_processor
        .payments
        .get_mut(&refund_payment.payment_id)
        .unwrap();
    refund_payment_details.transaction_id = Some("txid_refund_test".to_string());
    refund_payment_details.status = PaymentStatus::Confirmed;

    println!(
        "Payment confirmed with transaction ID: {}",
        refund_payment_details.transaction_id.as_ref().unwrap()
    );

    // Process a partial refund
    println!("\nProcessing a partial refund...");
    let refund = vendor_payment_manager
        .process_refund(
            &refund_payment.payment_id,
            &PaymentMethod::Bitcoin,
            Some("0.001".to_string()), // Refund half the amount
            "Item partially damaged".to_string(),
        )
        .await?;

    println!(
        "Refund processed with transaction ID: {}",
        refund.transaction_id
    );
    println!("Refund amount: {} BTC", refund.amount.as_ref().unwrap());
    println!("Refund reason: {}", refund.reason);
    println!("Payment status: {}", refund_payment_details.status.as_str());

    println!("\nPayment system examples completed successfully");

    Ok(())
}

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
