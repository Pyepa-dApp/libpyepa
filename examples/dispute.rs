//! Example usage of the dispute resolution framework

use chrono::Utc;
use libpyepa::{
    core::{
        crypto::Crypto,
        dispute::{DisputeClient, DisputeParty, DisputeState, EvidenceType},
    },
    models::{Location, Order, OrderItem},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Initializing dispute resolution example...");

    // Generate keys for the parties
    let buyer_keypair = Crypto::generate_identity_keypair()?;
    let vendor_keypair = Crypto::generate_identity_keypair()?;
    let mediator_keypair = Crypto::generate_identity_keypair()?;

    let buyer_public_key = Crypto::encode_base64(&buyer_keypair.public_key.serialize());
    let vendor_public_key = Crypto::encode_base64(&vendor_keypair.public_key.serialize());
    let mediator_public_key = Crypto::encode_base64(&mediator_keypair.public_key.serialize());

    println!("Generated keys for all parties");

    // Create dispute clients for each party
    let mut buyer_client = DisputeClient::new(DisputeParty::Buyer);
    let mut vendor_client = DisputeClient::new(DisputeParty::Vendor);
    let mut mediator_client = DisputeClient::new(DisputeParty::Mediator);

    buyer_client.set_keys(buyer_keypair.private_key, buyer_keypair.public_key);
    vendor_client.set_keys(vendor_keypair.private_key, vendor_keypair.public_key);
    mediator_client.set_keys(mediator_keypair.private_key, mediator_keypair.public_key);

    println!("Initialized dispute clients for buyer, vendor, and mediator");

    // Create a test order
    let order = create_test_order(
        "order-123",
        &buyer_public_key,
        &vendor_public_key,
        "delivered",
    );

    println!("Created test order with ID: {}", order.order_id);

    // Buyer initiates a dispute
    println!("\n--- Buyer initiates dispute ---");
    let (dispute, message) = buyer_client.initiate_dispute(
        &order,
        "Item received was damaged during shipping".to_string(),
    )?;

    println!("Dispute initiated with ID: {}", dispute.id);
    println!("Reason: {}", dispute.reason);
    println!("State: {}", dispute.state.as_str());

    // Vendor receives and processes the dispute message
    println!("\n--- Vendor processes dispute ---");
    let processed_dispute = vendor_client
        .process_dispute_message(&message, &order)?
        .unwrap();

    println!("Vendor received dispute with ID: {}", processed_dispute.id);
    println!(
        "Vendor's view of dispute state: {}",
        processed_dispute.state.as_str()
    );

    // Vendor submits evidence
    println!("\n--- Vendor submits evidence ---");
    let (evidence, evidence_message) = vendor_client.submit_evidence(
        &dispute.id,
        EvidenceType::Text("The item was properly packaged with bubble wrap and insured for the full value. The shipping carrier confirmed acceptance in good condition.".to_string()),
        "Shipping confirmation and packaging details".to_string(),
    )?;

    println!("Evidence submitted with ID: {}", evidence.id);
    println!("Evidence description: {}", evidence.description);

    // Buyer receives and processes the evidence message
    println!("\n--- Buyer processes evidence ---");
    let updated_dispute = buyer_client
        .process_dispute_message(&evidence_message, &order)?
        .unwrap();

    println!(
        "Buyer received evidence for dispute: {}",
        updated_dispute.id
    );
    println!("Updated dispute state: {}", updated_dispute.state.as_str());
    println!(
        "Number of evidence items: {}",
        updated_dispute.evidence.len()
    );

    // Buyer submits counter-evidence
    println!("\n--- Buyer submits counter-evidence ---");
    let (counter_evidence, counter_evidence_message) = buyer_client.submit_evidence(
        &dispute.id,
        EvidenceType::Text("The package arrived with visible damage to the outer box. Photos show the item was broken inside. The delivery receipt notes 'package damaged'.".to_string()),
        "Photos of damaged package and item".to_string(),
    )?;

    println!(
        "Counter-evidence submitted with ID: {}",
        counter_evidence.id
    );

    // Vendor processes the counter-evidence
    println!("\n--- Vendor processes counter-evidence ---");
    let updated_dispute = vendor_client
        .process_dispute_message(&counter_evidence_message, &order)?
        .unwrap();

    println!("Vendor received counter-evidence");
    println!(
        "Number of evidence items now: {}",
        updated_dispute.evidence.len()
    );

    // Buyer and vendor agree to use a mediator
    println!("\n--- Assigning a mediator ---");
    buyer_client.assign_mediator(&dispute.id, mediator_public_key.clone())?;

    println!("Mediator assigned to dispute");

    // Mediator reviews the case
    println!("\n--- Mediator reviews the case ---");
    let mediator_disputes = mediator_client.get_all_disputes();

    for d in mediator_disputes {
        println!("Mediator can see dispute: {}", d.id);
        println!("  Reason: {}", d.reason);
        println!("  State: {}", d.state.as_str());
        println!("  Evidence count: {}", d.evidence.len());
    }

    // Mediator resolves the dispute
    println!("\n--- Mediator resolves the dispute ---");
    let (resolution, resolution_message) = mediator_client.resolve_dispute(
        &dispute.id,
        DisputeState::ResolvedWithCompromise,
        "Based on the evidence, the damage likely occurred during shipping. Since the vendor properly packaged the item but the buyer received damaged goods, a 50% refund is recommended. The vendor should file an insurance claim for the remaining amount.".to_string(),
    )?;

    println!(
        "Dispute resolved with outcome: {}",
        resolution.outcome.as_str()
    );
    println!("Resolution details: {}", resolution.description);

    // Both parties receive the resolution
    println!("\n--- Parties receive the resolution ---");
    let buyer_final_dispute = buyer_client
        .process_dispute_message(&resolution_message, &order)?
        .unwrap();

    println!(
        "Buyer received resolution. Final state: {}",
        buyer_final_dispute.state.as_str()
    );

    // In a real application, the order state would be updated based on the dispute resolution
    println!("\n--- Updating order based on resolution ---");
    println!(
        "Order state would change from '{}' to 'disputed_resolved'",
        order.current_state
    );

    println!("\nDispute resolution process completed successfully");

    Ok(())
}

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
