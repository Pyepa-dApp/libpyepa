//! Example usage of the SDK for a Buyer

use libpyepa::{
    api::buyer::BuyerApi,
    core::crypto::Crypto,
    models::{Item, Location, OrderItem, VendorListing},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize a new buyer with generated keys
    let buyer_api = BuyerApi::new_with_generated_keys()?;
    println!("Buyer initialized with new keys");

    // Create a sample vendor listing (in a real scenario, this would be retrieved from the DHT)
    let vendor_keypair = Crypto::generate_identity_keypair()?;
    let vendor_public_key = Crypto::encode_base64(&vendor_keypair.public_key.serialize());

    let item = Item::new("item-123".to_string(), "Test Item".to_string())
        .with_description("A test item".to_string())
        .with_price("10.99".to_string())
        .with_availability("In Stock".to_string())
        .with_tags(vec!["test".to_string(), "example".to_string()]);

    let vendor_location = Location::new(40.7128, -74.0060); // New York City

    // Create a sample vendor listing
    let mut vendor_listing = VendorListing::new(
        vendor_public_key,
        vec![item.clone()],
        vec!["BTC".to_string(), "ETH".to_string()],
        chrono::Utc::now().timestamp() as u64,
        "dummy_signature".to_string(), // In a real scenario, this would be properly signed
    )
    .with_vendor_name("Test Vendor".to_string())
    .with_location(vendor_location)
    .with_service_terms("Terms and conditions apply".to_string());

    // In a real scenario, the vendor would sign the listing
    let listing_bytes = vendor_listing.serialize_for_signing()?;
    let signature = Crypto::sign(&vendor_keypair.private_key, &listing_bytes)?;
    vendor_listing.signature = Crypto::encode_base64(&signature);

    println!(
        "Found vendor: {}",
        vendor_listing.vendor_name.as_ref().unwrap()
    );

    // Create an order for the vendor
    let order_items = vec![OrderItem::new("item-123".to_string(), 2)];
    let buyer_location = Location::new(34.0522, -118.2437); // Los Angeles

    let order = buyer_api.create_order(
        &vendor_listing,
        order_items,
        "21.98".to_string(), // 2 * 10.99
        "BTC".to_string(),
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(), // Example Bitcoin address
        Some(buyer_location),
    )?;

    println!("Created order with ID: {}", order.order_id);
    println!("Order total: {}", order.total_amount);
    println!("Order state: {}", order.current_state);

    // In a real scenario, the order would be sent to the vendor
    // and the buyer would wait for a response

    println!("Order sent to vendor. Waiting for response...");

    // Simulate receiving an acceptance message from the vendor
    // (In a real scenario, this would be received over the network)

    println!("Order accepted by vendor!");

    // Simulate receiving a dispatch notification
    println!("Order dispatched by vendor!");

    // Simulate receiving a delivery notification
    println!("Order delivered!");

    // Accept the delivery
    let acceptance_message = buyer_api.accept_delivery(&order)?;
    println!("Delivery accepted: {}", acceptance_message.message_type);

    Ok(())
}
