//! Example usage of the SDK for a Vendor

use libpyepa::{
    api::vendor::VendorApi,
    core::crypto::Crypto,
    models::{Item, Location, Order, OrderItem},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize a new vendor with generated keys
    let vendor_api = VendorApi::new_with_generated_keys()?;
    println!("Vendor initialized with new keys");

    // Create some items to offer
    let item1 = Item::new("item-123".to_string(), "Test Item 1".to_string())
        .with_description("A test item".to_string())
        .with_price("10.99".to_string())
        .with_availability("In Stock".to_string())
        .with_tags(vec!["test".to_string(), "example".to_string()]);

    let item2 = Item::new("item-456".to_string(), "Test Item 2".to_string())
        .with_description("Another test item".to_string())
        .with_price("15.99".to_string())
        .with_availability("In Stock".to_string())
        .with_tags(vec!["test".to_string(), "premium".to_string()]);

    let vendor_location = Location::new(40.7128, -74.0060); // New York City

    // Create a vendor listing
    let listing = vendor_api.create_listing(
        vec![item1.clone(), item2.clone()],
        vec!["BTC".to_string(), "ETH".to_string()],
        Some("Test Vendor".to_string()),
        Some(vendor_location),
        Some("Terms and conditions apply".to_string()),
    )?;

    println!(
        "Created vendor listing with {} items",
        listing.items_offered.len()
    );

    // In a real scenario, the listing would be published to the DHT
    println!("Publishing listing to DHT...");

    // Simulate receiving an order from a buyer
    // (In a real scenario, this would be received over the network)
    let buyer_keypair = Crypto::generate_identity_keypair()?;
    let buyer_public_key = Crypto::encode_base64(&buyer_keypair.public_key.serialize());
    let vendor_public_key = Crypto::encode_base64(&vendor_api.public_key.serialize());

    let order_items = vec![OrderItem::new("item-123".to_string(), 2)];
    let buyer_location = Location::new(34.0522, -118.2437); // Los Angeles

    // Create a sample order (in a real scenario, this would come from the buyer)
    let mut order = Order::new(
        "order-123".to_string(),
        buyer_public_key,
        vendor_public_key,
        order_items,
        "21.98".to_string(), // 2 * 10.99
        chrono::Utc::now().timestamp() as u64,
        "BTC".to_string(),
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(), // Example Bitcoin address
        "dummy_signature".to_string(), // In a real scenario, this would be properly signed by the buyer
    )
    .with_buyer_location(buyer_location);

    // In a real scenario, the buyer would sign the order
    let order_bytes = order.serialize_for_signing()?;
    let signature = Crypto::sign(&buyer_keypair.private_key, &order_bytes)?;
    order.signature = Crypto::encode_base64(&signature);

    println!("Received order with ID: {}", order.order_id);
    println!("Order total: {}", order.total_amount);
    println!("Order state: {}", order.current_state);

    // Accept the order
    let acceptance_message = vendor_api.accept_order(&order)?;
    println!("Order accepted: {}", acceptance_message.message_type);

    // Update the order state based on the acceptance message
    let mut order_copy = order.clone();
    vendor_api.process_message(&mut order_copy, &acceptance_message)?;
    println!("Updated order state: {}", order_copy.current_state);

    // Dispatch the order
    let dispatch_message =
        vendor_api.dispatch_order(&order_copy, Some("Tracking number: 123456789".to_string()))?;
    println!("Order dispatched: {}", dispatch_message.message_type);

    // Update the order state based on the dispatch message
    vendor_api.process_message(&mut order_copy, &dispatch_message)?;
    println!("Updated order state: {}", order_copy.current_state);

    // Mark the order as delivered
    let delivery_message = vendor_api.mark_as_delivered(&order_copy)?;
    println!("Order delivered: {}", delivery_message.message_type);

    // Update the order state based on the delivery message
    vendor_api.process_message(&mut order_copy, &delivery_message)?;
    println!("Updated order state: {}", order_copy.current_state);

    // Simulate receiving a delivery acceptance message from the buyer
    println!("Buyer accepted delivery!");

    Ok(())
}
