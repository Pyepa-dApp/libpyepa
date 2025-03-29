//! Example usage of the DHT for vendor discovery and listing publication

use libpyepa::{
    core::dht::DhtClient,
    models::{Item, Location, VendorListing},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Bootstrap nodes for the DHT
    // In a real application, you would use actual bootstrap nodes
    // For testing, you can use public IPFS bootstrap nodes
    let bootstrap_addresses = vec![
        "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ"
            .to_string(),
        "/ip4/104.236.179.241/tcp/4001/p2p/QmSoLPppuBtQSGwKDZT2M73ULpjvfd3aZ6ha4oFGL1KrGM"
            .to_string(),
        "/ip4/128.199.219.111/tcp/4001/p2p/QmSoLSafTMBsPKadTEgaXctDQVcqN88CNLHXMkTNwMKPnu"
            .to_string(),
    ];

    println!("Initializing DHT client...");
    let dht_client = DhtClient::new(bootstrap_addresses).await?;
    println!("DHT client initialized");

    // Create some items to offer
    let item1 = Item::new("item-123".to_string(), "Organic Apples".to_string())
        .with_description("Fresh organic apples from local farms".to_string())
        .with_price("5.99".to_string())
        .with_availability("In Stock".to_string())
        .with_tags(vec![
            "organic".to_string(),
            "fruit".to_string(),
            "local".to_string(),
        ]);

    let item2 = Item::new("item-456".to_string(), "Artisanal Bread".to_string())
        .with_description("Freshly baked sourdough bread".to_string())
        .with_price("7.99".to_string())
        .with_availability("Limited Stock".to_string())
        .with_tags(vec![
            "bakery".to_string(),
            "artisanal".to_string(),
            "local".to_string(),
        ]);

    // Create a vendor location (San Francisco)
    let vendor_location = Location::new(37.7749, -122.4194);

    // Create a vendor listing
    let listing = VendorListing::new(
        "vendor_public_key_123".to_string(),
        vec![item1, item2],
        vec!["BTC".to_string(), "ETH".to_string()],
        chrono::Utc::now().timestamp() as u64,
        "signature_123".to_string(),
    )
    .with_vendor_name("Farm to Table Market".to_string())
    .with_location(vendor_location)
    .with_service_terms(
        "Delivery available within 10 miles. Returns accepted within 24 hours.".to_string(),
    );

    println!("Publishing vendor listing to DHT...");
    dht_client.publish_listing(listing).await?;
    println!("Vendor listing published successfully");

    // Search for vendors by tags
    println!("Searching for vendors with 'organic' tag...");
    let organic_vendors = dht_client
        .search_by_tags(vec!["organic".to_string()])
        .await?;
    println!("Found {} vendors with 'organic' tag", organic_vendors.len());

    for vendor in &organic_vendors {
        println!(
            "- {}",
            vendor
                .vendor_name
                .as_ref()
                .unwrap_or(&"Unknown".to_string())
        );
    }

    // Search for vendors by location
    println!("Searching for vendors near San Francisco...");
    let nearby_vendors = dht_client
        .search_by_location(37.7749, -122.4194, 20.0)
        .await?;
    println!(
        "Found {} vendors within 20km of San Francisco",
        nearby_vendors.len()
    );

    for vendor in &nearby_vendors {
        if let Some(location) = &vendor.location {
            let distance = Location::new(37.7749, -122.4194).distance_to(location);
            println!(
                "- {} ({}km away)",
                vendor
                    .vendor_name
                    .as_ref()
                    .unwrap_or(&"Unknown".to_string()),
                distance
            );
        }
    }

    // Get a specific vendor by public key
    println!("Getting vendor with public key 'vendor_public_key_123'...");
    let vendor = dht_client
        .get_listing("vendor_public_key_123".to_string())
        .await?;

    if let Some(vendor_listing) = vendor {
        println!(
            "Found vendor: {}",
            vendor_listing
                .vendor_name
                .unwrap_or_else(|| "Unknown".to_string())
        );
        println!("Items offered: {}", vendor_listing.items_offered.len());
    } else {
        println!("Vendor not found");
    }

    // Shutdown the DHT client
    println!("Shutting down DHT client...");
    dht_client.shutdown().await?;
    println!("DHT client shut down successfully");

    Ok(())
}
