## Pyepa: A Technical Specification for a Peer-to-Peer Order Management Protocol

**Version 2.0**

**Date:** March 27, 2025

**Authors:** Kenneth Matovu

**1. Introduction**

This document specifies a peer-to-peer protocol for managing orders directly between Buyers and Vendors without the need for a central intermediary. The protocol aims to provide robust features for discovery, secure and private order management, transparent order history, and mechanisms for building trust and resolving disputes, implemented using the Rust programming language.

**2. Goals and Requirements**

The primary goals of this protocol are to:

- Enable Buyers to discover available Vendors and their orderable items through enhanced search and reputation-based ranking in a decentralized manner.
- Establish secure and private end-to-end encrypted communication channels between Buyers and Vendors for each order, supporting asynchronous communication.
- Facilitate the complete lifecycle of an order, including creation, acceptance/rejection, dispatch, delivery, delivery acceptance/rejection, and optional returns.
- Integrate support for decentralized payment methods.
- Provide a framework for decentralized dispute resolution.
- Ensure that only the Buyer and Vendor involved in a specific order can access the order details.
- Allow each party to maintain their independent transaction history.
- Be implementable primarily using the Rust programming language and its ecosystem.

**3. Actors**

The protocol involves two primary actors:

- **Buyer:** The user who wants to place an order.
- **Vendor:** The user who offers items for order and accepts orders.

**4. Core Components**

The protocol relies on the following core components:

- **Cryptographic Primitives (Rust Libraries Recommended):**
  - **Hashing Algorithm:** SHA-256 (e.g., using `rust-crypto` or `ring`).
  - **Digital Signature Scheme:** ECDSA using secp256k1 (e.g., using `secp256k1`). Each user possesses a long-term Identity Key pair (`IKpub`, `IKpriv`).
  - **Key Exchange Protocol:** Adaptation of X3DH using Curve25519 (available in libraries like `curve25519-dalek` or within `ring`).
  - **Symmetric Encryption:** AES-GCM (e.g., using `rust-crypto` or `ring`).
  - **Key Derivation Function (KDF):** HKDF (e.g., using the `hkdf` crate).
- **Decentralized Directory (DHT) for Discovery (Rust Libraries Recommended):**
  - Kademlia protocol (e.g., using `tokio-dht` or `libp2p`).
- **Reputation System:**
  - A decentralized system for storing and retrieving Vendor ratings and reviews.
- **Payment Integration:**
  - Abstraction for handling decentralized payment details.
- **Dispute Resolution Framework:**
  - A defined process for handling disputes.
- **Order Data Structure:** A `struct` or similar data structure in Rust to represent an order.
- **Order State Machine:** An `enum` or state management mechanism in Rust to track the order's status.

**5. Protocol Workflow**

**5.1. Vendor Listing (Enhanced):**

1.  A Vendor generates a listing (represented as a Rust `struct`) containing:
    - `vendor_identity_key_public`: `String` (Base64 or hex encoded).
    - `vendor_name`: `Option<String>`.
    - `location`: `Option<Location>` where `Location` is a `struct` with `latitude: f64` and `longitude: f64`.
    - `items_offered`: `Vec<Item>` where `Item` is a `struct` with `item_id: String`, `item_name: String`, `description: Option<String>`, `price: Option<String>`, `availability: Option<String>`, `tags: Vec<String>`.
    - `payment_methods_accepted`: `Vec<String>` (e.g., ["BTC", "ETH"]).
    - `service_terms`: `Option<String>`.
    - `timestamp`: `u64` (Unix timestamp).
    - `signature`: `String` (Base64 or hex encoded).
2.  The Vendor serializes this listing (e.g., to JSON using `serde_json`), signs it using their identity private key, and publishes it to the DHT using a key derived from their public key or relevant search terms.

**5.2. Buyer Discovery (Enhanced):**

1.  A Buyer's client queries the DHT using search terms (e.g., item keywords, location).
2.  The DHT returns a list of serialized Vendor listings.
3.  The Buyer's client deserializes the listings and verifies the signature using the `vendor_identity_key_public`. The client can then rank the results based on relevance and the Vendor's reputation score (retrieved as described in Section 5.11).

**5.3. Secure Session Establishment (Advanced Key Management - Inspired by X3DH):**

1.  The Buyer retrieves the Vendor's `vendor_identity_key_public` and a fresh `signed_prekey_public` (and potentially a `one-time_prekey_public`) from the Vendor's listing or a dedicated prekey retrieval mechanism. These prekeys are also signed by the Vendor's identity key.
2.  The Buyer generates an ephemeral key pair (`buyer_ephemeral_public_key`, `buyer_ephemeral_private_key`) using Curve25519.
3.  The Buyer performs the following Diffie-Hellman (DH) exchanges using the `curve25519-dalek` or `ring` library:
    - DH1: `DH(buyer_ephemeral_private_key, vendor_identity_key_public)`
    - DH2: `DH(buyer_ephemeral_private_key, vendor_signed_prekey_public)`
    - DH3: `DH(buyer_ephemeral_private_key, vendor_one-time_prekey_public)` (if available)
4.  The Buyer derives a shared secret using HKDF with the results of these DH exchanges and their own `buyer_identity_key_private`.
5.  The Buyer sends an initial message (encrypted using AES-GCM with a key derived from the shared secret) to the Vendor containing their `buyer_identity_key_public`, `buyer_ephemeral_public_key`, the ID of the Vendor's signed prekey used, and potentially the ID of the one-time prekey used.
6.  Upon receiving the initial message, the Vendor performs the corresponding DH exchanges using their private keys and the information from the Buyer's message.
7.  The Vendor derives the same shared secret using HKDF.
8.  The Vendor decrypts the Buyer's initial message. The Vendor should then generate a new set of prekeys for future communication.
9.  A session key for symmetric encryption is derived from this shared secret.

**5.4. Order Creation:**

1.  The Buyer creates an `Order` struct instance, including `payment_method` (`String`) and `payment_details` (`String`).
2.  The Buyer serializes the `Order` to JSON, encrypts it using AES-GCM with the session key, and sends the ciphertext to the Vendor.

**5.5. Order Acceptance/Rejection:**

1.  The Vendor receives the encrypted order, decrypts it, and deserializes it.
2.  The Vendor verifies the Buyer's signature on the `Order`.
3.  The Vendor sends an encrypted `Message` struct back with `message_type` as "order_acceptance" or "order_rejection", the `order_id`, `status` ("accepted" or "rejected"), a timestamp, and a signature using their identity private key.

**5.6. Dispatch (if accepted):**

1.  The Vendor sends an encrypted `Message` with `message_type` as "dispatch_notification", the `order_id`, `status` as "dispatched", `dispatch_timestamp`, optional `tracking_information`, and signature.

**5.7. Delivery:**

1.  The Vendor sends an encrypted `Message` with `message_type` as "delivery_notification", the `order_id`, `status` as "delivered", `delivery_timestamp`, and signature.

**5.8. Delivery Acceptance/Rejection:**

1.  The Buyer sends an encrypted `Message` with `message_type` as "delivery_response", the `order_id`, `status` as "delivery_accepted" or "delivery_rejected", optional `reason`, timestamp, and signature.

**5.9. Return Process (Optional):**

1.  Buyer initiates a return with an encrypted `Message` with `message_type` as "return_request", `order_id`, `status` as "return_requested", `reason`, timestamp, and signature.
2.  Vendor responds with an encrypted `Message` with `message_type` as "return_response", `order_id`, `status` as "return_accepted" or "return_rejected", optional `reason`, timestamp, and signature.

**5.10. Payment Integration:**

1.  The `Order` struct contains fields for `payment_method` and `payment_details`. The protocol facilitates the secure exchange of this information.
2.  The actual payment processing is external to this protocol. Buyers and Vendors would use the agreed-upon payment method (e.g., initiate a cryptocurrency transaction) based on the details exchanged.

**5.11. Reputation System:**

1.  After order completion, the Buyer can create a signed rating (e.g., an integer from 1 to 5) and an optional review for the Vendor.
2.  This data, along with the Vendor's public identity key and the Buyer's public key, is signed by the Buyer.
3.  This signed reputation data can be stored in a decentralized registry (potentially a dedicated section in the DHT or another distributed storage system). The key for storage could be the Vendor's public key.
4.  Buyers querying for Vendors can retrieve this reputation data and use it for ranking and decision-making.

**5.12. Dispute Resolution Framework:**

1.  If a dispute occurs, either party can initiate a dispute. This could be signaled by a specific encrypted message type.
2.  The protocol can facilitate the exchange of evidence (encrypted order details, message history) between the Buyer and Vendor.
3.  For mediated resolution, a mutually agreed-upon third party's public key could be involved. Communication with the mediator could happen in a separate encrypted session, with relevant order information shared (with consent from both parties).
4.  For decentralized arbitration, the protocol could define a standard format for submitting dispute information to a chosen decentralized arbitration platform (if one is integrated).

**6. Data Structures (Rust)**

```rust
#[derive(Serialize, Deserialize, Debug)]
pub struct Location {
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Item {
    pub item_id: String,
    pub item_name: String,
    pub description: Option<String>,
    pub price: Option<String>,
    pub availability: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VendorListing {
    pub vendor_identity_key_public: String,
    pub vendor_name: Option<String>,
    pub location: Option<Location>,
    pub items_offered: Vec<Item>,
    pub payment_methods_accepted: Vec<String>,
    pub service_terms: Option<String>,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Order {
    pub order_id: String,
    pub buyer_public_key: String,
    pub vendor_public_key: String,
    pub order_items: Vec<OrderItem>,
    pub total_amount: String,
    pub buyer_location: Option<Location>,
    pub created_timestamp: u64,
    pub current_state: String, // e.g., "created", "accepted", "rejected", etc.
    pub payment_method: String,
    pub payment_details: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OrderItem {
    pub item_id: String,
    pub quantity: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub message_type: String,
    pub order_id: String,
    pub status: Option<String>,
    pub timestamp: u64,
    pub payload: Option<serde_json::Value>,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Reputation {
    pub vendor_public_key: String,
    pub buyer_public_key: String,
    pub rating: u8,
    pub review: Option<String>,
    pub timestamp: u64,
    pub signature: String, // Buyer's signature
}
```

**7. Security Considerations**

- End-to-End Encryption, Authentication, Forward Secrecy, and Privacy of Order Details remain as described in Version 1.0.
- **Asynchronous Communication Security:** X3DH-based key exchange ensures secure initial communication even when parties are offline. Proper prekey management by Vendors is crucial.
- **Reputation System Security:** Implement measures to prevent Sybil attacks and ensure the integrity of ratings. This might involve requiring a minimum number of confirmed transactions before a user can leave a rating or using cryptographic techniques to link ratings to specific interactions.
- **DHT Security:** Be aware of potential vulnerabilities in the chosen DHT implementation and consider mitigation strategies.

**8. Technology Choices (Recommendations - Rust)**

- **Cryptography:** `ring`, `ed25519-dalek`/`secp256k1`, `hkdf`.
- **DHT:** `tokio-dht` or `libp2p`.
- **Networking:** `tokio` or `async-std`.
- **Data Serialization:** `serde` and `serde_json`.

**9. Conclusion**

This comprehensive technical specification outlines a peer-to-peer order management protocol designed for implementation in Rust. It incorporates features for enhanced discovery, secure communication, order lifecycle management, payment integration considerations, a dispute resolution framework, and a decentralized reputation system. Developers can use this document as a solid foundation for building a fully functional and secure decentralized ordering platform.
