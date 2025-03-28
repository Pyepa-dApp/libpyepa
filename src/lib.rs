//! # libpyepa
//!
//! A Rust SDK for the Pyepa peer-to-peer order management protocol.
//!
//! This SDK enables direct peer-to-peer order management between Buyers and Vendors
//! without the need for a central intermediary.

pub mod api;
pub mod config;
pub mod core;
pub mod models;
pub mod network;
pub mod utils;

pub use crate::models::{Item, Location, Message, Order, OrderItem, Reputation, VendorListing};

pub use crate::core::error::Error;

/// Result type used throughout the SDK
pub type Result<T> = std::result::Result<T, Error>;

/// SDK version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
