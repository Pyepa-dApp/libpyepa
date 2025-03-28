//! Custom error types for the SDK

use thiserror::Error;

/// Main error type for the SDK
#[derive(Error, Debug)]
pub enum Error {
    /// Cryptographic operation failed
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Serialization or deserialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Network operation failed
    #[error("Network error: {0}")]
    Network(String),

    /// DHT operation failed
    #[error("DHT error: {0}")]
    Dht(String),

    /// Invalid data or parameter
    #[error("Invalid data: {0}")]
    InvalidData(String),

    /// Operation not permitted in current state
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Authentication or authorization failed
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Other error
    #[error("Other error: {0}")]
    Other(String),
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Other(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Other(s.to_string())
    }
}
