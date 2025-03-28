use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    #[error("DHT error: {0}")]
    DhtError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Signature verification failed")]
    SignatureVerificationError,
    #[error("Invalid data format: {0}")]
    InvalidDataFormat(String),
    #[error("Order processing error: {0}")]
    OrderError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Other error: {0}")]
    Other(String),
}
