//! Cryptographic primitives handling

use crate::core::error::Error;
use crate::Result;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use ring::{digest, rand};
use secp256k1::{Message as Secp256k1Message, PublicKey, Secp256k1, SecretKey};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519PrivateKey};

/// Key pair for identity (long-term keys)
pub struct IdentityKeyPair {
    /// Private key
    pub private_key: SecretKey,
    /// Public key
    pub public_key: PublicKey,
}

/// Key pair for ephemeral keys (used in X3DH)
pub struct EphemeralKeyPair {
    /// Private key
    pub private_key: X25519PrivateKey,
    /// Public key
    pub public_key: X25519PublicKey,
}

/// Cryptographic utilities
pub struct Crypto;

impl Crypto {
    /// Generates a new identity key pair
    pub fn generate_identity_keypair() -> Result<IdentityKeyPair> {
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let private_key = SecretKey::new(&mut rng);
        let public_key = PublicKey::from_secret_key(&secp, &private_key);

        Ok(IdentityKeyPair {
            private_key,
            public_key,
        })
    }

    /// Generates a new ephemeral key pair for X3DH
    pub fn generate_ephemeral_keypair() -> EphemeralKeyPair {
        let private_key = X25519PrivateKey::new(OsRng);
        let public_key = X25519PublicKey::from(&private_key);

        EphemeralKeyPair {
            private_key,
            public_key,
        }
    }

    /// Signs a message using the identity private key
    pub fn sign(private_key: &SecretKey, message: &[u8]) -> Result<Vec<u8>> {
        let secp = Secp256k1::new();
        let message_hash = digest::digest(&digest::SHA256, message);
        let message_to_sign = Secp256k1Message::from_slice(message_hash.as_ref())
            .map_err(|e| Error::Crypto(format!("Failed to create message to sign: {}", e)))?;

        let signature = secp.sign_ecdsa(&message_to_sign, private_key);
        Ok(signature.serialize_compact().to_vec())
    }

    /// Verifies a signature using the identity public key
    pub fn verify(public_key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<bool> {
        let secp = Secp256k1::new();
        let message_hash = digest::digest(&digest::SHA256, message);
        let message_to_verify = Secp256k1Message::from_slice(message_hash.as_ref())
            .map_err(|e| Error::Crypto(format!("Failed to create message to verify: {}", e)))?;

        let signature = secp256k1::ecdsa::Signature::from_compact(signature)
            .map_err(|e| Error::Crypto(format!("Failed to parse signature: {}", e)))?;

        match secp.verify_ecdsa(&message_to_verify, &signature, public_key) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Performs X3DH key exchange
    pub fn perform_x3dh(
        identity_key: &X25519PrivateKey,
        ephemeral_key: &X25519PrivateKey,
        other_identity_key: &X25519PublicKey,
        other_signed_prekey: &X25519PublicKey,
        other_onetime_prekey: Option<&X25519PublicKey>,
    ) -> Vec<u8> {
        // DH1 = DH(identity_key, other_signed_prekey)
        let dh1 = identity_key.diffie_hellman(other_signed_prekey);

        // DH2 = DH(ephemeral_key, other_identity_key)
        let dh2 = ephemeral_key.diffie_hellman(other_identity_key);

        // DH3 = DH(ephemeral_key, other_signed_prekey)
        let dh3 = ephemeral_key.diffie_hellman(other_signed_prekey);

        // DH4 = DH(ephemeral_key, other_onetime_prekey) (if available)
        let mut shared_secret = Vec::new();
        shared_secret.extend_from_slice(dh1.as_bytes());
        shared_secret.extend_from_slice(dh2.as_bytes());
        shared_secret.extend_from_slice(dh3.as_bytes());

        if let Some(onetime_prekey) = other_onetime_prekey {
            let dh4 = ephemeral_key.diffie_hellman(onetime_prekey);
            shared_secret.extend_from_slice(dh4.as_bytes());
        }

        // Derive the final shared secret using HKDF
        let h = Hkdf::<digest::Sha256>::new(None, &shared_secret);
        let mut okm = [0u8; 32];
        h.expand(b"X3DH", &mut okm)
            .expect("HKDF expansion should not fail with valid parameters");

        okm.to_vec()
    }

    /// Encrypts a message using AES-GCM
    pub fn encrypt(key: &[u8], plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err(Error::Crypto("Key must be 32 bytes for AES-256-GCM".into()));
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| Error::Crypto(format!("Failed to create cipher: {}", e)))?;

        // Generate a random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the plaintext
        let payload = Payload {
            msg: plaintext,
            aad: associated_data,
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| Error::Crypto(format!("Encryption failed: {}", e)))?;

        // Prepend the nonce to the ciphertext
        let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypts a message using AES-GCM
    pub fn decrypt(key: &[u8], ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err(Error::Crypto("Key must be 32 bytes for AES-256-GCM".into()));
        }

        if ciphertext.len() < 12 {
            return Err(Error::Crypto("Ciphertext too short".into()));
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| Error::Crypto(format!("Failed to create cipher: {}", e)))?;

        // Extract the nonce from the first 12 bytes
        let nonce = Nonce::from_slice(&ciphertext[..12]);

        // The actual ciphertext starts after the nonce
        let actual_ciphertext = &ciphertext[12..];

        // Decrypt the ciphertext
        let payload = Payload {
            msg: actual_ciphertext,
            aad: associated_data,
        };

        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|e| Error::Crypto(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }

    /// Encodes binary data as Base64
    pub fn encode_base64(data: &[u8]) -> String {
        BASE64.encode(data)
    }

    /// Decodes Base64 data to binary
    pub fn decode_base64(data: &str) -> Result<Vec<u8>> {
        BASE64
            .decode(data)
            .map_err(|e| Error::Crypto(format!("Base64 decoding failed: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_keypair_generation() {
        let keypair = Crypto::generate_identity_keypair().unwrap();
        assert!(keypair.private_key.secret_bytes().len() > 0);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = Crypto::generate_identity_keypair().unwrap();
        let message = b"Hello, world!";

        let signature = Crypto::sign(&keypair.private_key, message).unwrap();
        let is_valid = Crypto::verify(&keypair.public_key, message, &signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_encrypt_and_decrypt() {
        let key = [0u8; 32]; // Use a zero key for testing
        let plaintext = b"Secret message";
        let associated_data = b"Associated data";

        let ciphertext = Crypto::encrypt(&key, plaintext, associated_data).unwrap();
        let decrypted = Crypto::decrypt(&key, &ciphertext, associated_data).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_base64_encoding() {
        let data = b"Test data for Base64 encoding";
        let encoded = Crypto::encode_base64(data);
        let decoded = Crypto::decode_base64(&encoded).unwrap();

        assert_eq!(decoded, data);
    }
}
