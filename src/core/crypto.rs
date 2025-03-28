use crate::core::error::Error;
use crate::core::types::Result;
use curve25519_dalek::constants::BASEPOINT;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use rand_core::OsRng;
use ring::aead::{Aead, BoundKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305};
use ring::digest::{Context, SHA256};
use ring::hmac;
use ring::rand::SystemRandom;
use secp256k1::{ecdsa, PublicKey, Secp256k1, SecretKey};
use std::convert::TryInto;

const HKDF_OUTPUT_LEN: usize = 32; // Example length for derived keys
const AES_GCM_NONCE_LEN: usize = 12; // Standard nonce length for AES-GCM

/// Hashes the input data using SHA-256.
pub fn hash_sha256(data: &[u8]) -> Result<Vec<u8>> {
    let mut context = Context::new(&SHA256);
    context.update(data);
    Ok(context.finish().as_ref().to_vec())
}

/// Generates an ECDSA key pair using the secp256k1 curve.
pub fn generate_ecdsa_keypair() -> Result<(String, String)> {
    let s = Secp256k1::new();
    let (secret_key, public_key) = s.generate_keypair(&mut OsRng);
    Ok((
        secret_key
            .secret_bytes()
            .to_vec()
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect(),
        public_key
            .serialize()
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect(),
    ))
}

/// Signs data using the provided ECDSA private key (in hex format).
pub fn sign_ecdsa(private_key_hex: &str, data: &[u8]) -> Result<String> {
    let s = Secp256k1::new();
    let secret_bytes = hex::decode(private_key_hex)
        .map_err(|e| Error::CryptoError(format!("Failed to decode private key: {}", e)))?;
    let secret_key = SecretKey::from_slice(&secret_bytes)
        .map_err(|e| Error::CryptoError(format!("Invalid private key: {}", e)))?;
    let message =
        secp256k1::Message::from_digest(hash_sha256(data).unwrap().as_slice().try_into().unwrap())
            .map_err(|e| {
                Error::CryptoError(format!("Failed to create message for signing: {}", e))
            })?;
    let signature = s.sign_ecdsa(&message, &secret_key);
    Ok(signature
        .serialize_compact()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect())
}

pub fn verify_ecdsa(public_key_hex: &str, signature_hex: &str, data: &[u8]) -> Result<()> {
    let s = Secp256k1::new();
    let public_key_bytes = hex::decode(public_key_hex)
        .map_err(|e| Error::CryptoError(format!("Failed to decode public key: {}", e)))?;
    let public_key = PublicKey::from_slice(&public_key_bytes)
        .map_err(|e| Error::CryptoError(format!("Invalid public key: {}", e)))?;
    let signature_bytes = hex::decode(signature_hex)
        .map_err(|e| Error::CryptoError(format!("Failed to decode signature: {}", e)))?;
    let signature = ecdsa::Signature::from_compact(&signature_bytes)
        .map_err(|e| Error::CryptoError(format!("Invalid signature: {}", e)))?;
    let message =
        secp256k1::Message::from_digest(hash_sha256(data).unwrap().as_slice().try_into().unwrap())
            .map_err(|e| {
                Error::CryptoError(format!("Failed to create message for verification: {}", e))
            })?;
    match s.verify_ecdsa(&message, &signature, &public_key) {
        Ok(_) => Ok(()),
        Err(_) => Err(Error::SignatureVerificationError),
    }
}

pub fn generate_curve25519_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = OsRng;
    let secret = Scalar::random(&mut rng);
    let public = &secret * &BASEPOINT;
    Ok((secret.as_bytes().to_vec(), public.as_bytes().to_vec()))
}

pub fn curve25519_dh(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    let secret = Scalar::from_bytes_mod_order(
        private_key
            .try_into()
            .map_err(|_| Error::CryptoError("Invalid private key length".into()))?,
    );
    let public = MontgomeryPoint::from_bytes(
        &public_key
            .try_into()
            .map_err(|_| Error::CryptoError("Invalid public key length".into()))?,
    )
    .map_err(|_| Error::CryptoError("Invalid public key format".into()))?;
    let shared_secret = &secret * &public;
    Ok(shared_secret.as_bytes().to_vec())
}

pub fn derive_key_hkdf(salt: Option<&[u8]>, ikm: &[u8], info: Option<&[u8]>) -> Result<Vec<u8>> {
    let salt = salt.unwrap_or(&[]);
    let info = info.unwrap_or(&[]);
    let hk = Hkdf::<SHA256, hmac::Hmac<SHA256>>::new(Some(salt), ikm)
        .map_err(|e| Error::CryptoError(format!("HKDF error: {}", e)))?;
    let mut okm = [0u8; HKDF_OUTPUT_LEN];
    hk.expand(info, &mut okm)
        .map_err(|e| Error::CryptoError(format!("HKDF expand error: {}", e)))?;
    Ok(okm.to_vec())
}

pub fn encrypt_aes_gcm(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(Error::CryptoError(
            "Invalid AES-GCM key length (must be 32 bytes)".into(),
        ));
    }
    if nonce.len() != AES_GCM_NONCE_LEN {
        return Err(Error::CryptoError(format!(
            "Invalid AES-GCM nonce length (must be {} bytes)",
            AES_GCM_NONCE_LEN
        )));
    }

    let unbound_key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| Error::CryptoError("Failed to create AES-GCM unbound key".into()))?;
    let key_ref = BoundKey::from(unbound_key);
    let nonce_struct = Nonce::try_from(nonce)
        .map_err(|_| Error::CryptoError("Failed to create AES-GCM nonce".into()))?;

    let mut in_out = plaintext.to_vec();
    let tag = key_ref
        .seal_in_place_append_tag(nonce_struct, associated_data, &mut in_out)
        .map_err(|_| Error::CryptoError("AES-GCM encryption failed".into()))?;

    let mut ciphertext = in_out;
    ciphertext.extend_from_slice(tag.as_ref());
    Ok(ciphertext)
}

pub fn decrypt_aes_gcm(
    key: &[u8],
    nonce: &[u8],
    ciphertext_with_tag: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(Error::CryptoError(
            "Invalid AES-GCM key length (must be 32 bytes)".into(),
        ));
    }
    if nonce.len() != AES_GCM_NONCE_LEN {
        return Err(Error::CryptoError(format!(
            "Invalid AES-GCM nonce length (must be {} bytes)",
            AES_GCM_NONCE_LEN
        )));
    }
    if ciphertext_with_tag.len() < AES_256_GCM.tag_len() {
        return Err(Error::CryptoError("Ciphertext with tag too short".into()));
    }

    let unbound_key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| Error::CryptoError("Failed to create AES-GCM unbound key".into()))?;
    let key_ref = BoundKey::from(unbound_key);
    let nonce_struct = Nonce::try_from(nonce)
        .map_err(|_| Error::CryptoError("Failed to create AES-GCM nonce".into()))?;

    let ciphertext_len = ciphertext_with_tag.len() - AES_256_GCM.tag_len();
    let mut in_out = ciphertext_with_tag.to_vec();

    key_ref
        .open_in_place(nonce_struct, associated_data, &mut in_out)
        .map_err(|_| Error::CryptoError("AES-GCM decryption failed".into()))?;

    in_out.truncate(ciphertext_len);
    Ok(in_out)
}

pub fn generate_aes_gcm_nonce() -> Result<Vec<u8>> {
    let mut nonce = [0u8; AES_GCM_NONCE_LEN];
    let rng = SystemRandom::new();
    rng.fill(&mut nonce)
        .map_err(|e| Error::CryptoError(format!("Failed to generate AES-GCM nonce: {}", e)))?;
    Ok(nonce.to_vec())
}

#[allow(dead_code)]
pub fn encrypt_chacha20_poly1305(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(Error::CryptoError(
            "Invalid ChaCha20-Poly1305 key length (must be 32 bytes)".into(),
        ));
    }
    if nonce.len() != 12 {
        return Err(Error::CryptoError(
            "Invalid ChaCha20-Poly1305 nonce length (must be 12 bytes)".into(),
        ));
    }

    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key)
        .map_err(|_| Error::CryptoError("Failed to create ChaCha20-Poly1305 unbound key".into()))?;
    let key_ref = BoundKey::from(unbound_key);
    let nonce_struct = Nonce::try_from(nonce)
        .map_err(|_| Error::CryptoError("Failed to create ChaCha20-Poly1305 nonce".into()))?;

    let mut in_out = plaintext.to_vec();
    let tag = key_ref
        .seal_in_place_append_tag(nonce_struct, associated_data, &mut in_out)
        .map_err(|_| Error::CryptoError("ChaCha20-Poly1305 encryption failed".into()))?;

    let mut ciphertext = in_out;
    ciphertext.extend_from_slice(tag.as_ref());
    Ok(ciphertext)
}

#[allow(dead_code)]
pub fn decrypt_chacha20_poly1305(
    key: &[u8],
    nonce: &[u8],
    ciphertext_with_tag: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(Error::CryptoError(
            "Invalid ChaCha20-Poly1305 key length (must be 32 bytes)".into(),
        ));
    }
    if nonce.len() != 12 {
        return Err(Error::CryptoError(
            "Invalid ChaCha20-Poly1305 nonce length (must be 12 bytes)".into(),
        ));
    }
    if ciphertext_with_tag.len() < CHACHA20_POLY1305.tag_len() {
        return Err(Error::CryptoError("Ciphertext with tag too short".into()));
    }

    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key)
        .map_err(|_| Error::CryptoError("Failed to create ChaCha20-Poly1305 unbound key".into()))?;
    let key_ref = BoundKey::from(unbound_key);
    let nonce_struct = Nonce::try_from(nonce)
        .map_err(|_| Error::CryptoError("Failed to create ChaCha20-Poly1305 nonce".into()))?;

    let ciphertext_len = ciphertext_with_tag.len() - CHACHA20_POLY1305.tag_len();
    let mut in_out = ciphertext_with_tag.to_vec();

    key_ref
        .open_in_place(nonce_struct, associated_data, &mut in_out)
        .map_err(|_| Error::CryptoError("ChaCha20-Poly1305 decryption failed".into()))?;

    in_out.truncate(ciphertext_len);
    Ok(in_out)
}

#[allow(dead_code)]
pub fn generate_chacha20_poly1305_nonce() -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    let rng = SystemRandom::new();
    rng.fill(&mut nonce).map_err(|e| {
        Error::CryptoError(format!("Failed to generate ChaCha20-Poly1305 nonce: {}", e))
    })?;
    Ok(nonce.to_vec())
}
