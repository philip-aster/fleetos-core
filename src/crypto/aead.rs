// fleetos-core/src/crypto/aead.rs

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Result, anyhow};
use rand::prelude::*;

pub struct AeadEnvelope;

impl AeadEnvelope {
    /// Encrypts plaintext using AES-256-GCM and a randomly generated 12-byte nonce
    pub fn encrypt(key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let cipher = Aes256Gcm::new_from_slice(key_bytes)
            .map_err(|e| anyhow!("Invalid AES key length: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow!("Encryption error: {}", e))?;

        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    /// Decrypts ciphertext given the matching 32-byte AES key and 12-byte nonce
    pub fn decrypt(key_bytes: &[u8; 32], ciphertext: &[u8], nonce_bytes: &[u8]) -> Result<Vec<u8>> {
        if nonce_bytes.len() != 12 {
            return Err(anyhow!(
                "Invalid nonce length: expected 12 bytes, got {}",
                nonce_bytes.len()
            ));
        }

        let cipher = Aes256Gcm::new(key_bytes.into());

        let mut array = [0u8; 12];
        array.copy_from_slice(nonce_bytes);
        let nonce = Nonce::from(array);

        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption error: {}", e))?;

        Ok(plaintext)
    }
}
