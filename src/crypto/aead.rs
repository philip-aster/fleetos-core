use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Result, anyhow};

pub struct AeadEnvelope;

impl AeadEnvelope {
    /// Encrypts plaintext using AES-256-GCM with a randomly generated 12-byte CSPRNG nonce
    pub fn encrypt(key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        Self::encrypt_with_aad(key_bytes, plaintext, &[])
    }

    /// Encrypts plaintext with Additional Authenticated Data (AAD) bound to the ciphertext
    pub fn encrypt_with_aad(
        key_bytes: &[u8; 32],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let cipher = Aes256Gcm::new(key_bytes.into());

        let mut nonce_bytes = [0u8; 12];
        rand::fill(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|e| anyhow!("AES-GCM encryption failed: {}", e))?;

        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    /// Decrypts ciphertext given the matching 32-byte AES key and 12-byte nonce
    pub fn decrypt(key_bytes: &[u8; 32], ciphertext: &[u8], nonce_bytes: &[u8]) -> Result<Vec<u8>> {
        Self::decrypt_with_aad(key_bytes, ciphertext, nonce_bytes, &[])
    }

    /// Decrypts ciphertext verifying the matching Additional Authenticated Data (AAD)
    pub fn decrypt_with_aad(
        key_bytes: &[u8; 32],
        ciphertext: &[u8],
        nonce_bytes: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let nonce_array: &[u8; 12] = nonce_bytes.try_into().map_err(|_| {
            anyhow!(
                "Invalid nonce length: expected 12 bytes, got {}",
                nonce_bytes.len()
            )
        })?;

        let cipher = Aes256Gcm::new(key_bytes.into());
        let nonce = Nonce::from(*nonce_array);

        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        let plaintext = cipher
            .decrypt(&nonce, payload)
            .map_err(|e| anyhow!("AES-GCM decryption/authentication failed: {}", e))?;

        Ok(plaintext)
    }
}
