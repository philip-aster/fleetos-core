// SPDX-License-Identifier: Apache-2.0
//! Hand-assembled HPKE-style sealing (X25519 + ChaCha20Poly1305).

use chacha20poly1305::{
    ChaCha20Poly1305,
    Key,
    Nonce as AeadNonce, // Alias to avoid collision with our attestation Nonce
    aead::{Aead, KeyInit, Payload},
};
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CryptoError {
    #[error("decryption failed")]
    DecryptionFailed,
}

/// Monotonically increasing counter per SVID to prevent replay attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecretSequence(pub u64);

#[derive(Debug, Clone)]
pub struct SealedSecret {
    pub sealed_for_svid_version: u64,
    pub sequence: SecretSequence,
    pub ephemeral_pubkey: [u8; 32],
    pub ciphertext: Vec<u8>,
}

/// Ephemeral X25519 key agreement against recipient SVID public key, ChaCha20Poly1305 AEAD.
pub fn seal(
    recipient_pubkey: &[u8; 32],
    plaintext: &[u8],
    svid_version: u64,
    sequence: SecretSequence,
) -> Result<SealedSecret, CryptoError> {
    // 1. Generate ephemeral keypair using x25519-dalek's OS RNG (via `getrandom` feature)
    let eph_secret = EphemeralSecret::random();
    let eph_pubkey = PublicKey::from(&eph_secret);

    // 2. Diffie-Hellman key agreement
    let recipient_pubkey = PublicKey::from(*recipient_pubkey);
    let shared_secret = eph_secret.diffie_hellman(&recipient_pubkey);

    // 3. Derive 32-byte symmetric key using BLAKE3
    let key_bytes = blake3::hash(shared_secret.as_bytes());
    let key: &Key = key_bytes
        .as_bytes()
        .try_into()
        .expect("BLAKE3 output is 32 bytes");
    let cipher = ChaCha20Poly1305::new(key);

    // 4. Encrypt the payload
    // Using `From` on `[u8; 12]` avoids deprecated `from_slice`
    let aead_nonce = AeadNonce::from([0u8; 12]);

    // Additional Authenticated Data (binds context to the ciphertext)
    let mut ad = Vec::with_capacity(16);
    ad.extend_from_slice(&svid_version.to_le_bytes());
    ad.extend_from_slice(&sequence.0.to_le_bytes());

    let ciphertext = cipher
        .encrypt(
            &aead_nonce,
            Payload {
                msg: plaintext,
                aad: &ad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(SealedSecret {
        sealed_for_svid_version: svid_version,
        sequence,
        ephemeral_pubkey: eph_pubkey.to_bytes(),
        ciphertext,
    })
}

pub fn unseal(recipient_privkey: &[u8; 32], sealed: &SealedSecret) -> Result<Vec<u8>, CryptoError> {
    // 1. Load static recipient private key and public ephemeral key
    let recipient_secret = StaticSecret::from(*recipient_privkey);
    let eph_pubkey = PublicKey::from(sealed.ephemeral_pubkey);

    // 2. Compute identical DH shared secret
    let shared_secret = recipient_secret.diffie_hellman(&eph_pubkey);

    // 3. Derive key via BLAKE3
    let key_bytes = blake3::hash(shared_secret.as_bytes());
    let key: &Key = key_bytes
        .as_bytes()
        .try_into()
        .expect("BLAKE3 output is 32 bytes");
    let cipher = ChaCha20Poly1305::new(key);

    // 4. Reconstruct static nonce and AAD
    let aead_nonce = AeadNonce::from([0u8; 12]);

    let mut ad = Vec::with_capacity(16);
    ad.extend_from_slice(&sealed.sealed_for_svid_version.to_le_bytes());
    ad.extend_from_slice(&sealed.sequence.0.to_le_bytes());

    // 5. Decrypt payload
    cipher
        .decrypt(
            &aead_nonce,
            Payload {
                msg: &sealed.ciphertext,
                aad: &ad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}
