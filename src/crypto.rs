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
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CryptoError {
    #[error("decryption failed")]
    DecryptionFailed,
}

/// Monotonically increasing counter per SVID to prevent replay attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecretSequence(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecipientX25519Pubkey(pub [u8; 32]);

#[derive(Debug, Clone)]
pub struct SealedSecret {
    pub sealed_for_svid_version: u64,
    pub sequence: SecretSequence,
    pub ephemeral_pubkey: [u8; 32],
    pub ciphertext: Vec<u8>, // Contains [12-byte nonce || encrypted payload]
}

/// Ephemeral X25519 key agreement against recipient SVID public key, ChaCha20Poly1305 AEAD.
pub fn seal(
    recipient_pubkey: &RecipientX25519Pubkey,
    plaintext: &[u8],
    svid_version: u64,
    sequence: SecretSequence,
) -> Result<SealedSecret, CryptoError> {
    // 1. Generate ephemeral keypair using x25519-dalek's OS RNG (via `getrandom` feature)
    let eph_secret = EphemeralSecret::random();
    let eph_pubkey = PublicKey::from(&eph_secret);

    // 2. Diffie-Hellman key agreement
    let recipient_pubkey = PublicKey::from(recipient_pubkey.0);
    let shared_secret = eph_secret.diffie_hellman(&recipient_pubkey);

    // 3. Derive 32-byte symmetric key using BLAKE3 with explicit domain separation
    let key_bytes =
        blake3::derive_key("FleetOS v1 SecretSealing Context", shared_secret.as_bytes());
    // Use `From` for exact-size arrays instead of deprecated `from_slice`
    let key = Key::from(key_bytes);
    let cipher = ChaCha20Poly1305::new(&key);

    // 4. Generate a cryptographically secure random nonce per encryption
    let mut nonce_bytes = [0u8; 12];
    rand::fill(&mut nonce_bytes);
    let aead_nonce = AeadNonce::from(nonce_bytes);

    // 5. Additional Authenticated Data (binds context to the ciphertext)
    let mut ad = Vec::with_capacity(16);
    ad.extend_from_slice(&svid_version.to_le_bytes());
    ad.extend_from_slice(&sequence.0.to_le_bytes());

    // 6. Encrypt the payload
    let encrypted_payload = cipher
        .encrypt(
            &aead_nonce,
            Payload {
                msg: plaintext,
                aad: &ad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    // 7. Prepend nonce to ciphertext
    let mut ciphertext = Vec::with_capacity(12 + encrypted_payload.len());
    ciphertext.extend_from_slice(&nonce_bytes);
    ciphertext.extend_from_slice(&encrypted_payload);

    Ok(SealedSecret {
        sealed_for_svid_version: svid_version,
        sequence,
        ephemeral_pubkey: eph_pubkey.to_bytes(),
        ciphertext,
    })
}

pub fn unseal(
    recipient_privkey: &[u8; 32],
    sealed: &SealedSecret,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // 1. Load static recipient private key and public ephemeral key
    let recipient_secret = StaticSecret::from(*recipient_privkey);
    let eph_pubkey = PublicKey::from(sealed.ephemeral_pubkey);

    // 2. Compute identical DH shared secret
    let shared_secret = recipient_secret.diffie_hellman(&eph_pubkey);

    // 3. Derive key via BLAKE3 with explicit domain separation
    let key_bytes =
        blake3::derive_key("FleetOS v1 SecretSealing Context", shared_secret.as_bytes());
    let key = Key::from(key_bytes);
    let cipher = ChaCha20Poly1305::new(&key);

    if sealed.ciphertext.len() < 12 {
        return Err(CryptoError::DecryptionFailed);
    }

    // 4. Reconstruct nonce and split ciphertext
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&sealed.ciphertext[..12]);
    let aead_nonce = AeadNonce::from(nonce_bytes);

    let encrypted_payload = &sealed.ciphertext[12..];

    // 5. Reconstruct AAD
    let mut ad = Vec::with_capacity(16);
    ad.extend_from_slice(&sealed.sealed_for_svid_version.to_le_bytes());
    ad.extend_from_slice(&sealed.sequence.0.to_le_bytes());

    // 6. Decrypt payload and wrap in Zeroizing for memory safety
    let plaintext = cipher
        .decrypt(
            &aead_nonce,
            Payload {
                msg: encrypted_payload,
                aad: &ad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(Zeroizing::new(plaintext))
}
