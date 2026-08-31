// SPDX-License-Identifier: Apache-2.0
//! Hardware-rooted attestation traits and types.

use crate::crypto::RecipientX25519Pubkey;
use crate::nonce::Nonce;
use crate::spiffe::SpiffeId;
use async_trait::async_trait;
use core::fmt;
use core::str::FromStr;
use std::time::SystemTime;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AttestError {
    #[error("quote generation failed")]
    QuoteGenerationFailed,
    #[error("quote verification failed")]
    VerificationFailed,
    #[error("PCR policy mismatch")]
    PolicyMismatch,
    #[error("invalid or expired join token")]
    InvalidJoinToken, // New error variant
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationQuoteType {
    Tpm2,
    AppleSe,
    Vsock,
    #[cfg(feature = "dev")]
    DevMock,
}

/// A single-use, pre-shared token authorizing a node to join the cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinToken(pub String);

#[derive(Debug, Clone)]
pub struct AttestationQuote {
    pub quote_type: AttestationQuoteType,
    pub raw_quote: Vec<u8>,
    pub raw_signature: Vec<u8>,
    /// Required for initial cluster join. None during SVID rotation.
    pub join_token: Option<JoinToken>,
    /// CR-1: node's X25519 sealing pubkey, generated pre-attestation.
    /// Control registers it at submit_quote time keyed by the attested
    /// SPIFFE ID; it is the sealing target for `crate::crypto::seal` /
    /// SecretService::FetchSecret.
    ///
    /// SECURITY: claimed field — NOT covered by the hardware quote signature.
    /// Binding to the attested identity is only as strong as quote verification
    /// itself. Secret delivery MUST NOT be enabled in production until control's
    /// tpm/apple_se signature verification is implemented.
    pub agent_x25519_pubkey: RecipientX25519Pubkey,
}

/// PCR policy mapping. PCRs included depend on backend.
#[derive(Debug, Clone, Default)]
pub struct PcrPolicy {
    pub pcr0_firmware: Option<[u8; 32]>,
    pub pcr7_secure_boot: Option<[u8; 32]>,
    pub pcr9_kernel: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct AttestedIdentity {
    pub claimed_id: SpiffeId,
    pub quote_type: AttestationQuoteType,
    pub pcr_digest: Option<[u8; 32]>,
    pub verified_at: SystemTime,
}

#[async_trait]
pub trait HardwareAttestor: Send + Sync {
    fn quote_type(&self) -> AttestationQuoteType;
    /// MUST bind to a fresh, caller-supplied nonce.
    /// The caller is responsible for attaching the JoinToken to the resulting AttestationQuote.
    async fn generate_quote(&self, nonce: &Nonce) -> Result<AttestationQuote, AttestError>;
}

#[async_trait]
pub trait QuoteVerifier: Send + Sync {
    /// Verifies both the cryptographic quote and the JoinToken (if initial join).
    async fn verify(
        &self,
        quote: &AttestationQuote,
        nonce: &Nonce,
        policy: &PcrPolicy,
    ) -> Result<AttestedIdentity, AttestError>;
}

// ================= CR-10: canonical EK identity =================
//
// fleetos-core owns the EK-fingerprint hashing convention (same ownership
// rule as `SagRuleId` / `OperatorGrantId`): fleetos-control MUST call
// `EkFingerprint::of_ek_pub` when registering, revoking, or correlating
// Endorsement Keys; local re-implementations of this hash are prohibited.

/// Frozen 16-byte BLAKE3 fingerprint identifying a TPM Endorsement Key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EkFingerprint([u8; 16]);

impl EkFingerprint {
    /// Deterministic fingerprint of a canonical EK public key.
    ///
    /// Input is the EK *public key* bytes, not the EK certificate: the same
    /// EK presented via certificate or via raw public key MUST yield one
    /// fingerprint, so the caller extracts the public key from `ek_cert_der`
    /// before calling.
    ///
    /// Frozen layout as of CR-10 (domain tag, then a single `0x00` separator):
    ///   `b"FleetOS v1 EkFingerprint" || 0x00 || ek_pub`
    ///
    /// Upstream contract: `ek_pub` MUST be non-empty and canonical
    /// (TPM2B_PUBLIC marshaled or equivalent); validation happens at the
    /// registration/activation boundary, not here (same pure-hasher rule as
    /// `SagRuleId::of_rule` / `OperatorGrantId::of_grant`).
    pub fn of_ek_pub(ek_pub: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"FleetOS v1 EkFingerprint");
        hasher.update(&[0x00]);
        hasher.update(ek_pub);
        let mut id_bytes = [0u8; 16];
        let hash = hasher.finalize();
        id_bytes.copy_from_slice(&hash.as_bytes()[..16]);
        Self(id_bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Lowercase-hex wire form (matches the `ek_fingerprint` string fields in admin.proto).
    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(32);
        for &b in &self.0 {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        s
    }

    /// Parse the hex wire form. Accepts lower- and uppercase digits.
    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.len() != 32 {
            return None;
        }
        let mut out = [0u8; 16];
        for (i, slot) in out.iter_mut().enumerate() {
            let hi = hex_val(bytes[2 * i])?;
            let lo = hex_val(bytes[2 * i + 1])?;
            *slot = (hi << 4) | lo;
        }
        Some(Self(out))
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl fmt::Display for EkFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for EkFingerprint {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s).ok_or("invalid EkFingerprint hex")
    }
}

#[cfg(test)]
mod ek_fingerprint_tests {
    use super::*;

    fn ek_pub(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn deterministic() {
        assert_eq!(
            EkFingerprint::of_ek_pub(&ek_pub(0x11)),
            EkFingerprint::of_ek_pub(&ek_pub(0x11))
        );
    }

    #[test]
    fn every_byte_moves_the_fingerprint() {
        let base = EkFingerprint::of_ek_pub(&ek_pub(0x11));
        let mut flipped = ek_pub(0x11);
        flipped[17] ^= 0x01;
        assert_ne!(base, EkFingerprint::of_ek_pub(&flipped));
        // Length is part of the input: 32 vs 33 bytes must not collide.
        let longer = [0x11u8; 33];
        assert_ne!(base, EkFingerprint::of_ek_pub(&longer));
    }

    #[test]
    fn empty_input_is_distinct() {
        // Hashing is total over all inputs; non-emptiness is enforced
        // upstream at the registration/activation boundary.
        assert_ne!(
            EkFingerprint::of_ek_pub(&[]),
            EkFingerprint::of_ek_pub(&ek_pub(0x00))
        );
    }

    #[test]
    fn domain_separated_from_other_core_ids() {
        let fp = EkFingerprint::of_ek_pub(b"acme");
        let grant =
            crate::operator::OperatorGrantId::of_grant("acme", "acme", 0, 0, false, false, &[]);
        assert_ne!(fp.as_bytes(), grant.as_bytes());
    }

    #[test]
    fn hex_roundtrip() {
        let fp = EkFingerprint::of_ek_pub(&ek_pub(0x2a));
        let hex = fp.to_hex();
        assert_eq!(hex.len(), 32);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        );
        assert_eq!(EkFingerprint::from_hex(&hex), Some(fp));
        assert_eq!(hex.parse::<EkFingerprint>().ok(), Some(fp));
        assert_eq!(EkFingerprint::from_hex(&hex.to_uppercase()), Some(fp));
        assert!(EkFingerprint::from_hex("nothex").is_none());
        assert!(EkFingerprint::from_hex(&"0".repeat(31)).is_none());
    }
}
