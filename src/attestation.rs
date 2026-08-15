// SPDX-License-Identifier: Apache-2.0
//! Hardware-rooted attestation traits and types.

use crate::nonce::Nonce;
use crate::spiffe::SpiffeId;
use async_trait::async_trait;
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

// ... backend implementations remain structurally the same ...
