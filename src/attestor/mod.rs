// Node Attestation Trait Abstraction

pub mod mock;
pub mod tpm2;

use crate::spiffe::IdentityError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationPayload {
    pub public_identity_key: Vec<u8>,
    pub signature_quote: Vec<u8>,
    pub pcr_values: Vec<PcrEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrEntry {
    pub pcr_index: u32,
    pub digest: Vec<u8>,
}

#[async_trait]
pub trait HardwareAttestor: Send + Sync {
    /// Generates a hardware quote payload for the given nonce
    async fn generate_quote(&self, nonce: &[u8]) -> Result<AttestationPayload, IdentityError>;
    /// Verifies an incoming AttestationPayload against the expected nonce
    async fn verify_quote(
        &self,
        payload: &AttestationPayload,
        expected_nonce: &[u8],
    ) -> Result<bool, IdentityError>;
    /// Returns the public identity key of the attestor
    fn public_identity(&self) -> Result<Vec<u8>, IdentityError>;
}
