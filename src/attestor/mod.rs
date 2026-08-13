// Node Attestation Trait Abstraction

pub mod mock;
pub mod tpm2;

use crate::spiffe::IdentityError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationPayload {
    pub public_identity_key: Vec<u8>,
    pub signature_quote: Vec<u8>,
    pub pcr_values: Vec<PcrEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PcrEntry {
    pub pcr_index: u32,
    pub digest: Vec<u8>,
    pub algorithm: String, // e.g., "sha256" or "sha384"
}

impl PcrEntry {
    pub fn new_sha256(pcr_index: u32, digest: Vec<u8>) -> Self {
        Self {
            pcr_index,
            digest,
            algorithm: "sha256".to_string(),
        }
    }
}

pub trait HardwareAttestor: Send + Sync {
    /// Generates a hardware quote payload for the given challenge nonce
    fn generate_quote(
        &self,
        nonce: &[u8],
    ) -> impl std::future::Future<Output = Result<AttestationPayload, IdentityError>> + Send;

    /// Verifies an incoming AttestationPayload against the expected nonce
    fn verify_quote(
        &self,
        payload: &AttestationPayload,
        expected_nonce: &[u8],
    ) -> impl std::future::Future<Output = Result<bool, IdentityError>> + Send;

    /// Returns the public identity key of the attestor
    fn public_identity(&self) -> Result<Vec<u8>, IdentityError>;
}
