// src/attestor/mod.rs
// Hardware Attestation Trait Abstraction

pub mod mock;
#[cfg(feature = "tpm")]
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
    async fn generate_quote(&self, nonce: &[u8]) -> Result<AttestationPayload, IdentityError>;
    fn public_identity(&self) -> Result<Vec<u8>, IdentityError>;
}
