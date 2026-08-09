// fleetos-core/src/attestor/mock.rs

use crate::attestor::{AttestationPayload, HardwareAttestor, PcrEntry};
use crate::spiffe::IdentityError;
use async_trait::async_trait;

#[derive(Debug, Default, Clone)]
pub struct MockHardwareAttestor;

impl MockHardwareAttestor {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl HardwareAttestor for MockHardwareAttestor {
    async fn generate_quote(&self, nonce: &[u8]) -> Result<AttestationPayload, IdentityError> {
        let mock_pcrs = vec![
            PcrEntry {
                pcr_index: 0,
                digest: vec![0xAA; 32],
            },
            PcrEntry {
                pcr_index: 1,
                digest: vec![0xBB; 32],
            },
            PcrEntry {
                pcr_index: 7,
                digest: vec![0xCC; 32],
            },
        ];

        let mut signature = vec![0xDD; 64];
        signature.extend_from_slice(nonce);

        Ok(AttestationPayload {
            public_identity_key: self.public_identity()?,
            signature_quote: signature,
            pcr_values: mock_pcrs,
        })
    }

    // Add inside the `#[async_trait] impl HardwareAttestor for MockHardwareAttestor` block:

    async fn verify_quote(
        &self,
        payload: &AttestationPayload,
        expected_nonce: &[u8],
    ) -> Result<bool, IdentityError> {
        // Validate that the signature quote contains the mock prefix and ends with the nonce
        let starts_valid = payload.signature_quote.starts_with(&[0xDD; 64]);
        let ends_valid = payload.signature_quote.ends_with(expected_nonce);

        Ok(starts_valid && ends_valid)
    }

    fn public_identity(&self) -> Result<Vec<u8>, IdentityError> {
        // Return dummy SEC1 uncompressed public key bytes for mock testing
        Ok(vec![0x04; 65])
    }
}
