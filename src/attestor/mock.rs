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

    fn public_identity(&self) -> Result<Vec<u8>, IdentityError> {
        // Return dummy SEC1 uncompressed public key bytes for mock testing
        Ok(vec![0x04; 65])
    }
}
