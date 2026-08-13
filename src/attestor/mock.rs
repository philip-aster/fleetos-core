use crate::attestor::{AttestationPayload, HardwareAttestor, PcrEntry};
use crate::spiffe::IdentityError;

#[derive(Debug, Default, Clone)]
pub struct MockHardwareAttestor;

impl MockHardwareAttestor {
    pub fn new() -> Self {
        Self
    }
}

impl HardwareAttestor for MockHardwareAttestor {
    async fn generate_quote(&self, nonce: &[u8]) -> Result<AttestationPayload, IdentityError> {
        let mock_pcrs = vec![
            PcrEntry::new_sha256(0, vec![0xAA; 32]),
            PcrEntry::new_sha256(1, vec![0xBB; 32]),
            PcrEntry::new_sha256(7, vec![0xCC; 32]),
        ];

        let mut signature = vec![0xDD; 64];
        signature.extend_from_slice(nonce);

        Ok(AttestationPayload {
            public_identity_key: self.public_identity()?,
            signature_quote: signature,
            pcr_values: mock_pcrs,
        })
    }

    async fn verify_quote(
        &self,
        payload: &AttestationPayload,
        expected_nonce: &[u8],
    ) -> Result<bool, IdentityError> {
        if payload.signature_quote.len() < 64 + expected_nonce.len() {
            return Ok(false);
        }

        let prefix_valid = payload.signature_quote[..64] == [0xDD; 64];
        let nonce_valid = payload.signature_quote[64..].ends_with(expected_nonce);

        Ok(prefix_valid && nonce_valid)
    }

    fn public_identity(&self) -> Result<Vec<u8>, IdentityError> {
        let mut key = vec![0x04];
        key.extend_from_slice(&[0x01; 32]);
        key.extend_from_slice(&[0x02; 32]);
        Ok(key)
    }
}
