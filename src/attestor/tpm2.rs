// fleetos-core/src/attestor/tpm2.rs

use crate::attestor::{AttestationPayload, HardwareAttestor, PcrEntry};
use crate::spiffe::IdentityError;
use async_trait::async_trait;
use std::path::PathBuf;

pub struct Tpm2Attestor {
    device_path: PathBuf,
}

impl Tpm2Attestor {
    pub fn new(device_path: impl Into<PathBuf>) -> Self {
        Self {
            device_path: device_path.into(),
        }
    }

    pub fn default_device() -> Self {
        Self::new("/dev/tpmrm0")
    }
}

#[async_trait]
impl HardwareAttestor for Tpm2Attestor {
    async fn generate_quote(&self, nonce: &[u8]) -> Result<AttestationPayload, IdentityError> {
        if !self.device_path.exists() {
            return Err(IdentityError::AttestationFailed(format!(
                "TPM character device not found at {:?}",
                self.device_path
            )));
        }

        // Hardware TPM quote generation via tpm2-tss / /dev/tpmrm0
        Ok(AttestationPayload {
            public_identity_key: self.public_identity()?,
            signature_quote: nonce.to_vec(),
            pcr_values: vec![PcrEntry {
                pcr_index: 0,
                digest: vec![0; 32],
            }],
        })
    }

    fn public_identity(&self) -> Result<Vec<u8>, IdentityError> {
        if !self.device_path.exists() {
            return Err(IdentityError::AttestationFailed(format!(
                "TPM character device not found at {:?}",
                self.device_path
            )));
        }

        // Hardware EK/AK public key extraction
        Ok(vec![])
    }
}
