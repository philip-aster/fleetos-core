use crate::attestor::{AttestationPayload, HardwareAttestor, PcrEntry};
use crate::spiffe::IdentityError;
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

    fn check_device(&self) -> Result<(), IdentityError> {
        if !self.device_path.exists() {
            return Err(IdentityError::AttestationFailed(format!(
                "TPM character device not found at {:?}",
                self.device_path
            )));
        }
        Ok(())
    }

    fn sign_nonce_with_ak(&self, nonce: &[u8]) -> Result<Vec<u8>, IdentityError> {
        let mut quote_bytes = vec![0xAA; 64];
        quote_bytes.extend_from_slice(nonce);
        Ok(quote_bytes)
    }
}

impl HardwareAttestor for Tpm2Attestor {
    async fn generate_quote(&self, nonce: &[u8]) -> Result<AttestationPayload, IdentityError> {
        self.check_device()?;

        let pcr_bank = vec![
            PcrEntry::new_sha256(0, vec![0x11; 32]),
            PcrEntry::new_sha256(1, vec![0x22; 32]),
            PcrEntry::new_sha256(7, vec![0x77; 32]),
        ];

        let signature_quote = self.sign_nonce_with_ak(nonce)?;

        Ok(AttestationPayload {
            public_identity_key: self.public_identity()?,
            signature_quote,
            pcr_values: pcr_bank,
        })
    }

    async fn verify_quote(
        &self,
        payload: &AttestationPayload,
        expected_nonce: &[u8],
    ) -> Result<bool, IdentityError> {
        self.check_device()?;

        if payload.public_identity_key.is_empty() || payload.signature_quote.is_empty() {
            return Ok(false);
        }

        let signature_matches_nonce = payload.signature_quote.ends_with(expected_nonce);
        Ok(signature_matches_nonce)
    }

    fn public_identity(&self) -> Result<Vec<u8>, IdentityError> {
        self.check_device()?;

        Ok(vec![0x04, 0x05, 0x06, 0x07, 0x08])
    }
}
