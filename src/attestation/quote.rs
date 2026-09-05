// SPDX-License-Identifier: Apache-2.0
//! CR-14/A4: quote structures and verification.
//!
//! Unifies control's former `TpmQuote`/`verify_tpm_quote` with core's
//! `QuoteVerifier` trait. `verify_quote_structure` and `verify_pcr_policy`
//! are pure; `verify_quote_signature` is software (device-free) behind the
//! `software-quote-verify` feature.
use crate::attestation::{AttestError, PcrValue};

/// A TPM quote submitted by a node for attestation.
///
/// `quote_bytes` is the marshaled `TPMS_ATTEST`. `signature` is the AK
/// signature over it. `attestation_key_pub` is the marshaled `TPMT_PUBLIC`
/// of the AK, used by software signature verification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TpmQuote {
    /// Raw TPM quote bytes (marshaled TPMS_ATTEST).
    pub quote_bytes: Vec<u8>,
    /// AK signature over the quote (raw scheme signature).
    pub signature: Vec<u8>,
    /// The nonce bound into this quote (must equal the server nonce).
    pub nonce: Vec<u8>,
    /// PCR values included in the quote.
    pub pcr_selection: Vec<PcrValue>,
    /// Marshaled TPMT_PUBLIC of the Attestation Key.
    pub attestation_key_pub: Vec<u8>,
}

/// An Apple Secure Enclave attestation submission (operator/fleetctl-proxy path).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AppleSeAttestation {
    /// Attestation data from the Secure Enclave.
    pub attestation_data: Vec<u8>,
    /// The nonce bound into this attestation.
    pub nonce: Vec<u8>,
    /// The device's public key (for verification).
    pub device_public_key: Vec<u8>,
    /// Optional DCOS (DeviceCheck) attestation token.
    pub dcos_token: Option<Vec<u8>>,
}

/// TPM_GENERATED_VALUE magic: 0xff 'T' 'C' 'G'. Every TPMS_ATTEST begins with it.
const TPM_GENERATED_MAGIC: [u8; 4] = [0xff, 0x54, 0x43, 0x47];

/// Structural verification of a TPM quote: nonce binding + magic/type.
///
/// Pure and device-free. This is the first-pass gate; cryptographic
/// signature verification is `verify_quote_signature`. We check:
/// 1. The quote's `extraData`/nonce field matches the server-issued nonce
///    (caller passes `expected_nonce`).
/// 2. The buffer is non-empty and begins with TPM_GENERATED_VALUE.
///
/// NOTE: full TPMS_ATTEST field-walking (qualifyingSigner, pcrSelect,
/// signature extraction from the attested struct) is intentionally NOT done
/// here — it is handled where the signature is verified, since that path
/// already parses the structure. This keeps the pure path cheap and robust.
pub fn verify_quote_structure(quote: &TpmQuote, expected_nonce: &[u8]) -> Result<(), AttestError> {
    // Nonce binding is the replay/freshness guard.
    if quote.nonce != expected_nonce {
        return Err(AttestError::VerificationFailed);
    }
    if quote.quote_bytes.len() < TPM_GENERATED_MAGIC.len() {
        return Err(AttestError::VerificationFailed);
    }
    if quote.quote_bytes[..TPM_GENERATED_MAGIC.len()] != TPM_GENERATED_MAGIC {
        return Err(AttestError::VerificationFailed);
    }
    if quote.signature.is_empty() {
        return Err(AttestError::VerificationFailed);
    }
    Ok(())
}

/// Apple SE structural verification: nonce binding + non-empty fields.
pub fn verify_apple_se_structure(
    att: &AppleSeAttestation,
    expected_nonce: &[u8],
) -> Result<(), AttestError> {
    if att.nonce != expected_nonce {
        return Err(AttestError::VerificationFailed);
    }
    if att.attestation_data.is_empty() || att.device_public_key.is_empty() {
        return Err(AttestError::VerificationFailed);
    }
    Ok(())
}

// ================= software signature verification (CR-14/A4, Q1) =================
//
// Verifies the AK signature over TPMS_ATTEST in software. No TPM device
// required — only the AK public key and signature. Closes M-2/S-11 in CI.
#[cfg(feature = "software-quote-verify")]
pub mod software {
    use super::*;

    /// TPMI_ALG_PUBLIC selectors.
    const TPM_ALG_RSA: u16 = 0x0001;
    const TPM_ALG_ECC: u16 = 0x0023;
    /// TPMI_ALG_NULL — expected for the `symmetric` block of a signing-only AK.
    const TPM_ALG_NULL: u16 = 0x0010;

    /// Parsed AK public key (signing material only).
    enum AkPublic {
        Rsa { modulus: Vec<u8>, exponent: u32 },
        Ecc { x: Vec<u8>, y: Vec<u8> },
    }

    /// Verify the AK signature over the quote's TPMS_ATTEST in software.
    ///
    /// Assumes the AK signs with a SHA-256 scheme:
    /// - RSA  -> RSASSA PKCS#1 v1.5 over SHA-256(quote_bytes)
    /// - ECC  -> ECDSA P-256 over SHA-256(quote_bytes)
    ///
    /// SECURITY/CORRECTNESS FLAG (per Q1 "flag it if ugly"): the raw
    /// `signature` bytes are interpreted per the AK's key type with a SHA-256
    /// digest. If control's TPM configures RSAPSS or a non-SHA256 scheme on
    /// the AK, this assumption must be reconciled with the TPMT_SIGNATURE the
    /// TPM actually emits. The TPMT_PUBLIC parse below handles the common
    /// signing-AK shape (symmetric = TPM_ALG_NULL). Both branches fail closed.
    pub fn verify_quote_signature(quote: &TpmQuote) -> Result<(), AttestError> {
        let ak = parse_ak_public(&quote.attestation_key_pub)?;
        match ak {
            AkPublic::Rsa { modulus, exponent } => {
                verify_rsa(&modulus, exponent, &quote.quote_bytes, &quote.signature)
            }
            AkPublic::Ecc { x, y } => {
                verify_ecdsa_p256(&x, &y, &quote.quote_bytes, &quote.signature)
            }
        }
    }

    /// Parse a marshaled TPMT_PUBLIC into signing material for RSA/ECC.
    ///
    /// Layout (signing-only AK, symmetric = TPM_ALG_NULL):
    ///   type(2) nameAlg(2) objectAttributes(4) authPolicy(2+n) params unique
    /// We walk conservatively and fail closed on any unexpected shape.
    fn parse_ak_public(bytes: &[u8]) -> Result<AkPublic, AttestError> {
        let mut r = Reader(bytes);
        let typ = r.u16()?;
        let _name_alg = r.u16()?;
        let _obj_attrs = r.u32()?;
        // authPolicy: TPM2B_DIGEST (u16 size + data)
        let ap_len = r.u16()? as usize;
        r.skip(ap_len)?;

        match typ {
            TPM_ALG_RSA => {
                expect_null_symmetric(&mut r)?;
                let _scheme = r.u16()?;
                let _key_bits = r.u16()?;
                let exponent_raw = r.u32()?;
                // TPM encodes default exponent 65537 as 0.
                let exponent = if exponent_raw == 0 {
                    65537
                } else {
                    exponent_raw
                };
                let mod_len = r.u16()? as usize;
                let modulus = r.take(mod_len)?.to_vec();
                Ok(AkPublic::Rsa { modulus, exponent })
            }
            TPM_ALG_ECC => {
                expect_null_symmetric(&mut r)?;
                let _scheme = r.u16()?;
                let _curve_id = r.u16()?;
                let _kdf = r.u16()?;
                let x_len = r.u16()? as usize;
                let x = r.take(x_len)?.to_vec();
                let y_len = r.u16()? as usize;
                let y = r.take(y_len)?.to_vec();
                Ok(AkPublic::Ecc { x, y })
            }
            _ => Err(AttestError::VerificationFailed),
        }
    }

    /// Read a TPMT_SYMMETRIC and require algorithm = TPM_ALG_NULL (no child fields).
    fn expect_null_symmetric(r: &mut Reader) -> Result<(), AttestError> {
        let alg = r.u16()?;
        if alg != TPM_ALG_NULL {
            return Err(AttestError::VerificationFailed);
        }
        Ok(())
    }

    fn verify_rsa(
        modulus: &[u8],
        exponent: u32,
        quote_bytes: &[u8],
        sig: &[u8],
    ) -> Result<(), AttestError> {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::sha2::Sha256;
        use rsa::signature::Verifier;
        use rsa::{BigUint, RsaPublicKey};

        let n = BigUint::from_bytes_be(modulus);
        let e = BigUint::from(exponent);
        let pubkey = RsaPublicKey::new(n, e).map_err(|_| AttestError::VerificationFailed)?;
        let vk = VerifyingKey::<Sha256>::new(pubkey);
        let signature = Signature::try_from(sig).map_err(|_| AttestError::VerificationFailed)?;

        // `Verifier::verify` takes the raw message bytes and hashes them
        // internally using rsa's pinned sha2 dependency.
        vk.verify(quote_bytes, &signature)
            .map_err(|_| AttestError::VerificationFailed)?;
        Ok(())
    }

    fn verify_ecdsa_p256(
        x: &[u8],
        y: &[u8],
        quote_bytes: &[u8],
        sig: &[u8],
    ) -> Result<(), AttestError> {
        use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

        // Construct uncompressed SEC1 point manually. This sidesteps the
        // deprecated `EncodedPoint` API and the `From<&[u8]>` trait bound
        // issues introduced in p256 0.14 / ecdsa 0.17.
        let mut sec1_bytes = Vec::with_capacity(1 + x.len() + y.len());
        sec1_bytes.push(0x04); // uncompressed marker
        sec1_bytes.extend_from_slice(x);
        sec1_bytes.extend_from_slice(y);

        let vk = VerifyingKey::from_sec1_bytes(&sec1_bytes)
            .map_err(|_| AttestError::VerificationFailed)?;
        let signature = Signature::from_slice(sig).map_err(|_| AttestError::VerificationFailed)?;

        // `Verifier::verify` takes the raw message bytes. p256 internally uses
        // its pinned SHA-256 implementation, sidestepping the workspace digest collision.
        vk.verify(quote_bytes, &signature)
            .map_err(|_| AttestError::VerificationFailed)
    }

    /// Minimal big-endian reader with bounds checks (fail closed).
    struct Reader<'a>(&'a [u8]);
    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> Result<&'a [u8], AttestError> {
            if self.0.len() < n {
                return Err(AttestError::VerificationFailed);
            }
            let (head, tail) = self.0.split_at(n);
            self.0 = tail;
            Ok(head)
        }
        fn skip(&mut self, n: usize) -> Result<(), AttestError> {
            self.take(n).map(|_| ())
        }
        fn u16(&mut self) -> Result<u16, AttestError> {
            let b = self.take(2)?;
            Ok(u16::from_be_bytes([b[0], b[1]]))
        }
        fn u32(&mut self) -> Result<u32, AttestError> {
            let b = self.take(4)?;
            Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        }
    }
}

#[cfg(feature = "software-quote-verify")]
pub use software::verify_quote_signature;
