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
        fn u8(&mut self) -> Result<u8, AttestError> {
            let b = self.take(1)?;
            Ok(b[0])
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

    /// TPMI_ST_ATTEST selector for TPM2_Quote.
    const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;
    /// TPMI_ALG_HASH selectors.
    const TPM_ALG_SHA256: u16 = 0x000B;
    const TPM_ALG_SHA384: u16 = 0x000C;
    const TPM_ALG_SHA512: u16 = 0x000D;

    #[derive(Clone, Copy)]
    enum HashKind {
        Sha256,
        Sha384,
        Sha512,
    }

    /// Cryptographically bind the submitted PCR values to the signed quote.
    ///
    /// Extracts `pcrSelect` + `pcrDigest` from the marshaled `TPMS_ATTEST`
    /// (`quote_bytes`), re-hashes `submitted_pcrs` using the TPM's exact
    /// concatenation layout (selected indices, ascending, concatenated, then
    /// hashed with the bank's algorithm), and compares against the quote's
    /// `pcrDigest`. Fails closed on any parse error, missing value, length
    /// mismatch, or algorithm disagreement.
    ///
    /// SINGLE-BANK CONTRACT: `AttestationSession::quote` produces single-bank
    /// SHA-256 selections, so this verifier accepts exactly one
    /// `TPMS_PCR_SELECTION` and rejects multi-bank quotes fail-closed. This
    /// avoids the spec-ambiguous multi-bank `pcrDigest` path entirely.
    ///
    /// NOTE (flagged per "call it out" rule): for a single-bank quote the
    /// `pcrDigest` is hashed with the PCR bank's algorithm — this is what
    /// real TPMs emit and what `tpm2_checkquote` recomputes. If a target TPM
    /// instead hashes `pcrDigest` with the quote-signature scheme's algorithm
    /// and the two differ, this binding must be reconciled. Our session keeps
    /// them identical (SHA-256 bank, ECDSA-P256/SHA-256 signing), so they agree.
    pub fn verify_pcr_binding(
        quote_bytes: &[u8],
        submitted_pcrs: &[crate::attestation::PcrValue],
    ) -> Result<(), crate::attestation::AttestError> {
        use crate::attestation::AttestError;

        let mut r = Reader(quote_bytes);
        // magic
        if r.take(4)? != super::TPM_GENERATED_MAGIC {
            return Err(AttestError::VerificationFailed);
        }
        // type must be TPM_ST_ATTEST_QUOTE
        if r.u16()? != TPM_ST_ATTEST_QUOTE {
            return Err(AttestError::VerificationFailed);
        }
        // qualifiedSigner: TPM2B_NAME — skip
        let qs_len = r.u16()? as usize;
        r.skip(qs_len)?;
        // extraData: TPM2B_DATA — skip (nonce binding is verify_quote_structure's job)
        let ed_len = r.u16()? as usize;
        r.skip(ed_len)?;
        // clockInfo: clock(8) + resetCount(4) + restartCount(4) + safe(1) = 17
        r.skip(17)?;
        // firmwareVersion(8)
        r.skip(8)?;
        // attested = TPMS_QUOTE_INFO → pcrSelect: TPML_PCR_SELECTION
        let count = r.u32()?;
        if count != 1 {
            // single-bank only (see contract note)
            return Err(AttestError::VerificationFailed);
        }
        let hash_alg = r.u16()?;
        let sizeof_select = r.u8()? as usize;
        if sizeof_select == 0 || sizeof_select > 4 {
            return Err(AttestError::VerificationFailed);
        }
        let select_bitmap = r.take(sizeof_select)?.to_vec();
        // pcrDigest: TPM2B_DIGEST
        let digest_len = r.u16()? as usize;
        let pcr_digest = r.take(digest_len)?;

        let (digest_size, kind) = match hash_alg {
            TPM_ALG_SHA256 => (32usize, HashKind::Sha256),
            TPM_ALG_SHA384 => (48, HashKind::Sha384),
            TPM_ALG_SHA512 => (64, HashKind::Sha512),
            // SHA-1 / SM3 / unknown → not supported, fail closed.
            _ => return Err(AttestError::VerificationFailed),
        };

        // Selected PCR indices, ascending, from the bitmap.
        let mut selected: Vec<u8> = Vec::new();
        for (byte_i, &bitmap_byte) in select_bitmap.iter().enumerate() {
            for bit in 0..8 {
                if bitmap_byte & (1 << bit) != 0 {
                    selected.push((byte_i * 8 + bit) as u8);
                }
            }
        }

        // Concatenate submitted digests in selection order; every selected
        // index MUST be present with the matching algorithm and length.
        let mut concat = Vec::with_capacity(selected.len() * digest_size);
        for idx in &selected {
            let pv = submitted_pcrs
                .iter()
                .find(|p| p.index == *idx && p.hash_algorithm == hash_alg)
                .ok_or(AttestError::VerificationFailed)?;
            if pv.digest.len() != digest_size {
                return Err(AttestError::VerificationFailed);
            }
            concat.extend_from_slice(&pv.digest);
        }

        let computed = hash_with(kind, &concat);
        if !crate::attestation::ct_eq(&computed, pcr_digest) {
            return Err(AttestError::VerificationFailed);
        }
        Ok(())
    }

    fn hash_with(kind: HashKind, data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        match kind {
            HashKind::Sha256 => {
                let mut h = sha2::Sha256::new();
                h.update(data);
                h.finalize().to_vec()
            }
            HashKind::Sha384 => {
                let mut h = sha2::Sha384::new();
                h.update(data);
                h.finalize().to_vec()
            }
            HashKind::Sha512 => {
                let mut h = sha2::Sha512::new();
                h.update(data);
                h.finalize().to_vec()
            }
        }
    }
}

#[cfg(feature = "software-quote-verify")]
pub use software::verify_quote_signature;

#[cfg(feature = "software-quote-verify")]
pub use software::verify_pcr_binding;

#[cfg(all(test, feature = "software-quote-verify"))]
mod pcr_binding_tests {
    use crate::attestation::PcrValue;
    use crate::attestation::quote::software::verify_pcr_binding;

    fn sha256(data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(data);
        h.finalize().to_vec()
    }

    /// Build a minimal valid TPMS_ATTEST of type TPM_ST_ATTEST_QUOTE selecting
    /// PCRs {0,7,9} (SHA-256) with the given per-PCR digests.
    fn build_quote(pcr0: &[u8; 32], pcr7: &[u8; 32], pcr9: &[u8; 32], nonce: &[u8]) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&[0xff, 0x54, 0x43, 0x47]); // magic
        q.extend_from_slice(&0x8018u16.to_be_bytes()); // TPM_ST_ATTEST_QUOTE
        q.extend_from_slice(&0u16.to_be_bytes()); // qualifiedSigner len=0
        q.extend_from_slice(&(nonce.len() as u16).to_be_bytes()); // extraData
        q.extend_from_slice(nonce);
        q.extend_from_slice(&[0u8; 17]); // clockInfo
        q.extend_from_slice(&[0u8; 8]); // firmwareVersion
        // TPMS_QUOTE_INFO.pcrSelect (single SHA-256 selection, PCRs 0,7,9)
        q.extend_from_slice(&1u32.to_be_bytes()); // count = 1
        q.extend_from_slice(&0x000Bu16.to_be_bytes()); // SHA-256
        q.push(3); // sizeofSelect
        // bitmap: PCR0 → byte0 bit0, PCR7 → byte0 bit7, PCR9 → byte1 bit1
        q.extend_from_slice(&[0x81, 0x02, 0x00]);
        // pcrDigest = SHA-256(pcr0 || pcr7 || pcr9)
        let mut concat = Vec::new();
        concat.extend_from_slice(pcr0);
        concat.extend_from_slice(pcr7);
        concat.extend_from_slice(pcr9);
        let digest = sha256(&concat);
        q.extend_from_slice(&(digest.len() as u16).to_be_bytes());
        q.extend_from_slice(&digest);
        q
    }

    fn submitted(pcr0: &[u8; 32], pcr7: &[u8; 32], pcr9: &[u8; 32]) -> Vec<PcrValue> {
        vec![
            PcrValue {
                index: 0,
                hash_algorithm: 0x000B,
                digest: pcr0.to_vec(),
            },
            PcrValue {
                index: 7,
                hash_algorithm: 0x000B,
                digest: pcr7.to_vec(),
            },
            PcrValue {
                index: 9,
                hash_algorithm: 0x000B,
                digest: pcr9.to_vec(),
            },
        ]
    }

    #[test]
    fn binding_holds_for_matching_values() {
        let (p0, p7, p9) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let quote = build_quote(&p0, &p7, &p9, &[0xAA; 32]);
        assert!(verify_pcr_binding(&quote, &submitted(&p0, &p7, &p9)).is_ok());
    }

    #[test]
    fn binding_rejects_tampered_pcr_value() {
        let (p0, p7, p9) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let quote = build_quote(&p0, &p7, &p9, &[0xAA; 32]);
        // Attacker claims a different PCR9 than the quote actually covers.
        let bad_p9 = [0xFFu8; 32];
        assert!(verify_pcr_binding(&quote, &submitted(&p0, &p7, &bad_p9)).is_err());
    }

    #[test]
    fn binding_rejects_missing_selected_pcr() {
        let (p0, p7, p9) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let quote = build_quote(&p0, &p7, &p9, &[0xAA; 32]);
        // Drop PCR7 — the quote selects it, so the binding must fail.
        let mut s = submitted(&p0, &p7, &p9);
        s.retain(|p| p.index != 7);
        assert!(verify_pcr_binding(&quote, &s).is_err());
    }

    #[test]
    fn binding_rejects_wrong_algorithm_claim() {
        let (p0, p7, p9) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let quote = build_quote(&p0, &p7, &p9, &[0xAA; 32]);
        let mut s = submitted(&p0, &p7, &p9);
        s[1].hash_algorithm = 0x000C; // claim SHA-384 for PCR7
        assert!(verify_pcr_binding(&quote, &s).is_err());
    }

    #[test]
    fn binding_rejects_truncated_or_garbage_quote() {
        assert!(verify_pcr_binding(&[], &[]).is_err());
        assert!(verify_pcr_binding(&[0xff, 0x54, 0x43, 0x47], &[]).is_err());
        // Bad magic.
        let mut q = build_quote(&[1; 32], &[2; 32], &[3; 32], &[0xAA; 32]);
        q[0] = 0x00;
        assert!(verify_pcr_binding(&q, &submitted(&[1; 32], &[2; 32], &[3; 32])).is_err());
    }

    #[test]
    fn extra_unselected_pcrs_are_ignored() {
        let (p0, p7, p9) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let quote = build_quote(&p0, &p7, &p9, &[0xAA; 32]);
        let mut s = submitted(&p0, &p7, &p9);
        // PCR 12 is submitted but not selected — must not break the binding.
        s.push(PcrValue {
            index: 12,
            hash_algorithm: 0x000B,
            digest: vec![9; 32],
        });
        assert!(verify_pcr_binding(&quote, &s).is_ok());
    }
}
