// SPDX-License-Identifier: Apache-2.0
//! TPM 2.0 client I/O and server-side credential activation primitives.
//!
//! Feature-gated behind `tpm`. Decoupled from control-plane configuration;
//! callers pass a `TpmEndpoint` to select the backend (hardware device, swtpm,
//! or mssim simulator).

/// Errors from TSS operations.
#[derive(Debug, thiserror::Error)]
pub enum TssError {
    #[error("tss-esapi error: {0}")]
    Esapi(String),
    #[error("invalid EK public key: {0}")]
    InvalidEk(String),
    #[error("invalid AK public key: {0}")]
    InvalidAk(String),
}

/// TPM backend endpoint descriptor.
///
/// Replaces control's `TpmConfig` at the core boundary so core never imports
/// control types. The enum-with-data form makes impossible states unrepresentable
/// (a `Device` endpoint has no host/port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpmEndpoint {
    /// Hardware TPM via the kernel resource manager.
    Device { path: String },
    /// Software TPM (`swtpm`) over a TCP socket.
    Swtpm { host: String, port: u16 },
    /// Microsoft TPM simulator over a TCP socket.
    Mssim { host: String, port: u16 },
}

use std::str::FromStr;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{Digest, Name};

/// Build the TCTI configuration string from a `TpmEndpoint`.
fn build_tcti_name_conf(endpoint: &TpmEndpoint) -> Result<tss_esapi::TctiNameConf, TssError> {
    let tcti_str = match endpoint {
        TpmEndpoint::Device { path } => format!("device:{}", path),
        TpmEndpoint::Swtpm { host, port } => format!("swtpm:host={},port={}", host, port),
        TpmEndpoint::Mssim { host, port } => format!("mssim:host={},port={}", host, port),
    };
    tss_esapi::TctiNameConf::from_str(&tcti_str)
        .map_err(|e| TssError::Esapi(format!("TCTI parse failed: {}", e)))
}

/// Create a `tss_esapi::Context` bound to the given endpoint.
fn create_context(endpoint: &TpmEndpoint) -> Result<tss_esapi::Context, TssError> {
    let tcti = build_tcti_name_conf(endpoint)?;
    tss_esapi::Context::new(tcti).map_err(|e| TssError::Esapi(e.to_string()))
}

/// TPM2_MakeCredential: encrypt `secret` to the EK public key, binding it to
/// the AK's name. Returns `(credential_blob, encrypted_secret)`.
pub fn make_credential(
    endpoint: &TpmEndpoint,
    ek_spki_der: &[u8],
    ak_pub: &[u8],
    secret: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), TssError> {
    let mut context = create_context(endpoint)?;
    let ek_public = spki_to_tpm_public(ek_spki_der)?;

    // The AK's Name is nameAlg || H(TPMT_PUBLIC) — a remote verifier needs
    // no TPM access to derive it, and MakeCredential binds the credential
    // to this Name. Loading the AK into the server TPM is unnecessary.
    let ak_name = compute_ak_name(ak_pub)?;

    // External public keys go into the Null hierarchy: they are not descendants of
    // this TPM's hierarchy primaries. load_external_public passes a true null
    // pointer for inPrivate, signaling a public-only load to the TPM.
    let ek_handle = context
        .load_external_public(ek_public, Hierarchy::Null)
        .map_err(|e| TssError::Esapi(format!("load EK failed: {}", e)))?;

    let credential = Digest::try_from(secret.to_vec())
        .map_err(|e| TssError::Esapi(format!("digest failed: {}", e)))?;

    let (id_object, enc_secret) = context
        .make_credential(ek_handle, credential, ak_name)
        .map_err(|e| TssError::Esapi(format!("make_credential failed: {}", e)))?;

    Ok((id_object.value().to_vec(), enc_secret.value().to_vec()))
}

/// Canonical TPM Name of an object from its marshaled TPMT_PUBLIC:
/// `nameAlg || H(TPMT_PUBLIC)` (TPM 2.0 Part 1 §16), where `H` is the hash
/// algorithm named by the `nameAlg` field embedded in the TPMT_PUBLIC itself.
///
/// Reads `nameAlg` from the TPMT_PUBLIC rather than assuming SHA-256, so the
/// Name stays correct even if the AK template's `name_hashing_algorithm`
/// changes. Hashes across the SHA-2 family (available via `sha2`); anything
/// we cannot hash (SHA-1, SM3, SHA-3) or any unknown value fails closed.
fn compute_ak_name(tpmt_public: &[u8]) -> Result<Name, TssError> {
    use sha2::Digest;

    // TPMT_PUBLIC layout: type(2) nameAlg(2) objectAttributes(4) authPolicy(2+n) ...
    // Need at least type(2) + nameAlg(2) to read the nameAlg.
    if tpmt_public.len() < 4 {
        return Err(TssError::InvalidAk(
            "TPMT_PUBLIC too short to contain nameAlg".to_owned(),
        ));
    }
    let name_alg = u16::from_be_bytes([tpmt_public[2], tpmt_public[3]]);

    // Dispatch on the embedded nameAlg. Fleet config is SHA-256 (ak_template),
    // but we handle the full SHA-2 family so a template change within that
    // family stays correct; everything else fails closed.
    let digest: Vec<u8> = match name_alg {
        0x000B => sha2::Sha256::digest(tpmt_public).to_vec(), // TPM_ALG_SHA256
        0x000C => sha2::Sha384::digest(tpmt_public).to_vec(), // TPM_ALG_SHA384
        0x000D => sha2::Sha512::digest(tpmt_public).to_vec(), // TPM_ALG_SHA512
        0x0004 => {
            return Err(TssError::InvalidAk(
                "unsupported nameAlg SHA-1 (0x0004): fleet requires a SHA-2 nameAlg".to_owned(),
            ));
        }
        other => {
            return Err(TssError::InvalidAk(format!(
                "unsupported or unknown nameAlg 0x{:04X}",
                other
            )));
        }
    };

    let mut name = Vec::with_capacity(2 + digest.len());
    name.extend_from_slice(&name_alg.to_be_bytes());
    name.extend_from_slice(&digest);
    Name::try_from(name).map_err(|e| TssError::InvalidAk(format!("AK name: {}", e)))
}

/// Convert an EK public key in SPKI DER (RFC 5280) to a tss-esapi `Public`.
fn spki_to_tpm_public(spki_der: &[u8]) -> Result<tss_esapi::structures::Public, TssError> {
    use spki::SubjectPublicKeyInfoRef;
    use spki::der::Decode;
    use tss_esapi::attributes::ObjectAttributes;
    use tss_esapi::interface_types::algorithm::{HashingAlgorithm, SymmetricMode};
    use tss_esapi::interface_types::key_bits::{AesKeyBits, RsaKeyBits};
    use tss_esapi::structures::{
        Public, PublicKeyRsa, PublicRsaParameters, RsaExponent, RsaScheme,
        SymmetricDefinitionObject,
    };

    const RSA_OID: spki::ObjectIdentifier =
        spki::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TssError::InvalidEk(format!("SPKI parse failed: {}", e)))?;

    if spki.algorithm.oid != RSA_OID {
        return Err(TssError::InvalidEk(
            "only RSA EKs are supported for MakeCredential".to_owned(),
        ));
    }

    let (modulus, exponent) = parse_rsa_public_key(spki.subject_public_key.raw_bytes())?;

    let key_bits = match modulus.len() * 8 {
        2048 => RsaKeyBits::Rsa2048,
        3072 => RsaKeyBits::Rsa3072,
        other => {
            return Err(TssError::InvalidEk(format!(
                "unsupported RSA EK size: {}",
                other
            )));
        }
    };

    let object_attributes = ObjectAttributes::builder()
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .map_err(|e| TssError::InvalidEk(format!("object attributes: {}", e)))?;

    Ok(Public::Rsa {
        object_attributes,
        name_hashing_algorithm: HashingAlgorithm::Sha256,
        auth_policy: Default::default(),
        parameters: PublicRsaParameters::new(
            SymmetricDefinitionObject::Aes {
                key_bits: AesKeyBits::Aes128,
                mode: SymmetricMode::Cfb,
            },
            RsaScheme::Null,
            key_bits,
            RsaExponent::try_from(exponent)
                .map_err(|e| TssError::InvalidEk(format!("exponent: {}", e)))?,
        ),
        unique: PublicKeyRsa::try_from(modulus)
            .map_err(|e| TssError::InvalidEk(format!("modulus: {}", e)))?,
    })
}

/// Parse a DER RSAPublicKey (SEQUENCE { modulus INTEGER, exponent INTEGER })
/// into (modulus bytes, exponent u32).
fn parse_rsa_public_key(der: &[u8]) -> Result<(Vec<u8>, u32), TssError> {
    if der.is_empty() || der[0] != 0x30 {
        return Err(TssError::InvalidEk("expected SEQUENCE".into()));
    }
    let (_seq_len, mut offset) = parse_der_length(&der[1..])?;
    offset += 1;

    if der.len() <= offset || der[offset] != 0x02 {
        return Err(TssError::InvalidEk("expected INTEGER for modulus".into()));
    }
    let (mod_len, mod_len_bytes) = parse_der_length(&der[offset + 1..])?;
    offset += 1 + mod_len_bytes;

    let mut modulus = der[offset..offset + mod_len].to_vec();
    if modulus.len() > 1 && modulus[0] == 0 {
        modulus.remove(0); // Strip leading sign byte
    }
    offset += mod_len;

    if der.len() <= offset || der[offset] != 0x02 {
        return Err(TssError::InvalidEk("expected INTEGER for exponent".into()));
    }
    let (exp_len, exp_len_bytes) = parse_der_length(&der[offset + 1..])?;
    offset += 1 + exp_len_bytes;

    let exp_bytes = &der[offset..offset + exp_len];
    let mut exponent: u32 = 0;
    for &b in exp_bytes {
        exponent = (exponent << 8) | b as u32;
    }
    if exponent == 65537 {
        exponent = 0; // TPM uses 0 to represent the default exponent (65537)
    }

    Ok((modulus, exponent))
}

fn parse_der_length(bytes: &[u8]) -> Result<(usize, usize), TssError> {
    if bytes.is_empty() {
        return Err(TssError::InvalidEk("unexpected end of DER".into()));
    }
    let b = bytes[0];
    if b < 0x80 {
        Ok((b as usize, 1))
    } else {
        let n = (b & 0x7f) as usize;
        if n == 0 || n > 4 || bytes.len() < 1 + n {
            return Err(TssError::InvalidEk("invalid DER length".into()));
        }
        let mut len = 0usize;
        for i in 1..=n {
            len = (len << 8) | bytes[i] as usize;
        }
        Ok((len, 1 + n))
    }
}

// ================= CR-14 Addendum A: node-side credential activation =================
use crate::attestation::PcrValue;
use tss_esapi::traits::Marshall;

/// Output of TPM2_Quote.
#[derive(Debug, Clone)]
pub struct QuoteOutput {
    pub quote: Vec<u8>,
    pub signature: Vec<u8>,
    pub pcr_values: Vec<PcrValue>,
}

pub struct AttestationSession {
    context: tss_esapi::Context,
    ak_handle: tss_esapi::handles::KeyHandle,
    ek_handle: tss_esapi::handles::KeyHandle,
    ak_pub: Vec<u8>,
    ek_spki: Vec<u8>,
}

impl AttestationSession {
    pub fn begin(endpoint: &TpmEndpoint) -> Result<Self, TssError> {
        use tss_esapi::interface_types::resource_handles::Hierarchy;

        let mut context = create_context(endpoint)?;

        let ek_public = ek_template()?;
        let ek_result = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Endorsement, ek_public, None, None, None, None)
            })
            .map_err(|e| TssError::Esapi(format!("create EK primary failed: {}", e)))?;
        let ek_handle = ek_result.key_handle;

        let (ek_modulus, ek_exponent) = extract_rsa_public(&ek_result.out_public)?;
        let ek_spki = rsa_public_to_spki(&ek_modulus, ek_exponent);

        let ak_public = ak_template()?;
        let ak_result = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Endorsement, ak_public, None, None, None, None)
            })
            .map_err(|e| TssError::Esapi(format!("create AK primary failed: {}", e)))?;
        let ak_handle = ak_result.key_handle;

        let ak_pub = ak_result
            .out_public
            .marshall()
            .map_err(|e| TssError::InvalidAk(format!("marshal AK public failed: {}", e)))?;

        Ok(Self {
            context,
            ak_handle,
            ek_handle,
            ak_pub,
            ek_spki,
        })
    }

    pub fn ak_pub(&self) -> Result<Vec<u8>, TssError> {
        Ok(self.ak_pub.clone())
    }

    pub fn read_ek_cert(&mut self) -> Result<Option<Vec<u8>>, TssError> {
        use tss_esapi::handles::NvIndexHandle;
        use tss_esapi::interface_types::resource_handles::NvAuth;

        // tss-esapi 7.7.0 allows direct construction from the u32 index.
        let nv_handle = NvIndexHandle::from(0x01C0_0002u32);

        match self.context.nv_read(NvAuth::Owner, nv_handle, 2048, 0) {
            Ok(data) => Ok(Some(data.value().to_vec())),
            Err(_) => Ok(None),
        }
    }

    pub fn ek_pub(&self) -> Result<Vec<u8>, TssError> {
        Ok(self.ek_spki.clone())
    }

    pub fn activate(&mut self, credential_blob: &[u8], secret: &[u8]) -> Result<Vec<u8>, TssError> {
        use tss_esapi::constants::SessionType;
        use tss_esapi::interface_types::algorithm::{HashingAlgorithm, SymmetricMode};
        use tss_esapi::interface_types::key_bits::AesKeyBits;
        use tss_esapi::interface_types::resource_handles::Hierarchy;
        use tss_esapi::interface_types::session_handles::AuthSession;
        use tss_esapi::structures::{
            Digest, EncryptedSecret, IdObject, Nonce, SymmetricDefinition,
        };

        let id_object = IdObject::try_from(credential_blob.to_vec())
            .map_err(|e| TssError::Esapi(format!("bad credentialBlob: {}", e)))?;
        let enc_secret = EncryptedSecret::try_from(secret.to_vec())
            .map_err(|e| TssError::Esapi(format!("bad secret: {}", e)))?;
        let ak_handle = self.ak_handle;
        let ek_handle = self.ek_handle;

        // 1. Start a policy session for the EK (Template L-1 authPolicy).
        let ek_policy_auth_session = self
            .context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::Aes {
                    key_bits: AesKeyBits::Aes128,
                    mode: SymmetricMode::Cfb,
                },
                HashingAlgorithm::Sha256,
            )
            .map_err(|e| TssError::Esapi(format!("start ek policy session: {}", e)))?
            .ok_or_else(|| TssError::Esapi("failed to allocate ek policy session".into()))?;

        // 2. Convert AuthSession → PolicySession for policy_secret.
        let ek_policy_session =
            ek_policy_auth_session
                .try_into()
                .map_err(|e: tss_esapi::Error| {
                    TssError::Esapi(format!("policy session convert: {}", e))
                })?;

        // 3. Satisfy the EK's authPolicy: PolicySecret(TPM_RH_ENDORSEMENT).
        let endorsement_auth: tss_esapi::handles::AuthHandle =
            tss_esapi::handles::ObjectHandle::from(Hierarchy::Endorsement).into();

        self.context
            .execute_with_nullauth_session(|ctx| {
                ctx.policy_secret(
                    ek_policy_session,
                    endorsement_auth,
                    Nonce::default(),
                    Digest::default(),
                    Nonce::default(),
                    None,
                )
            })
            .map_err(|e| TssError::Esapi(format!("policy secret failed: {}", e)))?;

        // 4. Set sessions for ActivateCredential:
        //    Session 1 (AK): Password (userWithAuth=true, empty authValue).
        //    Session 2 (EK): The satisfied policy session.
        self.context.set_sessions((
            Some(AuthSession::Password),
            Some(ek_policy_auth_session),
            None,
        ));

        let recovered = self
            .context
            .activate_credential(ak_handle, ek_handle, id_object, enc_secret)
            .map_err(|e| TssError::Esapi(format!("activate_credential failed: {}", e)))?;

        // SECURITY/STABILITY: Clear sessions to flush the EK policy session from
        // the TPM. Failing to do so leaks TPM session handles (causing
        // TPM2_RC_SESSION_HANDLES / 0x98B on subsequent operations) and leaves
        // the context in a confused state that breaks TPM2_Quote's auth session.
        self.context.set_sessions((None, None, None));

        Ok(recovered.value().to_vec())
    }

    pub fn quote(
        &mut self,
        server_nonce: &[u8],
        pcr_indices: &[u8],
    ) -> Result<QuoteOutput, TssError> {
        use tss_esapi::interface_types::algorithm::HashingAlgorithm;
        use tss_esapi::structures::{Data, PcrSelectionListBuilder, PcrSlot, SignatureScheme};

        let slots: Vec<PcrSlot> = pcr_indices
            .iter()
            .map(|&i| pcr_slot_from_index(i))
            .collect::<Result<Vec<_>, _>>()?;

        let selection = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &slots)
            .build()
            .map_err(|e| TssError::Esapi(format!("bad PCR selection: {}", e)))?;

        let qualifying: Data = server_nonce
            .to_vec()
            .try_into()
            .map_err(|e| TssError::Esapi(format!("bad nonce: {}", e)))?;

        let ak_handle = self.ak_handle;
        let (attest, signature) = self
            .context
            .execute_with_nullauth_session(move |ctx| {
                ctx.quote(ak_handle, qualifying, SignatureScheme::Null, selection)
            })
            .map_err(|e| TssError::Esapi(format!("TPM2_Quote failed: {}", e)))?;

        let quote_bytes = attest
            .marshall()
            .map_err(|e| TssError::Esapi(format!("marshal attest failed: {}", e)))?;

        let pcr_values = self.read_pcr_values(pcr_indices)?;

        Ok(QuoteOutput {
            quote: quote_bytes,
            signature: marshal_signature(&signature)?,
            pcr_values,
        })
    }

    fn read_pcr_values(&mut self, pcr_indices: &[u8]) -> Result<Vec<PcrValue>, TssError> {
        use tss_esapi::interface_types::algorithm::HashingAlgorithm;
        use tss_esapi::structures::{PcrSelectionListBuilder, PcrSlot};

        let slots: Vec<PcrSlot> = pcr_indices
            .iter()
            .map(|&i| pcr_slot_from_index(i))
            .collect::<Result<Vec<_>, _>>()?;

        let selection = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &slots)
            .build()
            .map_err(|e| TssError::Esapi(format!("bad PCR selection: {}", e)))?;

        let (_, _, pcr_data) = self
            .context
            .pcr_read(selection)
            .map_err(|e| TssError::Esapi(format!("PCR read failed: {}", e)))?;

        let digests = pcr_data.value();
        let mut out = Vec::new();
        for (i, &idx) in pcr_indices.iter().enumerate() {
            if i < digests.len() {
                out.push(PcrValue {
                    index: idx,
                    hash_algorithm: 0x000B,
                    digest: digests[i].value().to_vec(),
                });
            }
        }
        Ok(out)
    }
}

/// Map a PCR index (0–23) to the tss-esapi `PcrSlot` variant.
///
/// Deliberately avoids `PcrSlot::try_from`: the `TryFrom<u32>` impl in
/// tss-esapi 7.7.0 rejects index 0 at runtime ("the provided parameter is
/// invalid for that type"), and the enum-literal mapping is immune to any
/// future conversion-trait drift.
fn pcr_slot_from_index(i: u8) -> Result<tss_esapi::structures::PcrSlot, TssError> {
    use tss_esapi::structures::PcrSlot;
    match i {
        0 => Ok(PcrSlot::Slot0),
        1 => Ok(PcrSlot::Slot1),
        2 => Ok(PcrSlot::Slot2),
        3 => Ok(PcrSlot::Slot3),
        4 => Ok(PcrSlot::Slot4),
        5 => Ok(PcrSlot::Slot5),
        6 => Ok(PcrSlot::Slot6),
        7 => Ok(PcrSlot::Slot7),
        8 => Ok(PcrSlot::Slot8),
        9 => Ok(PcrSlot::Slot9),
        10 => Ok(PcrSlot::Slot10),
        11 => Ok(PcrSlot::Slot11),
        12 => Ok(PcrSlot::Slot12),
        13 => Ok(PcrSlot::Slot13),
        14 => Ok(PcrSlot::Slot14),
        15 => Ok(PcrSlot::Slot15),
        16 => Ok(PcrSlot::Slot16),
        17 => Ok(PcrSlot::Slot17),
        18 => Ok(PcrSlot::Slot18),
        19 => Ok(PcrSlot::Slot19),
        20 => Ok(PcrSlot::Slot20),
        21 => Ok(PcrSlot::Slot21),
        22 => Ok(PcrSlot::Slot22),
        23 => Ok(PcrSlot::Slot23),
        other => Err(TssError::Esapi(format!(
            "PCR index {} out of range 0-23",
            other
        ))),
    }
}

// ---- templates ----
/// Standard EK Credential Profile (Template L-1) authPolicy for RSA-2048 EK.
const EK_AUTH_POLICY: [u8; 32] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
    0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
];

fn ek_template() -> Result<tss_esapi::structures::Public, TssError> {
    use tss_esapi::attributes::ObjectAttributes;
    use tss_esapi::interface_types::algorithm::{HashingAlgorithm, SymmetricMode};
    use tss_esapi::interface_types::key_bits::{AesKeyBits, RsaKeyBits};
    use tss_esapi::structures::{
        Public, PublicKeyRsa, PublicRsaParameters, RsaExponent, RsaScheme,
        SymmetricDefinitionObject,
    };

    let attrs = ObjectAttributes::builder()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_admin_with_policy(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .map_err(|e| TssError::InvalidEk(format!("EK attrs: {}", e)))?;

    Ok(Public::Rsa {
        object_attributes: attrs,
        name_hashing_algorithm: HashingAlgorithm::Sha256,
        auth_policy: EK_AUTH_POLICY
            .to_vec()
            .try_into()
            .map_err(|e| TssError::InvalidEk(format!("EK authPolicy: {}", e)))?,
        parameters: PublicRsaParameters::new(
            SymmetricDefinitionObject::Aes {
                key_bits: AesKeyBits::Aes128,
                mode: SymmetricMode::Cfb,
            },
            RsaScheme::Null,
            RsaKeyBits::Rsa2048,
            RsaExponent::try_from(0u32)
                .map_err(|e| TssError::InvalidEk(format!("EK exponent: {}", e)))?,
        ),
        unique: PublicKeyRsa::try_from(vec![0u8; 256])
            .map_err(|e| TssError::InvalidEk(format!("EK unique: {}", e)))?,
    })
}

/// Encode an RSA public key as canonical SubjectPublicKeyInfo DER (RFC 5280).
fn rsa_public_to_spki(modulus: &[u8], exponent: u32) -> Vec<u8> {
    fn der_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else {
            let mut bytes = Vec::new();
            let mut l = len;
            while l > 0 {
                bytes.insert(0, (l & 0xff) as u8);
                l >>= 8;
            }
            let mut out = vec![0x80 | bytes.len() as u8];
            out.extend(bytes);
            out
        }
    }
    fn der_integer(mut v: &[u8]) -> Vec<u8> {
        while v.len() > 1 && v[0] == 0 {
            v = &v[1..];
        }
        let mut body = Vec::new();
        if v[0] & 0x80 != 0 {
            body.push(0);
        }
        body.extend_from_slice(v);
        let mut out = vec![0x02];
        out.extend(der_len(body.len()));
        out.extend(body);
        out
    }
    fn der_seq(body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x30];
        out.extend(der_len(body.len()));
        out.extend(body);
        out
    }
    fn der_bitstring(body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x03];
        out.extend(der_len(body.len() + 1));
        out.push(0);
        out.extend(body);
        out
    }

    let rsa_oid: [u8; 11] = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    let null: [u8; 2] = [0x05, 0x00];
    let mut alg = Vec::new();
    alg.extend_from_slice(&rsa_oid);
    alg.extend_from_slice(&null);
    let alg_seq = der_seq(&alg);

    let mod_int = der_integer(modulus);
    let exp_int = der_integer(&exponent.to_be_bytes());
    let mut rsa_key = Vec::new();
    rsa_key.extend(mod_int);
    rsa_key.extend(exp_int);
    let rsa_seq = der_seq(&rsa_key);

    let mut spki_body = Vec::new();
    spki_body.extend(alg_seq);
    spki_body.extend(der_bitstring(&rsa_seq));
    der_seq(&spki_body)
}

fn ak_template() -> Result<tss_esapi::structures::Public, TssError> {
    use tss_esapi::attributes::ObjectAttributes;
    use tss_esapi::interface_types::algorithm::HashingAlgorithm; // dropped SymmetricMode
    use tss_esapi::interface_types::ecc::EccCurve; // dropped AesKeyBits import
    use tss_esapi::structures::{
        EccScheme, HashScheme, KeyDerivationFunctionScheme, Public, PublicEccParameters,
        SymmetricDefinitionObject,
    };
    let attrs = ObjectAttributes::builder()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_sign_encrypt(true)
        .build()
        .map_err(|e| TssError::InvalidAk(format!("AK attrs: {}", e)))?;
    Ok(Public::Ecc {
        object_attributes: attrs,
        name_hashing_algorithm: HashingAlgorithm::Sha256,
        auth_policy: Default::default(),
        parameters: PublicEccParameters::new(
            SymmetricDefinitionObject::Null,
            EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
            EccCurve::NistP256,
            KeyDerivationFunctionScheme::Null,
        ),
        unique: Default::default(),
    })
}

fn extract_rsa_public(public: &tss_esapi::structures::Public) -> Result<(Vec<u8>, u32), TssError> {
    match public {
        tss_esapi::structures::Public::Rsa {
            unique, parameters, ..
        } => {
            let exp = parameters.exponent().value();
            let exp = if exp == 0 { 65537 } else { exp };
            Ok((unique.value().to_vec(), exp))
        }
        _ => Err(TssError::InvalidEk("expected RSA EK public".into())),
    }
}

// rsa_public_to_spki remains unchanged from the previous turn...

fn marshal_signature(sig: &tss_esapi::structures::Signature) -> Result<Vec<u8>, TssError> {
    use tss_esapi::structures::Signature;
    fn pad32(v: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 32usize.saturating_sub(v.len())];
        out.extend_from_slice(v);
        out
    }
    match sig {
        Signature::EcDsa(ecd) => {
            let mut out = Vec::with_capacity(64);
            out.extend(pad32(ecd.signature_r().value()));
            out.extend(pad32(ecd.signature_s().value()));
            Ok(out)
        }
        Signature::RsaSsa(rsa) => Ok(rsa.signature().value().to_vec()),
        _ => Err(TssError::Esapi("unsupported quote signature scheme".into())),
    }
}

#[cfg(test)]
mod compute_ak_name_tests {
    use super::*;

    /// Minimal marshaled TPMT_PUBLIC: type(2) || nameAlg(2) || trailing bytes.
    fn tpmt_public_with_name_alg(name_alg: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0x0023u16.to_be_bytes()); // type = ECC
        b.extend_from_slice(&name_alg.to_be_bytes());
        b.extend_from_slice(&[0u8; 32]); // hashed as part of the Name
        b
    }

    #[test]
    fn sha256_name_alg_is_accepted() {
        assert!(compute_ak_name(&tpmt_public_with_name_alg(0x000B)).is_ok());
    }

    #[test]
    fn sha384_name_alg_is_accepted() {
        assert!(compute_ak_name(&tpmt_public_with_name_alg(0x000C)).is_ok());
    }

    #[test]
    fn sha512_name_alg_is_accepted() {
        assert!(compute_ak_name(&tpmt_public_with_name_alg(0x000D)).is_ok());
    }

    #[test]
    fn sha1_name_alg_is_rejected() {
        assert!(compute_ak_name(&tpmt_public_with_name_alg(0x0004)).is_err());
    }

    #[test]
    fn unknown_name_alg_is_rejected() {
        assert!(compute_ak_name(&tpmt_public_with_name_alg(0xFFFF)).is_err());
    }

    #[test]
    fn too_short_buffer_is_rejected() {
        assert!(compute_ak_name(&[0x00, 0x23]).is_err());
    }
}
