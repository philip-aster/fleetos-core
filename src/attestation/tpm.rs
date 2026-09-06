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
    let ak_public = unmarshal_ak_public(ak_pub)?;

    let ek_sensitive = empty_sensitive_for(&ek_public)?;
    let ek_handle = context
        .load_external(ek_sensitive, ek_public, Hierarchy::Endorsement)
        .map_err(|e| TssError::Esapi(format!("load EK failed: {}", e)))?;

    let ak_sensitive = empty_sensitive_for(&ak_public)?;
    let ak_handle = context
        .load_external(ak_sensitive, ak_public, Hierarchy::Null)
        .map_err(|e| TssError::Esapi(format!("load AK failed: {}", e)))?;

    let ak_name: Name = context
        .tr_get_name(ak_handle.into())
        .map_err(|e| TssError::Esapi(format!("get AK name failed: {}", e)))?;

    let credential = Digest::try_from(secret.to_vec())
        .map_err(|e| TssError::Esapi(format!("digest failed: {}", e)))?;

    let (id_object, enc_secret) = context
        .make_credential(ek_handle, credential, ak_name)
        .map_err(|e| TssError::Esapi(format!("make_credential failed: {}", e)))?;

    Ok((id_object.value().to_vec(), enc_secret.value().to_vec()))
}

/// Convert an EK public key in SPKI DER (RFC 5280) to a tss-esapi `Public`.
fn spki_to_tpm_public(spki_der: &[u8]) -> Result<tss_esapi::structures::Public, TssError> {
    use spki::SubjectPublicKeyInfoRef;
    use spki::der::Decode;
    use tss_esapi::attributes::ObjectAttributes;
    use tss_esapi::interface_types::algorithm::HashingAlgorithm;
    use tss_esapi::interface_types::key_bits::RsaKeyBits;
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
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_admin_with_policy(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .map_err(|e| TssError::InvalidEk(format!("object attributes: {}", e)))?;

    Ok(Public::Rsa {
        object_attributes,
        name_hashing_algorithm: HashingAlgorithm::Sha256,
        auth_policy: Default::default(),
        parameters: PublicRsaParameters::new(
            SymmetricDefinitionObject::Null,
            RsaScheme::Null,
            key_bits,
            RsaExponent::try_from(exponent)
                .map_err(|e| TssError::InvalidEk(format!("exponent: {}", e)))?,
        ),
        unique: PublicKeyRsa::try_from(modulus)
            .map_err(|e| TssError::InvalidEk(format!("modulus: {}", e)))?,
    })
}

/// Unmarshal the AK public key (TPM2B_PUBLIC bytes) into a tss-esapi `Public`.
fn unmarshal_ak_public(ak_pub: &[u8]) -> Result<tss_esapi::structures::Public, TssError> {
    use tss_esapi::tss2_esys::{TPM2B_PUBLIC, Tss2_MU_TPM2B_PUBLIC_Unmarshal};

    let mut dest: TPM2B_PUBLIC = unsafe { std::mem::zeroed() };
    let mut offset: u64 = 0;
    let rc = unsafe {
        Tss2_MU_TPM2B_PUBLIC_Unmarshal(ak_pub.as_ptr(), ak_pub.len() as u64, &mut offset, &mut dest)
    };
    if rc != 0 {
        return Err(TssError::InvalidAk(format!(
            "TPM2B_PUBLIC unmarshal failed, rc={:#x}",
            rc
        )));
    }
    tss_esapi::structures::Public::try_from(dest).map_err(|e| {
        TssError::InvalidAk(format!("TPM2B_PUBLIC -> Public conversion failed: {}", e))
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

/// Build a structurally-valid but empty `Sensitive` for a public-only
/// `load_external`.
fn empty_sensitive_for(
    public: &tss_esapi::structures::Public,
) -> Result<tss_esapi::structures::Sensitive, TssError> {
    use tss_esapi::structures::{Public, Sensitive};
    match public {
        Public::Rsa { .. } => Ok(Sensitive::Rsa {
            auth_value: Default::default(),
            seed_value: Default::default(),
            sensitive: Default::default(),
        }),
        Public::Ecc { .. } => Ok(Sensitive::Ecc {
            auth_value: Default::default(),
            seed_value: Default::default(),
            sensitive: Default::default(),
        }),
        _ => Err(TssError::InvalidEk(
            "unsupported EK/AK key type for load_external".to_owned(),
        )),
    }
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
            .create_primary(Hierarchy::Endorsement, ek_public, None, None, None, None)
            .map_err(|e| TssError::Esapi(format!("create EK primary failed: {}", e)))?;
        let ek_handle = ek_result.key_handle;

        let (ek_modulus, ek_exponent) = extract_rsa_public(&ek_result.out_public)?;
        let ek_spki = rsa_public_to_spki(&ek_modulus, ek_exponent);

        let ak_public = ak_template()?;
        let ak_result = context
            .create_primary(Hierarchy::Endorsement, ak_public, None, None, None, None)
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
        use tss_esapi::structures::{EncryptedSecret, IdObject};

        let id_object = IdObject::try_from(credential_blob.to_vec())
            .map_err(|e| TssError::Esapi(format!("bad credentialBlob: {}", e)))?;
        let enc_secret = EncryptedSecret::try_from(secret.to_vec())
            .map_err(|e| TssError::Esapi(format!("bad secret: {}", e)))?;

        let recovered = self
            .context
            .activate_credential(self.ak_handle, self.ek_handle, id_object, enc_secret)
            .map_err(|e| TssError::Esapi(format!("activate_credential failed: {}", e)))?;
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
            .map(|&i| {
                PcrSlot::try_from(i as u32)
                    .map_err(|e| TssError::Esapi(format!("bad PCR slot {}: {}", i, e)))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let selection = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &slots)
            .build()
            .map_err(|e| TssError::Esapi(format!("bad PCR selection: {}", e)))?;

        let qualifying: Data = server_nonce
            .to_vec()
            .try_into()
            .map_err(|e| TssError::Esapi(format!("bad nonce: {}", e)))?;

        let (attest, signature) = self
            .context
            .quote(self.ak_handle, qualifying, SignatureScheme::Null, selection)
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
            .map(|&i| {
                PcrSlot::try_from(i as u32)
                    .map_err(|e| TssError::Esapi(format!("bad PCR slot {}: {}", i, e)))
            })
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
    use tss_esapi::interface_types::algorithm::{HashingAlgorithm, SymmetricMode};
    use tss_esapi::interface_types::ecc::EccCurve;
    use tss_esapi::interface_types::key_bits::AesKeyBits;
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
            SymmetricDefinitionObject::Aes {
                key_bits: AesKeyBits::Aes128,
                mode: SymmetricMode::Cfb,
            },
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
