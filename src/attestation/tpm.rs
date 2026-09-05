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
