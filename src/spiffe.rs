// SPDX-License-Identifier: Apache-2.0
//! SPIFFE Identity and X.509 SVID construction.

use core::cmp::Ordering;
use core::convert::TryFrom;
use core::fmt;
use core::str::FromStr;
// Re-export Zeroizing so the struct definition above compiles cleanly
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "grpc")]
use tracing::warn;
use zeroize::Zeroizing;

#[cfg(not(feature = "grpc"))]
macro_rules! warn {
    (target: $target:expr, $($arg:tt)*) => {};
    ($($arg:tt)*) => {};
}
#[cfg(not(feature = "grpc"))]
use warn;

/// FleetOS IANA Private Enterprise Number (PEN).
pub const FLEETOS_IANA_PEN: u64 = 66561;

// Custom OID Arcs under the FleetOS PEN
pub const FLEETOS_ROLE_OID: &str = "1.3.6.1.4.1.66561.1.1";
pub const FLEETOS_DEGRADED_OID: &str = "1.3.6.1.4.1.66561.1.2";
pub const FLEETOS_ORDINAL_OID: &str = "1.3.6.1.4.1.66561.1.3";

// Raw DER OID bytes for `1.3.6.1.4.1.66561.1.*`
// 66561 encodes to 0x84, 0x88, 0x01 in base-128 DER.
const FLEETOS_ROLE_OID_BYTES: [u8; 10] =
    [0x2B, 0x06, 0x01, 0x04, 0x01, 0x84, 0x88, 0x01, 0x01, 0x01];
const FLEETOS_DEGRADED_OID_BYTES: [u8; 10] =
    [0x2B, 0x06, 0x01, 0x04, 0x01, 0x84, 0x88, 0x01, 0x01, 0x02];
const FLEETOS_ORDINAL_OID_BYTES: [u8; 10] =
    [0x2B, 0x06, 0x01, 0x04, 0x01, 0x84, 0x88, 0x01, 0x01, 0x03];

// OID arcs under the FleetOS PEN as base-128 component lists. Single source
// for both the readers (DER byte constants above) and the writers (ca-gated
// builders below). CR-CORE-12 dedupe: control's former `ca/oid.rs`
// re-declared these arcs independently and is deleted in favor of these.
pub const FLEETOS_ROLE_OID_ARC: &[u64] = &[1, 3, 6, 1, 4, 1, FLEETOS_IANA_PEN, 1, 1];
pub const FLEETOS_DEGRADED_OID_ARC: &[u64] = &[1, 3, 6, 1, 4, 1, FLEETOS_IANA_PEN, 1, 2];
pub const FLEETOS_ORDINAL_OID_ARC: &[u64] = &[1, 3, 6, 1, 4, 1, FLEETOS_IANA_PEN, 1, 3];

/// DER length prefix (short form < 128, else one/two-byte long form).
#[cfg(feature = "ca")]
fn der_len_prefix(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

/// Build the workload-role extension. Value is a DER UTF8String — the exact
/// shape `extract_role` parses (tag 0x0C). Writer/reader convergence is the
/// point of CR-CORE-12's dedupe: the old control-side builder wrote raw
/// bytes that `extract_role` could not parse.
#[cfg(feature = "ca")]
pub fn role_extension(role: &str) -> rcgen::CustomExtension {
    let bytes = role.as_bytes();
    let mut value = Vec::with_capacity(2 + bytes.len());
    value.push(0x0C); // UTF8String
    value.extend_from_slice(&der_len_prefix(bytes.len()));
    value.extend_from_slice(bytes);
    let mut ext = rcgen::CustomExtension::from_oid_content(FLEETOS_ROLE_OID_ARC, value);
    ext.set_criticality(false);
    ext
}

/// Build the degraded-mode marker. Value is a DER BOOLEAN — the exact shape
/// `is_degraded` parses (tag 0x01). Unchanged from control's builder.
#[cfg(feature = "ca")]
pub fn degraded_extension(is_degraded: bool) -> rcgen::CustomExtension {
    let value = if is_degraded {
        vec![0x01, 0x01, 0xFF]
    } else {
        vec![0x01, 0x01, 0x00]
    };
    let mut ext = rcgen::CustomExtension::from_oid_content(FLEETOS_DEGRADED_OID_ARC, value);
    ext.set_criticality(false);
    ext
}

/// Build the ordinal extension. Value is a DER INTEGER — the exact shape
/// `extract_ordinal` parses (tag 0x02). Minimal big-endian encoding with a
/// 0x00 pad when the high bit is set (positive-integer rule).
#[cfg(feature = "ca")]
pub fn ordinal_extension(ordinal: u32) -> rcgen::CustomExtension {
    let bytes = ordinal.to_be_bytes();
    let mut start = 0usize;
    while start < 3 && bytes[start] == 0 && bytes[start + 1] & 0x80 == 0 {
        start += 1;
    }
    let significant = &bytes[start..];
    let pad = significant[0] & 0x80 != 0;
    let len = significant.len() + usize::from(pad);
    let mut value = Vec::with_capacity(2 + len);
    value.push(0x02); // INTEGER
    value.push(len as u8);
    if pad {
        value.push(0x00);
    }
    value.extend_from_slice(significant);
    let mut ext = rcgen::CustomExtension::from_oid_content(FLEETOS_ORDINAL_OID_ARC, value);
    ext.set_criticality(false);
    ext
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum SvidError {
    #[error("invalid SPIFFE ID format")]
    InvalidFormat,
    #[error("invalid SPIFFE ID kind")]
    InvalidKind,
    #[error("certificate validation failed")]
    ValidationFailed,
    #[error("feature not implemented")]
    Unimplemented,
    #[error("delegation key expired")]
    DelegationKeyExpired,
    #[error("target SVID mismatch")]
    TargetSvidMismatch,
    #[error("ordinal mismatch")]
    OrdinalMismatch,
    #[error("validity overrun")]
    ValidityOverrun,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum RoleError {
    #[error("role contains embedded NUL byte")]
    EmbeddedNul,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IdKind {
    Sa,
    Node,
    Router,
    Gateway,
    Ctrl,
    Control,
    Operator,
}

impl fmt::Display for IdKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdKind::Sa => write!(f, "sa"),
            IdKind::Node => write!(f, "node"),
            IdKind::Router => write!(f, "router"),
            IdKind::Gateway => write!(f, "gateway"),
            IdKind::Ctrl => write!(f, "ctrl"),
            IdKind::Control => write!(f, "control"),
            IdKind::Operator => write!(f, "operator"),
        }
    }
}

impl FromStr for IdKind {
    type Err = SvidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sa" => Ok(IdKind::Sa),
            "node" => Ok(IdKind::Node),
            "router" => Ok(IdKind::Router),
            "gateway" => Ok(IdKind::Gateway),
            "ctrl" => Ok(IdKind::Ctrl),
            "control" => Ok(IdKind::Control),
            "operator" => Ok(IdKind::Operator),
            _ => Err(SvidError::InvalidKind),
        }
    }
}

/// Helper to map IdKind to static byte slice for zero-allocation hashing
pub(crate) fn kind_to_bytes(kind: &IdKind) -> &'static [u8] {
    match kind {
        IdKind::Sa => b"sa",
        IdKind::Node => b"node",
        IdKind::Router => b"router",
        IdKind::Gateway => b"gateway",
        IdKind::Ctrl => b"ctrl",
        IdKind::Control => b"control",
        IdKind::Operator => b"operator",
    }
}

/// `spiffe://<trust-domain>/ns/<tenant>/<kind>/<name>`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpiffeId {
    pub trust_domain: String,
    pub tenant: String,
    pub kind: IdKind,
    pub name: String,
}

impl SpiffeId {
    pub fn new(
        trust_domain: impl Into<String>,
        tenant: impl Into<String>,
        kind: IdKind,
        name: impl Into<String>,
    ) -> Self {
        Self {
            trust_domain: trust_domain.into(),
            tenant: tenant.into(),
            kind,
            name: name.into(),
        }
    }

    /// Writes the URI bytes directly to a hasher without allocating a String.
    /// Format: `spiffe://<trust-domain>/ns/<tenant>/<kind>/<name>`
    pub fn write_uri_bytes(&self, hasher: &mut blake3::Hasher) {
        hasher.update(b"spiffe://");
        hasher.update(self.trust_domain.as_bytes());
        hasher.update(b"/ns/");
        hasher.update(self.tenant.as_bytes());
        hasher.update(b"/");
        hasher.update(kind_to_bytes(&self.kind));
        hasher.update(b"/");
        hasher.update(self.name.as_bytes());
    }
}

impl Ord for SpiffeId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.trust_domain
            .cmp(&other.trust_domain)
            .then_with(|| self.tenant.cmp(&other.tenant))
            .then_with(|| self.kind.cmp(&other.kind))
            .then_with(|| self.name.cmp(&other.name))
    }
}

impl PartialOrd for SpiffeId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "spiffe://{}/ns/{}/{}/{}",
            self.trust_domain, self.tenant, self.kind, self.name
        )
    }
}

impl FromStr for SpiffeId {
    type Err = SvidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix("spiffe://")
            .ok_or(SvidError::InvalidFormat)?;
        let (trust_domain, path) = rest.split_once("/ns/").ok_or(SvidError::InvalidFormat)?;

        let parts: Vec<&str> = path.splitn(3, '/').collect();
        if parts.len() != 3 {
            return Err(SvidError::InvalidFormat);
        }

        let tenant = parts[0].to_string();
        let kind = parts[1].parse::<IdKind>()?;
        let name = parts[2].to_string();

        Ok(Self {
            trust_domain: trust_domain.to_string(),
            tenant,
            kind,
            name,
        })
    }
}

// Custom Serde implementation to serialize SpiffeId as a flat string
impl Serialize for SpiffeId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SpiffeId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        SpiffeId::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Workload role (e.g., primary, replica). Not part of the URI.
/// Validates against embedded NUL bytes to protect domain-separated hashing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WorkloadRole(String);

impl TryFrom<String> for WorkloadRole {
    type Error = RoleError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.contains('\0') {
            return Err(RoleError::EmbeddedNul);
        }
        Ok(Self(value))
    }
}

impl TryFrom<&str> for WorkloadRole {
    type Error = RoleError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.contains('\0') {
            return Err(RoleError::EmbeddedNul);
        }
        Ok(Self(value.to_string()))
    }
}

impl WorkloadRole {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WorkloadRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a workload instance (post-expansion).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WorkloadId(String);

impl WorkloadId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WorkloadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a pod instance (post-expansion).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PodId(String);

impl PodId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PodId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// --- DER Parsing Helpers ---

/// Parses DER length starting at `bytes[0]`.
/// Returns (length, num_bytes_consumed_for_length_encoding)
fn parse_der_length(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.is_empty() {
        return None;
    }
    let b = bytes[0];
    if b < 0x80 {
        // Short form
        Some((b as usize, 1))
    } else {
        // Long form
        let n = (b & 0x7f) as usize;
        if n == 0 || n > 4 || bytes.len() < 1 + n {
            return None; // Indefinite length or too large, invalid or unsupported
        }
        let mut len = 0usize;
        for i in 1..=n {
            len = (len << 8) | (bytes[i] as usize);
        }
        Some((len, 1 + n))
    }
}

/// Parses a DER Tag-Length-Value structure and returns the value slice.
fn parse_der_tlv<'a>(bytes: &'a [u8], expected_tag: u8) -> Option<&'a [u8]> {
    if bytes.is_empty() || bytes[0] != expected_tag {
        return None;
    }
    let (len, consumed) = parse_der_length(&bytes[1..])?;
    let val_start = 1 + consumed;
    if val_start + len > bytes.len() {
        return None;
    }
    Some(&bytes[val_start..val_start + len])
}

/// Scans DER for an OID and returns the inner OCTET STRING value slice.
/// Properly skips the optional `critical` BOOLEAN and supports long-form lengths.
fn find_oid_extension<'a>(cert_der: &'a [u8], oid: &[u8]) -> Option<&'a [u8]> {
    if cert_der.len() < oid.len() {
        return None;
    }
    for i in 0..=cert_der.len() - oid.len() {
        if cert_der[i..].starts_with(oid) {
            let mut j = i + oid.len();

            // Skip optional BOOLEAN (critical flag, tag 0x01)
            if j < cert_der.len() && cert_der[j] == 0x01 {
                if let Some((len, consumed)) = parse_der_length(&cert_der[j + 1..]) {
                    j += 1 + consumed + len;
                } else {
                    continue;
                }
            }

            // Expect OCTET STRING (extnValue, tag 0x04)
            if j < cert_der.len() && cert_der[j] == 0x04 {
                if let Some((len, consumed)) = parse_der_length(&cert_der[j + 1..]) {
                    let val_start = j + 1 + consumed;
                    if val_start + len <= cert_der.len() {
                        return Some(&cert_der[val_start..val_start + len]);
                    }
                }
            }
        }
    }
    None
}

/// Extracts the role from a DER-encoded X.509 certificate without full parsing.
/// Emits a `warn` log if an extension is found but is corrupt/invalid.
pub fn extract_role(cert_der: &[u8]) -> Option<WorkloadRole> {
    let val = find_oid_extension(cert_der, &FLEETOS_ROLE_OID_BYTES)?;

    let string_bytes = match parse_der_tlv(val, 0x0C).or_else(|| parse_der_tlv(val, 0x13)) {
        Some(bytes) => bytes,
        None => {
            warn!(
                target: "fleetos::spiffe::extract_role",
                "Role extension present in SVID but missing required DER string tag (0x0C or 0x13)."
            );
            return None;
        }
    };

    let role_str = match core::str::from_utf8(string_bytes) {
        Ok(s) => s,
        Err(_) => {
            warn!(
                target: "fleetos::spiffe::extract_role",
                "Role extension present in SVID but contains invalid UTF-8."
            );
            return None;
        }
    };

    match WorkloadRole::try_from(role_str) {
        Ok(role) => Some(role),
        Err(e) => {
            warn!(
                target: "fleetos::spiffe::extract_role",
                error = %e,
                "Role extension present in SVID but failed validation."
            );
            None
        }
    }
}

/// Extracts the ordinal (replica instance) from a DER-encoded X.509 certificate.
pub fn extract_ordinal(cert_der: &[u8]) -> Option<u32> {
    let val = find_oid_extension(cert_der, &FLEETOS_ORDINAL_OID_BYTES)?;
    let int_bytes = parse_der_tlv(val, 0x02)?;
    if int_bytes.len() > 4 {
        return None;
    }
    let mut result = 0u32;
    for &byte in int_bytes {
        result = (result << 8) | byte as u32;
    }
    Some(result)
}

/// Checks for the degraded-mode marker in a DER-encoded X.509 certificate.
pub fn is_degraded(cert_der: &[u8]) -> bool {
    if let Some(val) = find_oid_extension(cert_der, &FLEETOS_DEGRADED_OID_BYTES) {
        if let Some(bool_bytes) = parse_der_tlv(val, 0x01) {
            if !bool_bytes.is_empty() && bool_bytes[0] != 0 {
                return true;
            }
        }
    }
    false
}

/// Extract the SPIFFE identity from a DER-encoded X.509 certificate.
///
/// Parses the certificate with `x509-parser`, locates the SubjectAltName
/// extension, and returns the first URI SAN with a `spiffe://` prefix as a
/// typed `SpiffeId` (kind/tenant validated by the `FromStr` impl).
/// First-match semantics = parity with control's former
/// `extract_spiffe_uri_san`, which this replaces (CR-CORE-12 / B4).
#[cfg(feature = "ca")]
pub fn extract_spiffe_id(cert_der: &[u8]) -> Result<SpiffeId, SvidError> {
    use x509_parser::prelude::*;

    let (_, cert) = parse_x509_certificate(cert_der).map_err(|_| SvidError::InvalidFormat)?;

    let san_ext = cert
        .extensions()
        .iter()
        .find(|ext| {
            matches!(
                ext.parsed_extension(),
                ParsedExtension::SubjectAlternativeName(_)
            )
        })
        .ok_or(SvidError::InvalidFormat)?;

    let san = match san_ext.parsed_extension() {
        ParsedExtension::SubjectAlternativeName(san) => san,
        _ => return Err(SvidError::InvalidFormat),
    };

    let mut spiffe_uri: Option<&str> = None;
    for general_name in &san.general_names {
        if let GeneralName::URI(uri) = general_name {
            if uri.starts_with("spiffe://") {
                spiffe_uri = Some(uri);
                break;
            }
        }
    }

    let uri = spiffe_uri.ok_or(SvidError::InvalidFormat)?;
    uri.parse::<SpiffeId>()
        .map_err(|_| SvidError::InvalidFormat)
}

#[cfg(not(feature = "ca"))]
pub fn extract_spiffe_id(_cert_der: &[u8]) -> Result<SpiffeId, SvidError> {
    Err(SvidError::Unimplemented)
}

/// Trust Bundle is available to ALL nodes, not just the CA.
#[derive(Debug, Clone)]
pub struct TrustBundle {
    pub trust_domain: String,
    pub roots: Vec<Vec<u8>>,
}

/// Validate an SVID against a trust bundle and return its SPIFFE identity.
///
/// Full chain validation via rustls's webpki-backed client-cert verifier:
/// signature verification, validity window, basic constraints, and
/// NameConstraints against the DER roots in the bundle — then the SPIFFE
/// URI SAN is extracted and its trust domain must match the bundle's.
/// Replaces control's former `TrustBundle::validate_svid` (CR-CORE-12 / B3);
/// control keeps bundle lifecycle (rotation, `PreviousRoot` overlap is
/// mapped into `roots` at the boundary) and adapts the result to its
/// `Ok(bool)`/`CaError` shape.
#[cfg(feature = "ca")]
pub fn validate_svid(cert_der: &[u8], trust_bundle: &TrustBundle) -> Result<SpiffeId, SvidError> {
    use rustls::pki_types::{CertificateDer, UnixTime};
    use rustls::server::WebPkiClientVerifier;
    use std::sync::Arc;

    // Install a process-default crypto provider if absent. Binaries install
    // one at startup, but library callers/tests may not; install_default is
    // a no-op if one is already installed.
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    let mut root_store = rustls::RootCertStore::empty();
    for root in &trust_bundle.roots {
        root_store
            .add(CertificateDer::from(root.as_slice()))
            .map_err(|_| SvidError::ValidationFailed)?;
    }

    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|_| SvidError::ValidationFailed)?;

    // Fail-closed on a pre-epoch clock: `now` collapses to epoch 0, every
    // certificate appears not-yet-valid, validation returns an error.
    let now = UnixTime::since_unix_epoch(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default(),
    );

    if verifier
        .verify_client_cert(&CertificateDer::from(cert_der), &[], now)
        .is_err()
    {
        return Err(SvidError::ValidationFailed);
    }

    let spiffe_id = extract_spiffe_id(cert_der)?;
    if spiffe_id.trust_domain != trust_bundle.trust_domain {
        return Err(SvidError::ValidationFailed);
    }

    Ok(spiffe_id)
}

#[cfg(not(feature = "ca"))]
pub fn validate_svid(_cert_der: &[u8], _trust_bundle: &TrustBundle) -> Result<SpiffeId, SvidError> {
    Err(SvidError::Unimplemented)
}

/// A delegated signing key granted to a node for degraded-mode SVID renewal.
///
/// SECURITY MODEL:
///  `intermediate_cert_der`  MUST be issued with standard RFC 5280 `NameConstraints`
/// restricting the URI SAN to the specific trust domain. This provides a true
/// structural backstop: any standards-compliant TLS library will reject SVIDs
/// signed outside that trust domain, even if the agent is compromised.
///
/// Application-level scope guards live in `ca::sign_svid_delegated`: the CSR's
/// SPIFFE URI must byte-match `target_svid_id`, and the role/ordinal
/// extensions are stamped exclusively from `target_role`/`target_ordinal` —
/// there is no caller-supplied channel for either. The 4-hour TTL and
/// `revoked_delegation_ids` broadcast are the blast-radius backstops.
///
/// NOTE (CR-CORE-12 / A6): the former BLAKE3 `DelegationId` type was deleted.
/// The canonical delegation identifier is the composite string
/// `"{node_id}|{target}|{ordinal}|{issued_at}"` documented in `state.proto`
/// and used by control's storage; core never derives a parallel id.
pub struct DelegatedSigningKey {
    pub node_id: SpiffeId,           // The node this key was issued to
    pub target_svid_id: SpiffeId,    // The workload SVID this key is allowed to renew
    pub target_ordinal: Option<u32>, // The exact ordinal it can renew
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub signing_key: Zeroizing<Vec<u8>>, // DER-encoded private key
    pub intermediate_cert_der: Vec<u8>,  // The constrained intermediate CA cert
    /// Workload role stamped into renewed SVIDs. Bound from the matched
    /// placement at issuance, never from the caller (CR-CORE-12 / A5).
    pub target_role: Option<WorkloadRole>,
}

// --- CA Specific Functionality (Only compiled for fleetos-control) ---
#[cfg(feature = "ca")]
pub mod ca {
    use super::*;
    use core::time::Duration;
    use rcgen::KeyPair;

    pub struct Csr {
        pub der: Vec<u8>,
    }

    pub fn build_csr(id: &SpiffeId, keypair: &KeyPair) -> Result<Csr, SvidError> {
        // CSR carries ONLY the SPIFFE URI SAN + standard extensions. Role,
        // ordinal, and degraded are stamped by the CA at signing time (CR-14/A7,
        // Q4) — never embedded in the CSR, so a compromised joiner cannot assert
        // its own role.
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
            .map_err(|_| SvidError::InvalidFormat)?;
        let spiffe_uri: rcgen::string::Ia5String = id
            .to_string()
            .try_into()
            .map_err(|_| SvidError::InvalidFormat)?;
        params
            .subject_alt_names
            .push(rcgen::SanType::URI(spiffe_uri));
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, id.to_string());
        params.distinguished_name = dn;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        params.is_ca = rcgen::IsCa::NoCa;
        let csr = params
            .serialize_request(keypair)
            .map_err(|_| SvidError::InvalidFormat)?;
        Ok(Csr {
            der: csr.der().to_vec(),
        })
    }

    /// Renew an SVID using a delegated signing key — CSR-based, identity-locked.
    ///
    /// CR-CORE-12 / A5 (corrected per the CR-10 invariant): the caller supplies
    /// a CSR and keeps its own private key; this function NEVER generates or
    /// returns key material — it returns the signed leaf certificate DER only.
    ///
    /// Verification sequence, fail-closed at every step:
    /// 1. Delegation-key expiry.
    /// 2. CSR parse. Structural guard: per the `build_csr` contract, rcgen
    ///    rejects CSRs carrying custom extensions, so role/ordinal/degraded
    ///    cannot ride in the CSR.
    /// 3. SAN purity: exactly one SAN, and it must be a `spiffe://` URI.
    ///    Zero, multiple, DNS/IP entries, or non-SPIFFE URIs are rejected.
    /// 4. Scope match: the CSR URI must byte-match `key.target_svid_id`.
    /// 5. Validity window: bounded by the key's remaining lifetime, granted
    ///    from `current_unix_time`.
    /// 6. Stamp and sign: extensions come EXCLUSIVELY from the key's scope —
    ///    `degraded = true`, ordinal from `key.target_ordinal`, role from
    ///    `key.target_role`. A compromised agent holding a valid delegation
    ///    key can renew exactly the SVID+ordinal+role it was delegated for —
    ///    nothing else. Role/ordinal scoping is structurally impossible to
    ///    violate: they have no caller-supplied input channel (`OrdinalMismatch`
    ///    remains in `SvidError` but is unreachable by construction).
    ///
    /// The issuer is built from `key.intermediate_cert_der` + `key.signing_key`;
    /// the returned leaf chains to that intermediate (the wire response's
    /// `cert_chain_der` is this leaf DER — the intermediate travels in the
    /// `DelegatedSigningKey`).
    pub fn sign_svid_delegated(
        key: &DelegatedSigningKey,
        csr_der: &[u8],
        new_validity: Duration,
        current_unix_time: u64,
    ) -> Result<Vec<u8>, SvidError> {
        use rustls::pki_types::{CertificateDer, CertificateSigningRequestDer};

        // 1. Key expiry.
        if key.expires_at_unix <= current_unix_time {
            return Err(SvidError::DelegationKeyExpired);
        }

        // 2. CSR parse.
        let csr_der_type = CertificateSigningRequestDer::from(csr_der);
        let csr_params = rcgen::CertificateSigningRequestParams::from_der(&csr_der_type)
            .map_err(|_| SvidError::InvalidFormat)?;

        // 3. SAN purity: exactly one SAN, a spiffe:// URI.
        if csr_params.params.subject_alt_names.len() != 1 {
            return Err(SvidError::InvalidFormat);
        }
        let csr_uri = match &csr_params.params.subject_alt_names[0] {
            rcgen::SanType::URI(uri) => uri.as_str(),
            _ => return Err(SvidError::InvalidFormat),
        };
        if !csr_uri.starts_with("spiffe://") {
            return Err(SvidError::InvalidFormat);
        }

        // 4. Scope match — byte-exact SpiffeId comparison.
        let csr_spiffe_id: SpiffeId = csr_uri.parse().map_err(|_| SvidError::InvalidFormat)?;
        if csr_spiffe_id != key.target_svid_id {
            return Err(SvidError::TargetSvidMismatch);
        }

        // 5. Validity window — bounded by the key's remaining lifetime.
        let remaining_window = key.expires_at_unix - current_unix_time;
        if new_validity.as_secs() > remaining_window {
            return Err(SvidError::ValidityOverrun);
        }
        let validity_secs = new_validity.as_secs().min(remaining_window);

        // 6. Stamp from the key's scope and sign.
        let mut final_params = csr_params.params;
        final_params
            .custom_extensions
            .push(degraded_extension(true));
        if let Some(role) = &key.target_role {
            final_params
                .custom_extensions
                .push(role_extension(role.as_str()));
        }
        if let Some(ordinal) = key.target_ordinal {
            final_params
                .custom_extensions
                .push(ordinal_extension(ordinal));
        }
        let not_before = time::OffsetDateTime::from_unix_timestamp(current_unix_time as i64)
            .map_err(|_| SvidError::InvalidFormat)?;
        final_params.not_before = not_before;
        final_params.not_after = not_before + time::Duration::seconds(validity_secs as i64);

        let delegated_key_pem = der_to_pem(&key.signing_key, "PRIVATE KEY")?;
        let delegated_key = rcgen::KeyPair::from_pem(&delegated_key_pem)
            .map_err(|_| SvidError::ValidationFailed)?;
        let delegated_cert = CertificateDer::from(key.intermediate_cert_der.as_slice());
        let issuer = rcgen::Issuer::from_ca_cert_der(&delegated_cert, &delegated_key)
            .map_err(|_| SvidError::ValidationFailed)?;

        let cert = final_params
            .signed_by(&csr_params.public_key, &issuer)
            .map_err(|_| SvidError::ValidationFailed)?;

        Ok(cert.der().to_vec())
    }

    /// Convert DER bytes to PEM (base64 body, 64-char lines).
    fn der_to_pem(der: &[u8], label: &str) -> Result<String, SvidError> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let b64 = STANDARD.encode(der);
        let mut pem = String::new();
        pem.push_str(&format!("-----BEGIN {}-----\n", label));
        for chunk in b64.as_bytes().chunks(64) {
            // base64 output is ASCII by construction.
            pem.push_str(std::str::from_utf8(chunk).expect("base64 output is ASCII"));
            pem.push('\n');
        }
        pem.push_str(&format!("-----END {}-----\n", label));
        Ok(pem)
    }
}

#[cfg(all(test, feature = "ca"))]
mod cr_core_12_tests {
    use super::*;
    use core::time::Duration;

    const TD: &str = "fleet.example.internal";

    struct RootCa {
        key: rcgen::KeyPair,
        cert_der: Vec<u8>,
    }

    fn generate_root(trust_domain: &str) -> RootCa {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(
            rcgen::DnType::CommonName,
            format!("Test Root CA ({})", trust_domain),
        );
        params.distinguished_name = dn;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let cert = params.self_signed(&key).unwrap();
        RootCa {
            key,
            cert_der: cert.der().to_vec(),
        }
    }

    /// Control-shaped SVID: SPIFFE URI SAN + DigitalSignature KU + mTLS EKUs.
    fn sign_workload_svid(root: &RootCa, spiffe_id: &str) -> Vec<u8> {
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        let uri: rcgen::string::Ia5String = spiffe_id.to_string().try_into().unwrap();
        params.subject_alt_names.push(rcgen::SanType::URI(uri));
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, spiffe_id);
        params.distinguished_name = dn;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let issuer = rcgen::Issuer::from_ca_cert_der(
            &rustls::pki_types::CertificateDer::from(root.cert_der.as_slice()),
            &root.key,
        )
        .unwrap();
        params.signed_by(&leaf_key, &issuer).unwrap().der().to_vec()
    }

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn bundle(root_der: Vec<u8>) -> TrustBundle {
        TrustBundle {
            trust_domain: TD.to_owned(),
            roots: vec![root_der],
        }
    }

    // ---------------- extract_spiffe_id ----------------

    #[test]
    fn extract_spiffe_id_parses_control_shaped_svid() {
        let root = generate_root(TD);
        let uri = format!("spiffe://{TD}/ns/tenant-1/sa/db");
        let cert = sign_workload_svid(&root, &uri);
        let id = extract_spiffe_id(&cert).unwrap();
        assert_eq!(id, uri.parse::<SpiffeId>().unwrap());
        assert_eq!(id.trust_domain, TD);
        assert_eq!(id.tenant, "tenant-1");
        assert_eq!(id.kind, IdKind::Sa);
        assert_eq!(id.name, "db");
    }

    #[test]
    fn extract_spiffe_id_rejects_cert_without_spiffe_san() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "no-san");
        params.distinguished_name = dn;
        let cert = params.self_signed(&key).unwrap();
        assert_eq!(
            extract_spiffe_id(cert.der()).unwrap_err(),
            SvidError::InvalidFormat
        );
    }

    // ---------------- validate_svid matrix ----------------

    #[test]
    fn validate_svid_accepts_valid_chain() {
        let root = generate_root(TD);
        let uri = format!("spiffe://{TD}/ns/tenant-1/sa/db");
        let cert = sign_workload_svid(&root, &uri);
        let id = validate_svid(&cert, &bundle(root.cert_der.clone())).unwrap();
        assert_eq!(id, uri.parse::<SpiffeId>().unwrap());
    }

    #[test]
    fn validate_svid_rejects_foreign_ca() {
        let root = generate_root(TD);
        let foreign = generate_root("other.example.internal");
        let uri = format!("spiffe://{TD}/ns/tenant-1/sa/db");
        let cert = sign_workload_svid(&foreign, &uri);
        assert_eq!(
            validate_svid(&cert, &bundle(root.cert_der)).unwrap_err(),
            SvidError::ValidationFailed
        );
    }

    #[test]
    fn validate_svid_rejects_wrong_trust_domain_uri() {
        let root = generate_root(TD);
        // Chains to our root, but claims a foreign trust domain in the URI.
        let uri = format!("spiffe://evil.example.internal/ns/tenant-1/sa/db");
        let cert = sign_workload_svid(&root, &uri);
        assert_eq!(
            validate_svid(&cert, &bundle(root.cert_der)).unwrap_err(),
            SvidError::ValidationFailed
        );
    }

    // ---------------- extension builders: writer/reader convergence --------

    #[test]
    fn extension_builders_emit_reader_parseable_values() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "ext-roundtrip");
        params.distinguished_name = dn;
        params.custom_extensions.push(role_extension("replica"));
        params.custom_extensions.push(degraded_extension(true));
        params.custom_extensions.push(ordinal_extension(7));
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der();

        assert_eq!(
            extract_role(der).unwrap(),
            WorkloadRole::try_from("replica").unwrap()
        );
        assert!(is_degraded(der));
        assert_eq!(extract_ordinal(der), Some(7));
    }

    // ---------------- delegated renewal ----------------

    struct DelegatedSetup {
        key: DelegatedSigningKey,
        intermediate_cert_der: Vec<u8>,
    }

    fn delegated_setup(role: &str, ordinal: Option<u32>) -> DelegatedSetup {
        let root = generate_root(TD);
        // Intermediate CA with pathLenConstraint = 0 (M-1 backstop).
        let int_key = rcgen::KeyPair::generate().unwrap();
        let mut int_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "Test Delegated Intermediate");
        int_params.distinguished_name = dn;
        int_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        int_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let issuer = rcgen::Issuer::from_ca_cert_der(
            &rustls::pki_types::CertificateDer::from(root.cert_der.as_slice()),
            &root.key,
        )
        .unwrap();
        let int_cert = int_params.signed_by(&int_key, &issuer).unwrap();
        let int_cert_der = int_cert.der().to_vec();

        let now = now_unix();
        let key = DelegatedSigningKey {
            node_id: format!("spiffe://{TD}/ns/system/node/agent-1")
                .parse()
                .unwrap(),
            target_svid_id: format!("spiffe://{TD}/ns/tenant-1/sa/db").parse().unwrap(),
            target_ordinal: ordinal,
            target_role: Some(WorkloadRole::try_from(role).unwrap()),
            issued_at_unix: now,
            expires_at_unix: now + 14_400,
            signing_key: Zeroizing::new(int_key.serialize_der()),
            intermediate_cert_der: int_cert_der.clone(),
        };
        DelegatedSetup {
            key,
            intermediate_cert_der: int_cert_der,
        }
    }

    #[test]
    fn delegated_renewal_round_trip_stamps_scope_from_key() {
        let setup = delegated_setup("replica", Some(2));
        let now = now_unix();
        let csr = ca::build_csr(
            &setup.key.target_svid_id,
            &rcgen::KeyPair::generate().unwrap(),
        )
        .unwrap();

        let leaf_der =
            ca::sign_svid_delegated(&setup.key, &csr.der, Duration::from_secs(3600), now).unwrap();

        // Identity locked to the key scope.
        assert_eq!(
            extract_spiffe_id(&leaf_der).unwrap(),
            setup.key.target_svid_id
        );
        // Extensions stamped exclusively from the key scope.
        assert!(is_degraded(&leaf_der));
        assert_eq!(
            extract_role(&leaf_der).unwrap(),
            WorkloadRole::try_from("replica").unwrap()
        );
        assert_eq!(extract_ordinal(&leaf_der), Some(2));
        // Validity window granted from current_unix_time.
        let (_, cert) = x509_parser::parse_x509_certificate(&leaf_der).unwrap();
        assert_eq!(cert.validity().not_before.timestamp(), now as i64);
        assert_eq!(cert.validity().not_after.timestamp(), (now + 3600) as i64);
        // Leaf chains to the delegated intermediate (pathLen=0 regression).
        let int_bundle = TrustBundle {
            trust_domain: TD.to_owned(),
            roots: vec![setup.intermediate_cert_der.clone()],
        };
        assert_eq!(
            validate_svid(&leaf_der, &int_bundle).unwrap(),
            setup.key.target_svid_id
        );
    }

    #[test]
    fn delegated_renewal_rejects_cross_tenant_csr() {
        let setup = delegated_setup("replica", Some(0));
        let now = now_unix();
        let other: SpiffeId = format!("spiffe://{TD}/ns/tenant-2/sa/db").parse().unwrap();
        let csr = ca::build_csr(&other, &rcgen::KeyPair::generate().unwrap()).unwrap();
        assert_eq!(
            ca::sign_svid_delegated(&setup.key, &csr.der, Duration::from_secs(3600), now)
                .unwrap_err(),
            SvidError::TargetSvidMismatch
        );
    }

    #[test]
    fn delegated_renewal_rejects_cross_service_csr() {
        let setup = delegated_setup("replica", Some(0));
        let now = now_unix();
        let other: SpiffeId = format!("spiffe://{TD}/ns/tenant-1/sa/web").parse().unwrap();
        let csr = ca::build_csr(&other, &rcgen::KeyPair::generate().unwrap()).unwrap();
        assert_eq!(
            ca::sign_svid_delegated(&setup.key, &csr.der, Duration::from_secs(3600), now)
                .unwrap_err(),
            SvidError::TargetSvidMismatch
        );
    }

    #[test]
    fn delegated_renewal_rejects_cross_trust_domain_csr() {
        let setup = delegated_setup("replica", Some(0));
        let now = now_unix();
        let other: SpiffeId = "spiffe://other.example.internal/ns/tenant-1/sa/db"
            .parse()
            .unwrap();
        let csr = ca::build_csr(&other, &rcgen::KeyPair::generate().unwrap()).unwrap();
        assert_eq!(
            ca::sign_svid_delegated(&setup.key, &csr.der, Duration::from_secs(3600), now)
                .unwrap_err(),
            SvidError::TargetSvidMismatch
        );
    }

    #[test]
    fn delegated_renewal_rejects_csr_with_dns_san() {
        let setup = delegated_setup("replica", Some(0));
        let now = now_unix();
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["db.tenant-1.svc".to_owned()]).unwrap();
        let csr = params.serialize_request(&key).unwrap();
        assert_eq!(
            ca::sign_svid_delegated(&setup.key, csr.der(), Duration::from_secs(3600), now)
                .unwrap_err(),
            SvidError::InvalidFormat
        );
    }

    #[test]
    fn delegated_renewal_rejects_csr_with_extra_san() {
        let setup = delegated_setup("replica", Some(0));
        let now = now_unix();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        let uri: rcgen::string::Ia5String =
            setup.key.target_svid_id.to_string().try_into().unwrap();
        params.subject_alt_names.push(rcgen::SanType::URI(uri));
        params.subject_alt_names.push(rcgen::SanType::DnsName(
            "extra.local".to_string().try_into().unwrap(),
        ));
        let csr = params.serialize_request(&key).unwrap();
        assert_eq!(
            ca::sign_svid_delegated(&setup.key, csr.der(), Duration::from_secs(3600), now)
                .unwrap_err(),
            SvidError::InvalidFormat
        );
    }

    #[test]
    fn delegated_renewal_rejects_csr_without_san() {
        let setup = delegated_setup("replica", Some(0));
        let now = now_unix();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "no-san");
        params.distinguished_name = dn;
        let csr = params.serialize_request(&key).unwrap();
        assert_eq!(
            ca::sign_svid_delegated(&setup.key, csr.der(), Duration::from_secs(3600), now)
                .unwrap_err(),
            SvidError::InvalidFormat
        );
    }

    #[test]
    fn delegated_renewal_rejects_expired_key() {
        let mut setup = delegated_setup("replica", Some(0));
        setup.key.expires_at_unix = now_unix() - 1;
        let csr = ca::build_csr(
            &setup.key.target_svid_id,
            &rcgen::KeyPair::generate().unwrap(),
        )
        .unwrap();
        assert_eq!(
            ca::sign_svid_delegated(&setup.key, &csr.der, Duration::from_secs(60), now_unix())
                .unwrap_err(),
            SvidError::DelegationKeyExpired
        );
    }

    #[test]
    fn delegated_renewal_rejects_validity_overrun() {
        let setup = delegated_setup("replica", Some(0));
        let now = now_unix();
        let csr = ca::build_csr(
            &setup.key.target_svid_id,
            &rcgen::KeyPair::generate().unwrap(),
        )
        .unwrap();
        // Key expires in 14_400 s; ask for more.
        assert_eq!(
            ca::sign_svid_delegated(&setup.key, &csr.der, Duration::from_secs(99_999), now)
                .unwrap_err(),
            SvidError::ValidityOverrun
        );
    }

    #[test]
    fn delegated_renewal_role_stamped_from_key_only() {
        // There is no caller-supplied role/ordinal channel on the CSR path
        // (build_csr contract). Two renewals with different caller keypairs
        // produce identical identity, role, and ordinal — all from the key.
        let setup = delegated_setup("primary", None);
        let now = now_unix();
        let csr1 = ca::build_csr(
            &setup.key.target_svid_id,
            &rcgen::KeyPair::generate().unwrap(),
        )
        .unwrap();
        let csr2 = ca::build_csr(
            &setup.key.target_svid_id,
            &rcgen::KeyPair::generate().unwrap(),
        )
        .unwrap();
        let leaf1 =
            ca::sign_svid_delegated(&setup.key, &csr1.der, Duration::from_secs(3600), now).unwrap();
        let leaf2 =
            ca::sign_svid_delegated(&setup.key, &csr2.der, Duration::from_secs(3600), now).unwrap();
        assert_eq!(
            extract_role(&leaf1).unwrap(),
            WorkloadRole::try_from("primary").unwrap()
        );
        assert_eq!(
            extract_role(&leaf2).unwrap(),
            WorkloadRole::try_from("primary").unwrap()
        );
        assert_eq!(extract_ordinal(&leaf1), None);
        assert_eq!(extract_ordinal(&leaf2), None);
        assert_eq!(extract_spiffe_id(&leaf1).unwrap(), setup.key.target_svid_id);
        assert_eq!(extract_spiffe_id(&leaf2).unwrap(), setup.key.target_svid_id);
    }
}
