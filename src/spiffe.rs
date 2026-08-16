// SPDX-License-Identifier: Apache-2.0
//! SPIFFE Identity and X.509 SVID construction.

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;
use thiserror::Error;

/// FleetOS IANA Private Enterprise Number (PEN).
/// TODO (Project Manager): Replace `99999` with the official assigned PEN from IANA.
pub const FLEETOS_IANA_PEN: u64 = 99999;

// Custom OID Arcs under the FleetOS PEN
pub const FLEETOS_ROLE_OID: &str = "1.3.6.1.4.1.99999.1.1";
pub const FLEETOS_DEGRADED_OID: &str = "1.3.6.1.4.1.99999.1.2";
pub const FLEETOS_ORDINAL_OID: &str = "1.3.6.1.4.1.99999.1.3";

// Raw DER OID bytes for `1.3.6.1.4.1.99999.1.*`
const FLEETOS_ROLE_OID_BYTES: [u8; 10] =
    [0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F, 0x01, 0x01];
const FLEETOS_DEGRADED_OID_BYTES: [u8; 10] =
    [0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F, 0x01, 0x02];
const FLEETOS_ORDINAL_OID_BYTES: [u8; 10] =
    [0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F, 0x01, 0x03];

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
    #[error("node ID mismatch")]
    NodeIdMismatch,
    #[error("validity overrun")]
    ValidityOverrun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IdKind {
    Sa,
    Node,
    Router,
    Gateway,
    Ctrl,
}

impl fmt::Display for IdKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdKind::Sa => write!(f, "sa"),
            IdKind::Node => write!(f, "node"),
            IdKind::Router => write!(f, "router"),
            IdKind::Gateway => write!(f, "gateway"),
            IdKind::Ctrl => write!(f, "ctrl"),
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

/// Workload role (e.g., primary, replica). Not part of the URI.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WorkloadRole(pub String);

impl fmt::Display for WorkloadRole {
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
pub fn extract_role(cert_der: &[u8]) -> Option<WorkloadRole> {
    let val = find_oid_extension(cert_der, &FLEETOS_ROLE_OID_BYTES)?;
    // Value is wrapped in a UTF8String (0x0C) or PrintableString (0x13)
    let string_bytes = parse_der_tlv(val, 0x0C)
        .or_else(|| parse_der_tlv(val, 0x13))
        .unwrap_or(val);
    let role_str = core::str::from_utf8(string_bytes).ok()?;
    Some(WorkloadRole(role_str.to_string()))
}

/// Extracts the ordinal (replica instance) from a DER-encoded X.509 certificate.
pub fn extract_ordinal(cert_der: &[u8]) -> Option<u32> {
    let val = find_oid_extension(cert_der, &FLEETOS_ORDINAL_OID_BYTES)?;
    // Value is wrapped in an INTEGER (0x02)
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
        // BOOLEAN in DER is tag 0x01
        if let Some(bool_bytes) = parse_der_tlv(val, 0x01) {
            if !bool_bytes.is_empty() && bool_bytes[0] != 0 {
                return true;
            }
        }
    }
    false
}

pub fn extract_spiffe_id(_cert_der: &[u8]) -> Result<SpiffeId, SvidError> {
    // Stub for actual SAN URI extraction to be implemented with rustls/x509-parser
    Err(SvidError::Unimplemented)
}

/// Trust Bundle is available to ALL nodes, not just the CA.
#[derive(Debug, Clone)]
pub struct TrustBundle {
    pub trust_domain: String,
    pub roots: Vec<Vec<u8>>,
}

pub fn validate_svid(_cert_der: &[u8], _trust_bundle: &TrustBundle) -> Result<SpiffeId, SvidError> {
    Err(SvidError::Unimplemented)
}

/// Deterministic identifier for a delegation session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DelegationId(pub [u8; 16]);

/// A delegated signing key granted to a node for degraded-mode SVID renewal.
pub struct DelegatedSigningKey {
    pub node_id: SpiffeId,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

impl DelegatedSigningKey {
    pub fn delegation_id(&self) -> DelegationId {
        let mut hasher = blake3::Hasher::new();
        // Zero-allocation hashing for delegation id
        self.node_id.write_uri_bytes(&mut hasher);
        hasher.update(&self.issued_at_unix.to_le_bytes());

        let mut id_bytes = [0u8; 16];
        let hash = hasher.finalize();
        id_bytes.copy_from_slice(&hash.as_bytes()[..16]);
        DelegationId(id_bytes)
    }
}

// --- CA Specific Functionality (Only compiled for fleetos-control) ---
#[cfg(feature = "ca")]
pub mod ca {
    use super::*;
    use core::time::Duration;
    use rcgen::{Certificate, KeyPair};
    use zeroize::Zeroizing; // Moved import here to fix warning

    pub struct Csr {
        pub der: Vec<u8>,
    }

    pub struct X509Svid {
        pub cert_chain_der: Vec<u8>,
        pub keypair_der: Zeroizing<Vec<u8>>,
        pub expires_at_unix: u64,
    }

    pub fn build_csr(
        _id: &SpiffeId,
        _role: Option<&WorkloadRole>,
        _keypair: &KeyPair,
    ) -> Result<Csr, SvidError> {
        Err(SvidError::Unimplemented)
    }

    pub fn sign_svid(
        _csr: &Csr,
        _ca_cert: &Certificate,
        _ca_key: &KeyPair,
    ) -> Result<X509Svid, SvidError> {
        Err(SvidError::Unimplemented)
    }

    /// Renews an SVID using a delegated key. Enforces strict scope and validity invariants.
    pub fn sign_svid_delegated(
        key: &DelegatedSigningKey,
        existing_svid: &X509Svid,
        new_validity: Duration,
        current_unix_time: u64,
    ) -> Result<X509Svid, SvidError> {
        // 1. Key Expiration
        if key.expires_at_unix <= current_unix_time {
            return Err(SvidError::DelegationKeyExpired);
        }

        // 2. Node Scoping
        let svid_id = extract_spiffe_id(&existing_svid.cert_chain_der)?;
        if svid_id != key.node_id {
            return Err(SvidError::NodeIdMismatch);
        }

        // FIX: Removed the existing_svid.expires_at_unix check to allow renewing
        // already expired SVIDs during connectivity outages (degraded mode purpose).

        // 3. Validity Window
        let remaining_window = key.expires_at_unix - current_unix_time;
        if new_validity.as_secs() > remaining_window {
            return Err(SvidError::ValidityOverrun);
        }

        Err(SvidError::Unimplemented)
    }
}
