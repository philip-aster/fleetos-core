// SPDX-License-Identifier: Apache-2.0
//! SPIFFE Identity and X.509 SVID construction.

use core::cmp::Ordering;
use core::convert::TryFrom;
use core::fmt;
use core::str::FromStr;

use thiserror::Error;
use tracing::warn;

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
    #[error("target SVID mismatch")]
    TargetSvidMismatch, // Renamed from NodeIdMismatch
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

// --- DER Parsing Helpers ---

fn parse_der_length(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.is_empty() {
        return None;
    }
    let b = bytes[0];
    if b < 0x80 {
        Some((b as usize, 1))
    } else {
        let n = (b & 0x7f) as usize;
        if n == 0 || n > 4 || bytes.len() < 1 + n {
            return None;
        }
        let mut len = 0usize;
        for i in 1..=n {
            len = (len << 8) | (bytes[i] as usize);
        }
        Some((len, 1 + n))
    }
}

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

pub fn extract_spiffe_id(_cert_der: &[u8]) -> Result<SpiffeId, SvidError> {
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
/// Scoped to a specific (node, target_svid, ordinal) tuple.
pub struct DelegatedSigningKey {
    pub node_id: SpiffeId,           // The node this key was issued to
    pub target_svid_id: SpiffeId,    // The workload SVID this key is allowed to renew
    pub target_ordinal: Option<u32>, // The exact ordinal it can renew
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

impl DelegatedSigningKey {
    pub fn delegation_id(&self) -> DelegationId {
        let mut hasher = blake3::Hasher::new();

        // Derive ID from node + target + ordinal + issued_at
        self.node_id.write_uri_bytes(&mut hasher);
        hasher.update(&[0x00]);
        self.target_svid_id.write_uri_bytes(&mut hasher);
        hasher.update(&[0x00]);
        if let Some(o) = self.target_ordinal {
            hasher.update(&o.to_le_bytes());
        }
        hasher.update(&[0x00]);
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
    use zeroize::Zeroizing;

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

        // 2. Target SVID Scoping
        let svid_id = extract_spiffe_id(&existing_svid.cert_chain_der)?;
        if svid_id != key.target_svid_id {
            return Err(SvidError::TargetSvidMismatch);
        }

        // 3. Ordinal Scoping
        let svid_ordinal = extract_ordinal(&existing_svid.cert_chain_der);
        if svid_ordinal != key.target_ordinal {
            return Err(SvidError::OrdinalMismatch);
        }

        // 4. Validity Window
        let remaining_window = key.expires_at_unix - current_unix_time;
        if new_validity.as_secs() > remaining_window {
            return Err(SvidError::ValidityOverrun);
        }

        Err(SvidError::Unimplemented)
    }
}
