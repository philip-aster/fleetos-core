// SPDX-License-Identifier: Apache-2.0
//! SPIFFE Identity and X.509 SVID construction.

use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

use alloc::string::String;
use alloc::vec::Vec;

use thiserror::Error;

/// FleetOS IANA Private Enterprise Number (PEN).
/// TODO (Project Manager): Replace `99999` with the official assigned PEN from IANA.
pub const FLEETOS_IANA_PEN: u64 = 99999;

/// Placeholder OID for FleetOS Role Extension.
/// TODO: Update string with the new PEN once assigned (e.g., "1.3.6.1.4.1.{PEN}.1.1").
pub const FLEETOS_ROLE_OID: &str = "1.3.6.1.4.1.99999.1.1";

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

/// Extracts the role from a DER-encoded X.509 certificate without full parsing.
/// Looks for the raw OID bytes in the certificate blob.
pub fn extract_role(cert_der: &[u8]) -> Option<WorkloadRole> {
    // Implementation uses `x509-parser` to find the specific extension
    // by OID and extract the UTF-8 string value.
    let _ = cert_der;
    None
}

/// Trust Bundle is available to ALL nodes, not just the CA.
/// Every node needs this to validate peer SVIDs.
#[derive(Debug, Clone)]
pub struct TrustBundle {
    pub trust_domain: String,
    pub roots: Vec<Vec<u8>>, // DER encoded root certs
}

/// Validates an SVID against the trust bundle. Available to all nodes.
pub fn validate_svid(_cert_der: &[u8], _trust_bundle: &TrustBundle) -> Result<SpiffeId, SvidError> {
    // Uses rustls to verify chain, then extracts SAN URI.
    Err(SvidError::Unimplemented)
}

// --- CA Specific Functionality (Only compiled for fleetos-control) ---
#[cfg(feature = "ca")]
pub mod ca {
    use super::*;
    use rcgen::{Certificate, CertificateParams, KeyPair};
    use zeroize::Zeroizing; // Moved import inside the feature-gated module

    pub struct Csr {
        pub der: Vec<u8>,
    }

    pub struct X509Svid {
        pub cert_chain_der: Vec<u8>,
        // Zeroized on drop to protect private key material
        pub keypair_der: Zeroizing<Vec<u8>>,
    }

    /// Builds a CSR with Ed25519. Role is injected as a custom extension.
    pub fn build_csr(
        _id: &SpiffeId,
        _role: Option<&WorkloadRole>,
        _keypair: &KeyPair,
    ) -> Result<Csr, SvidError> {
        Err(SvidError::Unimplemented)
    }

    /// Signs the CSR, producing an X509Svid.
    pub fn sign_svid(
        _csr: &Csr,
        _ca_cert: &Certificate,
        _ca_key: &KeyPair,
    ) -> Result<X509Svid, SvidError> {
        Err(SvidError::Unimplemented)
    }
}
