// SPIFFE ID parser, generator, and validator for FleetOS

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum IdentityError {
    #[error("Invalid SPIFFE URI format: {0}")]
    InvalidUri(String),
    #[error("Missing expected segment in SPIFFE ID: {0}")]
    MissingSegment(&'static str),
    #[error("Attestation failed: {0}")]
    AttestationFailed(String),
}

/// Strongly-typed SPIFFE ID representation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpiffeId {
    pub trust_domain: String,
    pub namespace: String,
    pub entity_type: EntityType,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityType {
    Node { node_id: String },
    Router { router_id: String },
    Workload { service: String, role: String },
}

impl SpiffeId {
    pub fn new_workload(
        trust_domain: impl Into<String>,
        namespace: impl Into<String>,
        service: impl Into<String>,
        role: impl Into<String>,
    ) -> Self {
        Self {
            trust_domain: trust_domain.into(),
            namespace: namespace.into(),
            entity_type: EntityType::Workload {
                service: service.into(),
                role: role.into(),
            },
        }
    }

    pub fn to_uri(&self) -> String {
        match &self.entity_type {
            EntityType::Node { node_id } => {
                format!(
                    "spiffe://{}/ns/{}/node/{}",
                    self.trust_domain, self.namespace, node_id
                )
            }
            EntityType::Router { router_id } => {
                format!(
                    "spiffe://{}/ns/{}/router/{}",
                    self.trust_domain, self.namespace, router_id
                )
            }
            EntityType::Workload { service, role } => {
                format!(
                    "spiffe://{}/ns/{}/service/{}/role/{}",
                    self.trust_domain, self.namespace, service, role
                )
            }
        }
    }
}

impl FromStr for SpiffeId {
    type Err = IdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("spiffe://") {
            return Err(IdentityError::InvalidUri(s.to_string()));
        }

        let trimmed = &s[9..];
        let parts: Vec<&str> = trimmed.split('/').collect();

        if parts.len() < 4 || parts[1] != "ns" {
            return Err(IdentityError::InvalidUri(s.to_string()));
        }

        let trust_domain = parts[0].to_string();
        let namespace = parts[2].to_string();

        let entity_type = match parts[3] {
            "node" => {
                let node_id = parts
                    .get(4)
                    .ok_or(IdentityError::MissingSegment("node_id"))?
                    .to_string();
                EntityType::Node { node_id }
            }
            "router" => {
                let router_id = parts
                    .get(4)
                    .ok_or(IdentityError::MissingSegment("router_id"))?
                    .to_string();
                EntityType::Router { router_id }
            }
            "service" => {
                let service = parts
                    .get(4)
                    .ok_or(IdentityError::MissingSegment("service"))?
                    .to_string();
                if parts.get(5) != Some(&"role") {
                    return Err(IdentityError::MissingSegment("role prefix"));
                }
                let role = parts
                    .get(6)
                    .ok_or(IdentityError::MissingSegment("role"))?
                    .to_string();
                EntityType::Workload { service, role }
            }
            _ => return Err(IdentityError::InvalidUri(s.to_string())),
        };

        Ok(SpiffeId {
            trust_domain,
            namespace,
            entity_type,
        })
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_uri())
    }
}
