// SPDX-License-Identifier: Apache-2.0
//! Service Authorization Graph (SAG) Schema.
//! Cross-tenant rules are prevented at compile-time via the TenantCtx builder.

use crate::spiffe::WorkloadRole;
use crate::tenant::TenantId;
use crate::version::MonotonicVersion;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServicePattern {
    pub tenant: TenantId, // Made public
    pub name: String,     // Made public
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerSelector {
    pub service: ServicePattern,
    pub role: Option<WorkloadRole>,
    pub port: Option<u16>, // None = wildcard tier, Some = exact tier
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SagRuleId([u8; 16]);

impl SagRuleId {
    /// Standardized deterministic hashing for SagRuleId.
    /// Ensures rule identity reflects full rule content, including ports.
    /// Uses domain separators *between* every field to prevent concatenation collisions.
    pub fn of_rule(
        tenant: &str,
        from_service: &str,
        from_role: Option<&WorkloadRole>,
        from_port: Option<u16>,
        to_service: &str,
        to_role: Option<&WorkloadRole>,
        to_port: Option<u16>,
        action: &str,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();

        hasher.update(tenant.as_bytes());
        hasher.update(&[0x00]); // separator

        hasher.update(from_service.as_bytes());
        hasher.update(&[0x00]); // separator
        if let Some(r) = from_role {
            hasher.update(r.as_str().as_bytes());
        }
        hasher.update(&[0x00]); // separator
        if let Some(p) = from_port {
            hasher.update(&p.to_be_bytes());
        }
        hasher.update(&[0x00]); // separator

        hasher.update(to_service.as_bytes());
        hasher.update(&[0x00]); // separator
        if let Some(r) = to_role {
            hasher.update(r.as_str().as_bytes());
        }
        hasher.update(&[0x00]); // separator
        if let Some(p) = to_port {
            hasher.update(&p.to_be_bytes());
        }
        hasher.update(&[0x00]); // separator

        hasher.update(action.as_bytes());

        let mut id_bytes = [0u8; 16];
        let hash = hasher.finalize();
        id_bytes.copy_from_slice(&hash.as_bytes()[..16]);
        SagRuleId(id_bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SagAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct SagRule {
    pub id: SagRuleId,
    pub from: PeerSelector,
    pub to: PeerSelector,
    pub action: SagAction,
}

pub struct TenantCtx<'a> {
    tenant: &'a TenantId,
}

impl<'a> TenantCtx<'a> {
    pub fn service(&self, name: impl Into<String>) -> ServicePattern {
        ServicePattern {
            tenant: self.tenant.clone(),
            name: name.into(),
        }
    }

    pub fn selector(
        &self,
        name: impl Into<String>,
        role: Option<WorkloadRole>,
        port: Option<u16>,
    ) -> PeerSelector {
        PeerSelector {
            service: self.service(name),
            role,
            port,
        }
    }
}

impl TenantId {
    pub fn create_rule<F>(&self, action: SagAction, f: F) -> SagRule
    where
        F: FnOnce(&TenantCtx) -> (PeerSelector, PeerSelector),
    {
        let ctx = TenantCtx { tenant: self };
        let (from, to) = f(&ctx);

        let action_str = match action {
            SagAction::Allow => "ALLOW",
            SagAction::Deny => "DENY",
        };

        let id = SagRuleId::of_rule(
            self.as_str(),
            from.service.name.as_str(),
            from.role.as_ref(),
            from.port,
            to.service.name.as_str(),
            to.role.as_ref(),
            to.port,
            action_str,
        );

        SagRule {
            id,
            from,
            to,
            action,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ServiceAuthorizationGraph {
    pub version: MonotonicVersion,
    pub rules: Vec<SagRule>,
}
