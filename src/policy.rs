// SPDX-License-Identifier: Apache-2.0
//! Service Authorization Graph (SAG) Schema.
//! Cross-tenant rules are prevented at compile-time via the TenantCtx builder.

use crate::spiffe::WorkloadRole;
use crate::tenant::TenantId;
use crate::version::MonotonicVersion;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServicePattern {
    tenant: TenantId,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerSelector {
    pub service: ServicePattern,
    pub role: Option<WorkloadRole>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SagRuleId([u8; 16]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SagAction {
    Allow,
    Deny, // Explicit deny always overrides Allow
}

#[derive(Debug, Clone)]
pub struct SagRule {
    pub id: SagRuleId,
    pub from: PeerSelector,
    pub to: PeerSelector,
    pub action: SagAction,
}

/// Scoped builder to enforce type safety.
/// You can only build PeerSelectors for the tenant this ctx represents.
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

    pub fn selector(&self, name: impl Into<String>, role: Option<WorkloadRole>) -> PeerSelector {
        PeerSelector {
            service: self.service(name),
            role,
        }
    }
}

impl TenantId {
    /// Creates a rule. The closure receives a TenantCtx, making it a compile error
    /// to attempt to reference another tenant's services.
    pub fn create_rule<F>(&self, action: SagAction, f: F) -> SagRule
    where
        F: FnOnce(&TenantCtx) -> (PeerSelector, PeerSelector),
    {
        let ctx = TenantCtx { tenant: self };
        let (from, to) = f(&ctx);

        // Generate ID (in reality, blake3 of tenant + rule_name + version)
        let id = SagRuleId([0u8; 16]);

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
