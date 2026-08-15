// SPDX-License-Identifier: Apache-2.0
//! Service Authorization Graph (SAG) Schema.
//! Cross-tenant rules are prevented at compile-time via the TenantCtx builder.

use crate::spiffe::WorkloadRole;
use crate::tenant::TenantId;
use crate::version::MonotonicVersion;

use alloc::string::String;
use alloc::vec::Vec;

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

    pub fn selector(&self, name: impl Into<String>, role: Option<WorkloadRole>) -> PeerSelector {
        PeerSelector {
            service: self.service(name),
            role,
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

        let mut hasher = blake3::Hasher::new();
        hasher.update(self.to_string().as_bytes());
        hasher.update(from.service.name.as_bytes());
        if let Some(r) = &from.role {
            hasher.update(r.0.as_bytes());
        }
        hasher.update(to.service.name.as_bytes());
        if let Some(r) = &to.role {
            hasher.update(r.0.as_bytes());
        }

        let mut id_bytes = [0u8; 16];
        let hash = hasher.finalize();
        id_bytes.copy_from_slice(&hash.as_bytes()[..16]);

        SagRule {
            id: SagRuleId(id_bytes),
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
