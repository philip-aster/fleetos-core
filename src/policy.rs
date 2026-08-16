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

        // Align evaluation to use IdentityFingerprint directly
        let action_str = match action {
            SagAction::Allow => "ALLOW",
            SagAction::Deny => "DENY",
        };

        let fingerprint = crate::hash::IdentityFingerprint::of_rule(
            self.as_str(),
            from.service.name.as_str(),
            from.role.as_ref(),
            to.service.name.as_str(),
            to.role.as_ref(),
            action_str,
        );

        SagRule {
            id: SagRuleId(fingerprint.0),
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
