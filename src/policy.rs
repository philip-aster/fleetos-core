// Service Authorization Graph (SAG) schemas & eBPF policy keys

use crate::hash::IdentityHash;
use crate::spiffe::SpiffeId;
use serde::{Deserialize, Serialize};

/// Basic allow/deny policy action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PolicyAction {
    Deny = 0,
    Allow = 1,
}

/// Evaluatable rule in the Service Authorization Graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SagRule {
    pub source_pattern: String,
    pub target_spiffe: SpiffeId,
    pub target_hash: IdentityHash,
    pub allowed_ports: Vec<u16>,
    pub action: PolicyAction,
}

/// C-compatible representation matching eBPF kernel maps
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct EbpfPolicyKey {
    pub src_hash: [u8; 16],
    pub dst_hash: [u8; 16],
    pub port: u16,
    pub _pad: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct EbpfPolicyValue {
    pub action: u8,
}
