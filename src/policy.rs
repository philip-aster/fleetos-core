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

impl SagRule {
    /// Evaluates whether a source SPIFFE ID matches the rule's `source_pattern`
    pub fn matches_source(&self, src_id: &SpiffeId) -> bool {
        let src_uri = src_id.to_uri();

        if self.source_pattern == "*" || self.source_pattern == src_uri {
            return true;
        }

        // Support prefix/glob matching (e.g., "spiffe://cluster.local/ns/prod/*")
        if let Some(prefix) = self.source_pattern.strip_suffix('*') {
            return src_uri.starts_with(prefix);
        }

        false
    }

    /// Converts a matched rule and source identity into eBPF map entries
    pub fn to_ebpf_key_value(
        &self,
        src_hash: &IdentityHash,
        port: u16,
    ) -> (EbpfPolicyKey, EbpfPolicyValue) {
        let key = EbpfPolicyKey {
            src_hash: src_hash.0,
            dst_hash: self.target_hash.0,
            port,
            _pad: 0,
        };

        let value = EbpfPolicyValue {
            action: self.action as u8,
            _pad: [0; 3],
        };

        (key, value)
    }
}

/// C-compatible representation matching eBPF kernel maps
/// Exactly aligned for Aya eBPF BPF_MAP_TYPE_HASH operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "bytemuck", derive(bytemuck::Pod, bytemuck::Zeroable))]
#[repr(C)]
pub struct EbpfPolicyKey {
    pub src_hash: [u8; 16],
    pub dst_hash: [u8; 16],
    pub port: u16,
    pub _pad: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "bytemuck", derive(bytemuck::Pod, bytemuck::Zeroable))]
#[repr(C)]
pub struct EbpfPolicyValue {
    pub action: u8,
    pub _pad: [u8; 3], // Explicitly pad to 4 bytes for C alignment
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_ebpf_struct_alignment() {
        // EbpfPolicyKey: 16 (src) + 16 (dst) + 2 (port) + 2 (pad) = 36 bytes
        assert_eq!(mem::size_of::<EbpfPolicyKey>(), 36);
        assert_eq!(mem::align_of::<EbpfPolicyKey>(), 2);

        // EbpfPolicyValue: 1 (action) + 3 (pad) = 4 bytes
        assert_eq!(mem::size_of::<EbpfPolicyValue>(), 4);
        assert_eq!(mem::align_of::<EbpfPolicyValue>(), 1);
    }
}
