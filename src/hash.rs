// SPDX-License-Identifier: Apache-2.0
//! 128-bit BLAKE3 fingerprints for eBPF and router hot-paths.

use crate::spiffe::{SpiffeId, WorkloadRole};
use std::cmp::Ordering;

/// Frozen 16-byte layout for eBPF maps.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdentityFingerprint(pub [u8; 16]);

impl IdentityFingerprint {
    /// Domain separated hash: `hash(id_string || 0x00 || role_string_or_empty)`
    pub fn of(id: &SpiffeId, role: Option<&WorkloadRole>) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(id.to_string().as_bytes());
        hasher.update(&[0x00]); // domain separator

        if let Some(r) = role {
            hasher.update(r.0.as_bytes());
        }

        let mut out = [0u8; 16];
        let full_hash = hasher.finalize();
        out.copy_from_slice(&full_hash.as_bytes()[..16]);
        Self(out)
    }
}

impl PartialOrd for IdentityFingerprint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IdentityFingerprint {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl AsRef<[u8; 16]> for IdentityFingerprint {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}
