// SPDX-License-Identifier: Apache-2.0
//! 128-bit BLAKE3 fingerprints for eBPF and router hot-paths.

use bytemuck::{Pod, Zeroable};
use core::cmp::Ordering;

/// Frozen 16-byte layout for eBPF maps.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Pod, Zeroable)]
pub struct IdentityFingerprint(pub [u8; 16]);

// Static assertions to prevent padding/mismatch across kernel boundaries
const _: () = assert!(core::mem::size_of::<IdentityFingerprint>() == 16);
const _: () = assert!(core::mem::align_of::<IdentityFingerprint>() == 1);

#[cfg(feature = "minimal")]
use crate::spiffe::{SpiffeId, WorkloadRole};

#[cfg(feature = "minimal")]
impl IdentityFingerprint {
    /// Domain separated hash: `id_string || 0x00 || role_string_or_empty || 0x00 || ordinal_bytes`
    /// Uses zero-allocation direct byte feeding instead of `.to_string()`.
    pub fn of_with_ordinal(
        id: &SpiffeId,
        role: Option<&WorkloadRole>,
        ordinal: Option<u32>,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();

        // Write URI components directly without allocating
        id.write_uri_bytes(&mut hasher);

        hasher.update(&[0x00]); // domain separator
        if let Some(r) = role {
            hasher.update(r.0.as_bytes());
        }

        hasher.update(&[0x00]); // domain separator
        if let Some(o) = ordinal {
            hasher.update(&o.to_le_bytes());
        }

        let mut out = [0u8; 16];
        let full_hash = hasher.finalize();
        out.copy_from_slice(&full_hash.as_bytes()[..16]);
        Self(out)
    }

    pub fn of(id: &SpiffeId, role: Option<&WorkloadRole>) -> Self {
        Self::of_with_ordinal(id, role, None)
    }

    /// Standardized hashing for SagRuleId to align with IdentityFingerprint
    pub fn of_rule(
        tenant: &str,
        from_service: &str,
        from_role: Option<&WorkloadRole>,
        to_service: &str,
        to_role: Option<&WorkloadRole>,
        action: &str,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(tenant.as_bytes());
        hasher.update(&[0x00]);

        hasher.update(from_service.as_bytes());
        if let Some(r) = from_role {
            hasher.update(r.0.as_bytes());
        }
        hasher.update(&[0x00]);

        hasher.update(to_service.as_bytes());
        if let Some(r) = to_role {
            hasher.update(r.0.as_bytes());
        }
        hasher.update(&[0x00]);

        hasher.update(action.as_bytes());

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
