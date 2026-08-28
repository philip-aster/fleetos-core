// SPDX-License-Identifier: Apache-2.0
//! CR-8: Operator JIT access — canonical grant identity.
//!
//! fleetos-core owns the grant-id hashing convention (same ownership rule as
//! `SagRuleId`): fleetos-control MUST call `OperatorGrantId::of_grant` when
//! recomputing ids server-side; local re-implementations of this hash are
//! prohibited.

use core::fmt;
use core::str::FromStr;

/// Frozen 16-byte BLAKE3 fingerprint identifying an operator access grant.
///
/// Recomputed by the leader from the canonical grant content before Raft
/// proposal, so every replica derives the identical id and callers cannot
/// forge ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OperatorGrantId([u8; 16]);

impl OperatorGrantId {
    /// Deterministic content hash of an operator access grant.
    ///
    /// Frozen layout (domain tag, then `0x00` between every field):
    /// `b"FleetOS v1 OperatorGrantId" || 0x00 || operator_id || 0x00 ||
    ///  granted_by || 0x00 || granted_at_unix (LE) || 0x00 ||
    ///  expires_at_unix (LE) || 0x00 || cluster_admin (1 byte) || 0x00 ||
    ///  tenants (byte-wise sorted, deduped, 0x00-joined)`
    ///
    /// Tenant elements MUST NOT contain NUL bytes; enforced upstream by
    /// `TenantId::new` validation (same separator-safety contract as
    /// `SagRuleId::of_rule` / `WorkloadRole`).
    pub fn of_grant(
        operator_id: &str,
        granted_by: &str,
        granted_at_unix: u64,
        expires_at_unix: u64,
        cluster_admin: bool,
        tenants: &[&str],
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"FleetOS v1 OperatorGrantId");
        hasher.update(&[0x00]);
        hasher.update(operator_id.as_bytes());
        hasher.update(&[0x00]);
        hasher.update(granted_by.as_bytes());
        hasher.update(&[0x00]);
        hasher.update(&granted_at_unix.to_le_bytes());
        hasher.update(&[0x00]);
        hasher.update(&expires_at_unix.to_le_bytes());
        hasher.update(&[0x00]);
        hasher.update(&[u8::from(cluster_admin)]);
        hasher.update(&[0x00]);
        // Canonical tenant set: byte-wise sorted + deduped, so semantically
        // identical scopes always yield the same id regardless of wire order.
        let mut canonical: Vec<&str> = tenants.to_vec();
        canonical.sort_unstable();
        canonical.dedup();
        for (i, tenant) in canonical.iter().enumerate() {
            if i > 0 {
                hasher.update(&[0x00]);
            }
            hasher.update(tenant.as_bytes());
        }
        let mut id_bytes = [0u8; 16];
        let hash = hasher.finalize();
        id_bytes.copy_from_slice(&hash.as_bytes()[..16]);
        Self(id_bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Lowercase-hex wire form (matches the `grant_id` string fields in admin.proto).
    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(32);
        for &b in &self.0 {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        s
    }

    /// Parse the hex wire form. Accepts lower- and uppercase digits.
    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.len() != 32 {
            return None;
        }
        let mut out = [0u8; 16];
        for (i, slot) in out.iter_mut().enumerate() {
            let hi = hex_val(bytes[2 * i])?;
            let lo = hex_val(bytes[2 * i + 1])?;
            *slot = (hi << 4) | lo;
        }
        Some(Self(out))
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl fmt::Display for OperatorGrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for OperatorGrantId {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s).ok_or("invalid OperatorGrantId hex")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(tenants: &[&str]) -> OperatorGrantId {
        OperatorGrantId::of_grant(
            "spiffe://admin.example.org/ns/system/operator/alice",
            "spiffe://admin.example.org/ns/system/operator/root",
            1_700_000_000,
            1_700_003_600,
            false,
            tenants,
        )
    }

    #[test]
    fn deterministic() {
        assert_eq!(grant(&["acme"]), grant(&["acme"]));
    }

    #[test]
    fn tenant_order_and_dupes_canonicalized() {
        assert_eq!(grant(&["acme", "beta"]), grant(&["beta", "acme"]));
        assert_eq!(grant(&["acme", "acme", "beta"]), grant(&["beta", "acme"]));
    }

    #[test]
    fn separator_safety() {
        // Classic concatenation-collision shapes defeated by 0x00 separators.
        assert_ne!(grant(&["ab", "c"]), grant(&["abc"]));
        assert_ne!(grant(&["a", "bc"]), grant(&["ab", "c"]));
    }

    #[test]
    fn every_field_moves_the_id() {
        let base = grant(&["acme"]);
        assert_ne!(
            base,
            OperatorGrantId::of_grant(
                "spiffe://admin.example.org/ns/system/operator/bob",
                "spiffe://admin.example.org/ns/system/operator/root",
                1_700_000_000,
                1_700_003_600,
                false,
                &["acme"],
            )
        );
        assert_ne!(
            base,
            OperatorGrantId::of_grant(
                "spiffe://admin.example.org/ns/system/operator/alice",
                "spiffe://admin.example.org/ns/system/operator/root",
                1_700_000_001,
                1_700_003_600,
                false,
                &["acme"],
            )
        );
        assert_ne!(
            base,
            OperatorGrantId::of_grant(
                "spiffe://admin.example.org/ns/system/operator/alice",
                "spiffe://admin.example.org/ns/system/operator/root",
                1_700_000_000,
                1_700_003_601,
                false,
                &["acme"],
            )
        );
        assert_ne!(
            base,
            OperatorGrantId::of_grant(
                "spiffe://admin.example.org/ns/system/operator/alice",
                "spiffe://admin.example.org/ns/system/operator/root",
                1_700_000_000,
                1_700_003_600,
                true,
                &["acme"],
            )
        );
        assert_ne!(base, grant(&["beta"]));
    }

    #[test]
    fn hex_roundtrip() {
        let id = grant(&["acme"]);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 32);
        assert_eq!(OperatorGrantId::from_hex(&hex), Some(id));
        assert_eq!(hex.parse::<OperatorGrantId>().ok(), Some(id));
        assert!(OperatorGrantId::from_hex("nothex").is_none());
        assert!(OperatorGrantId::from_hex(&"0".repeat(31)).is_none());
    }
}
