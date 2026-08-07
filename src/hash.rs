// Truncated 128-bit BLAKE3 identity fingerprinting engine for eBPF maps

use crate::spiffe::SpiffeId;
use serde::{Deserialize, Serialize};

/// Fixed 16-byte (128-bit) fingerprint optimized for eBPF map keys
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct IdentityHash(pub [u8; 16]);

impl IdentityHash {
    pub fn from_spiffe(spiffe_id: &SpiffeId) -> Self {
        let uri = spiffe_id.to_uri();
        Self::from_bytes(uri.as_bytes())
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(bytes);
        let mut output = [0u8; 16];
        hasher.finalize_xof().fill(&mut output);
        IdentityHash(output)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}
