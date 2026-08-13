// Truncated 128-bit BLAKE3 identity fingerprinting engine for eBPF maps

use crate::spiffe::SpiffeId;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;

/// Fixed 16-byte (128-bit) fingerprint optimized for eBPF map keys
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "bytemuck", derive(bytemuck::Pod, bytemuck::Zeroable))]
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

// Inside src/spiffe.rs or src/hash.rs
impl From<&SpiffeId> for IdentityHash {
    fn from(spiffe_id: &SpiffeId) -> Self {
        IdentityHash::from_spiffe(spiffe_id)
    }
}

impl From<[u8; 16]> for IdentityHash {
    fn from(bytes: [u8; 16]) -> Self {
        IdentityHash(bytes)
    }
}

impl AsRef<[u8]> for IdentityHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for IdentityHash {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for IdentityHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl fmt::LowerHex for IdentityHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}
