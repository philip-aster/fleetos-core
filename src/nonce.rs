// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce([u8; 32]);

impl Nonce {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        // OsRng was renamed to SysRng
        rand::fill(&mut bytes);
        Self(bytes)
    }

    // Changed from pub(crate) to pub
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
