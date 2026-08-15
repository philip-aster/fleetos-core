// SPDX-License-Identifier: Apache-2.0
// src/tenant.rs
use alloc::string::String;
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantId(String);

impl TenantId {
    pub fn new(id: impl Into<String>) -> Result<Self, &'static str> {
        let id = id.into();
        if id.is_empty() || id.len() > 64 || id.contains('/') || id.contains('\0') || id == ".." {
            return Err("Invalid tenant ID");
        }
        Ok(Self(id))
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
