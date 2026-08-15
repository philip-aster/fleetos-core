// SPDX-License-Identifier: Apache-2.0
// src/time.rs
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Copy)]
pub struct Ttl(pub Duration);

#[derive(Debug, Clone)]
pub struct Expiring<T> {
    pub inner: T,
    pub expires_at: SystemTime,
}

impl<T> Expiring<T> {
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }
}
