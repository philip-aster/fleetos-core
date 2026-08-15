// SPDX-License-Identifier: Apache-2.0
// src/time.rs
use core::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct Ttl(pub Duration);

#[derive(Debug, Clone)]
pub struct Expiring<T> {
    pub inner: T,
    pub expires_at_unix: u64,
}

impl<T> Expiring<T> {
    /// Accepts the current time as a u64 unix timestamp to maintain no_std compatibility
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix > self.expires_at_unix
    }
}
