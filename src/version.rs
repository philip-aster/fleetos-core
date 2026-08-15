// SPDX-License-Identifier: Apache-2.0
use std::cmp::Ordering;

// Added `Default` to the derive list
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MonotonicVersion(u64);

impl MonotonicVersion {
    pub fn new(v: u64) -> Self {
        Self(v)
    }

    pub fn advance(&mut self, new_v: u64) -> Result<(), &'static str> {
        if new_v <= self.0 {
            return Err("Version must be strictly monotonic");
        }
        self.0 = new_v;
        Ok(())
    }

    pub fn get(&self) -> u64 {
        self.0
    }
}

impl PartialOrd for MonotonicVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for MonotonicVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}
