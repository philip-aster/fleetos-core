// SPDX-License-Identifier: Apache-2.0
//! fleetos-core: The foundational library crate for FleetOS.
//! Pure primitives, identity, and protocol layer. Zero I/O side effects.

#![cfg_attr(not(feature = "minimal"), no_std)]

// Explicitly link `alloc` so ubiquitous modules can use `String` and `Vec`
// directly via `alloc::...` paths in both `no_std` and `std` builds.
extern crate alloc;

#[cfg(all(feature = "dev", not(fleetos_dev)))]
compile_error!(
    "The `dev` feature is strictly for integration tests and must not be shipped. \
     Compile with `RUSTFLAGS='--cfg fleetos_dev'` to override."
);

// Core ubiquitous modules (Available in no_std / minimal)
pub mod hash;
pub mod mesh;
pub mod policy;
pub mod spiffe;
pub mod tenant;
pub mod time;
pub mod version;

// Heavier modules gated behind features
#[cfg(feature = "minimal")]
pub mod attestation;
#[cfg(feature = "minimal")]
pub mod crypto;
#[cfg(feature = "minimal")]
pub mod nonce;
#[cfg(feature = "minimal")]
pub mod proto;

pub use hash::IdentityFingerprint;
pub use mesh::MeshAddress;
pub use policy::{SagRule, SagRuleId, ServiceAuthorizationGraph, TenantCtx};
pub use spiffe::{SpiffeId, WorkloadRole};
pub use tenant::TenantId;
pub use time::{Expiring, Ttl};
pub use version::MonotonicVersion;

#[cfg(feature = "minimal")]
pub use nonce::Nonce;
