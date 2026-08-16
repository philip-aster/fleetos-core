// SPDX-License-Identifier: Apache-2.0
//! fleetos-core: The foundational library crate for FleetOS.
//! Pure primitives, identity, and protocol layer. Zero I/O side effects.

#![cfg_attr(not(feature = "minimal"), no_std)]

// Explicitly link `alloc` so ubiquitous modules can use `String` and `Vec`
// directly via `alloc::...` paths in both `no_std` and `std` builds.
#[cfg(feature = "minimal")]
extern crate alloc;

#[cfg(all(feature = "dev", not(fleetos_dev)))]
compile_error!(
    "The `dev` feature is strictly for integration tests and must not be shipped. \
     Compile with `RUSTFLAGS='--cfg fleetos_dev'` to override."
);

// Core ubiquitous modules (Available in no_std)
pub mod hash;
pub mod time;
pub mod version;

// Modules requiring alloc (gated out of strict no_std/eBPF profile)
#[cfg(feature = "minimal")]
pub mod mesh;
#[cfg(feature = "minimal")]
pub mod policy;
#[cfg(feature = "minimal")]
pub mod spiffe;
#[cfg(feature = "minimal")]
pub mod tenant;

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
pub use time::{Expiring, Ttl};
pub use version::MonotonicVersion;

#[cfg(feature = "minimal")]
pub use mesh::MeshAddress;
#[cfg(feature = "minimal")]
pub use policy::{PeerSelector, SagAction, SagRule, SagRuleId, TenantCtx};
#[cfg(feature = "minimal")]
pub use spiffe::{SpiffeId, WorkloadRole};
#[cfg(feature = "minimal")]
pub use tenant::TenantId;

// Vec-bearing container gated out of no_std/eBPF profile
#[cfg(feature = "minimal")]
pub use policy::ServiceAuthorizationGraph;

#[cfg(feature = "minimal")]
pub use nonce::Nonce;
