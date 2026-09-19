// SPDX-License-Identifier: Apache-2.0
//! fleetos-core: The foundational library crate for FleetOS.
//! Pure primitives, identity, and protocol layer. Zero I/O side effects.

#![cfg_attr(not(feature = "primitives"), no_std)]

// Explicitly link `alloc` so ubiquitous modules can use `String` and `Vec`
// directly via `alloc::...` paths in both `no_std` and `std` builds.
#[cfg(feature = "primitives")]
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
#[cfg(feature = "primitives")]
pub mod mesh;
#[cfg(feature = "primitives")]
pub mod operator;
#[cfg(feature = "primitives")]
pub mod policy;
#[cfg(feature = "primitives")]
pub mod spiffe;
#[cfg(feature = "primitives")]
pub mod tenant;

// Heavier modules gated behind features
#[cfg(feature = "primitives")]
pub mod attestation;
#[cfg(feature = "primitives")]
pub mod crypto;
#[cfg(feature = "primitives")]
pub mod naming;
#[cfg(feature = "primitives")]
pub mod nonce;

#[cfg(feature = "grpc")]
pub mod proto;

#[cfg(feature = "vsock-attest")]
pub mod vsock_proto;

pub use hash::IdentityFingerprint;
pub use time::{Expiring, Ttl};
pub use version::MonotonicVersion;

#[cfg(all(feature = "grpc", feature = "x509-cert", feature = "der"))]
pub use attestation::EkExtractionError;
#[cfg(feature = "minimal")]
pub use attestation::EkFingerprint;
#[cfg(all(feature = "minimal", feature = "software-quote-verify"))]
pub use attestation::quote::software::verify_quote_signature;
#[cfg(feature = "minimal")]
pub use attestation::{
    PcrPolicy, PcrValue, compute_activation_proof, verify_activation_proof, verify_pcr_policy,
};
#[cfg(feature = "minimal")]
pub use mesh::MeshAddress;
#[cfg(feature = "minimal")]
pub use operator::OperatorGrantId;
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

#[cfg(feature = "minimal")]
pub use naming::dummy_ip_hostname;

#[cfg(all(feature = "minimal", feature = "software-quote-verify"))]
pub use attestation::quote::verify_pcr_binding;
#[cfg(all(feature = "minimal", feature = "tpm"))]
pub use attestation::{AttestationSession, QuoteOutput};
