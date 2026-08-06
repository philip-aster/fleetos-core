// src/lib.rs
// Root module declaration file for fleetos-core

pub mod attestor;
pub mod hash;
pub mod policy;
pub mod proto;
pub mod spiffe;

// Convenient top-level re-exports
pub use attestor::{AttestationPayload, HardwareAttestor};
pub use hash::IdentityHash;
pub use policy::{PolicyAction, SagRule};
pub use spiffe::{EntityType, SpiffeId};
