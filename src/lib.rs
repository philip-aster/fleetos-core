// Root module declaration file for the fleetos-core

pub mod attestor;
pub mod crypto;
pub mod hash;
pub mod policy;
pub mod proto;
pub mod spiffe;

// Convenient top-level re-exports
pub use attestor::{AttestationPayload, HardwareAttestor};
pub use hash::IdentityHash;
pub use policy::{PolicyAction, SagRule};
pub use spiffe::{EntityType, SpiffeId};

// fleetos-core/src/models.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuntimeEngine {
    CloudHypervisor(CloudHypervisorConfig),
    Containerd(ContainerdConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudHypervisorConfig {
    pub kernel_path: String,
    pub initrd_path: Option<String>,
    pub vcpus: u32,
    pub memory_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerdConfig {
    pub image: String,
    pub snapshotter: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodSpec {
    pub id: String,
    pub namespace: String,
    pub runtime: RuntimeEngine,
}
