// SPDX-License-Identifier: Apache-2.0
// src/mesh.rs
use crate::spiffe::{SpiffeId, WorkloadRole};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MeshAddress {
    pub id: SpiffeId,
    pub role: Option<WorkloadRole>,
}

/// Enum telling the router which agent node hosts the destination.
#[derive(Debug, Clone)]
pub enum RouteHint {
    Local,
    Agent(SpiffeId),
}
