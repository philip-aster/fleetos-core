// SPDX-License-Identifier: Apache-2.0
//! Tonic-generated proto code and wire framing.

/// Includes the generated protobuf code.
pub mod fleetos {
    tonic::include_proto!("fleetos");
}

// Re-export the types into their logical modules to match the original .proto file structure.
pub mod admin {
    pub use crate::proto::fleetos::admin_service_server::AdminService;
    pub use crate::proto::fleetos::{
        ClusterStatus, CreateTenantRequest, CreateTenantResponse, CronWorkloadAck,
        GenerateJoinTokenRequest, GenerateJoinTokenResponse, GetClusterStatusRequest,
        ListNodesRequest, ListNodesResponse, WorkloadSpecAck,
    };
}

pub mod identity {
    pub use crate::proto::fleetos::attestation_service_server::AttestationService;
    pub use crate::proto::fleetos::ca_service_server::CaService;
    pub use crate::proto::fleetos::{
        AttestationQuote, AttestedIdentity, CsrRequest, NonceRequest, NonceResponse, QuoteType,
        SvidResponse, TrustBundle, TrustBundleRequest,
    };
}

pub mod secret {
    pub use crate::proto::fleetos::secret_service_server::SecretService;
    pub use crate::proto::fleetos::{FetchSecretRequest, SealedSecret};
}

pub mod state {
    pub use crate::proto::fleetos::policy_service_server::PolicyService;
    pub use crate::proto::fleetos::router_assignment_service_server::RouterAssignmentService;
    pub use crate::proto::fleetos::scheduler_service_server::SchedulerService;
    pub use crate::proto::fleetos::watch_service_server::WatchService;
    pub use crate::proto::fleetos::{
        PeerSelector, RouteEntry, RouteUpdate, SagRule, SagUpdate, ScheduleUpdate,
        SecretRotationNotification, WatchEvent, WatchRequest, WorkloadAssignment,
    };
}

pub mod provisioning {
    pub use crate::proto::fleetos::provisioning_service_client::ProvisioningServiceClient;
    pub use crate::proto::fleetos::provisioning_service_server::ProvisioningService;
    pub use crate::proto::fleetos::{
        Empty, NodeKind, NodeLifecycleState, NodePoolId, NodePoolSpec, NodePoolStatus,
        ProvisionedNode, ResourceSpec,
    };
}

pub mod workload {
    pub use crate::proto::fleetos::{
        ContainerPort, CronSchedule, CronWorkload, EnvVar, ExecCheck, HttpGetCheck, PlacementMode,
        PodSpec, Probe, ProbeSet, ReplaceStrategy, ResourceRequirements, RestartPolicy,
        RollingReplaceStrategy, TcpSocketCheck, TerminationSpec, UpdateStrategy, VolumeMount,
        WorkloadSpec,
    };
}

/// Out-of-band identity header prefixing gRPC frames.
/// 4-byte length + identity header + gRPC frame.
pub mod identity_header {
    use bytes::{Buf, BufMut, BytesMut};

    /// Header structure: [version: 1 byte] [svid_len: 2 bytes] [svid_str] [role_len: 1 byte] [role_str]
    pub fn write_header(svid: &str, role: Option<&str>) -> BytesMut {
        let svid_bytes = svid.as_bytes();
        let role_bytes = role.map(|r| r.as_bytes()).unwrap_or(&[]);

        let header_len = 1 + 2 + svid_bytes.len() + 1 + role_bytes.len();
        let mut buf = BytesMut::with_capacity(4 + header_len);

        // 4-byte length prefix
        buf.put_u32(header_len as u32);

        // Header payload
        buf.put_u8(1); // version
        buf.put_u16(svid_bytes.len() as u16);
        buf.put_slice(svid_bytes);
        buf.put_u8(role_bytes.len() as u8);
        buf.put_slice(role_bytes);

        buf
    }

    pub fn read_header(buf: &mut &[u8]) -> Option<(String, Option<String>)> {
        if buf.remaining() < 4 {
            return None;
        }

        // Safely read length without advancing cursor and without assuming contiguous bytes > 4
        let len_bytes = &buf[..4];
        let len =
            u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;

        if buf.remaining() < 4 + len {
            return None;
        }

        // Safe to advance cursor now
        buf.advance(4);

        let _version = buf.get_u8();
        let svid_len = buf.get_u16() as usize;

        // We know we have `len` bytes available, so we can safely slice
        let svid_bytes = &buf[..svid_len];
        let svid = std::str::from_utf8(svid_bytes).ok()?.to_string();
        buf.advance(svid_len);

        let role_len = buf.get_u8() as usize;
        let role = if role_len > 0 {
            let role_bytes = &buf[..role_len];
            let r = std::str::from_utf8(role_bytes).ok()?.to_string();
            buf.advance(role_len);
            Some(r)
        } else {
            None
        };

        Some((svid, role))
    }
}
