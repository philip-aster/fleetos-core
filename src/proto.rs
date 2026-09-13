// SPDX-License-Identifier: Apache-2.0
//! Tonic-generated proto code and wire framing.

/// Includes the generated protobuf code.
pub mod fleetos {
    tonic::include_proto!("fleetos");
}

pub mod admin {
    pub use crate::proto::fleetos::admin_service_client::AdminServiceClient;
    pub use crate::proto::fleetos::admin_service_server::AdminService;
    pub use crate::proto::fleetos::{
        AuditEntry, ClusterStatus, CreateTenantRequest, CreateTenantResponse, CronWorkloadAck,
        DelegatedKeyRequest, DelegatedKeyResponse, DeleteSagRuleRequest, DeleteWorkloadRequest,
        GenerateJoinTokenRequest, GenerateJoinTokenResponse, GetClusterStatusRequest,
        GrantOperatorAccessRequest, ListAuditLogRequest, ListAuditLogResponse,
        ListNodePoolsRequest, ListNodePoolsResponse, ListNodesRequest, ListNodesResponse,
        ListOperatorAccessRequest, ListOperatorAccessResponse, NodeAck, NodeId, NodePoolAck,
        NodePoolCreateRequest, NodePoolDeleteRequest, NodePoolInfo, OperatorAccessAck,
        OperatorAccessGrant, OperatorScope, PcrPolicyAck, PcrValueProto, QuotaAck, QuotaRequest,
        QuotaResponse, RegisterNodeEkRequest, RegisterNodeEkResponse, RemoveNodeTaintRequest,
        RevokeNodeEkRequest, RevokeOperatorAccessRequest, SagRuleAck, ScaleWorkloadRequest,
        SecretAck, SecretAclChange, SetNodeTaintsRequest, SetPcrPolicyRequest, StoreSecretRequest,
        Taint, TenantQuota, UpsertSagRuleRequest, WorkloadSpecAck,
    };
}

pub mod identity {
    pub use crate::proto::fleetos::attestation_service_client::AttestationServiceClient;
    pub use crate::proto::fleetos::attestation_service_server::AttestationService;
    pub use crate::proto::fleetos::ca_service_client::CaServiceClient;
    pub use crate::proto::fleetos::ca_service_server::CaService;
    pub use crate::proto::fleetos::{
        ActivationChallenge, ActivationProof, ActivationRequest, AttestationQuote,
        AttestedIdentity, CsrRequest, NonceRequest, NonceResponse, QuoteType, SvidResponse,
        TrustBundle, TrustBundleRequest,
    };
}

pub mod secret {
    // CR-17 (CR-CORE-4): agent-side client for FetchSecret.
    pub use crate::proto::fleetos::secret_service_client::SecretServiceClient;
    pub use crate::proto::fleetos::secret_service_server::SecretService;
    pub use crate::proto::fleetos::{FetchSecretRequest, SealedSecret};
}

pub mod state {
    pub use crate::proto::fleetos::policy_service_server::PolicyService;
    pub use crate::proto::fleetos::router_assignment_service_server::RouterAssignmentService;
    pub use crate::proto::fleetos::scheduler_service_server::SchedulerService;
    pub use crate::proto::fleetos::watch_service_server::WatchService;
    // CR-4: client exported too — fleetos-agent is the client-side consumer
    // (precedent: provisioning module).
    pub use crate::proto::fleetos::workload_status_service_client::WorkloadStatusServiceClient;
    pub use crate::proto::fleetos::workload_status_service_server::WorkloadStatusService;

    // CR-16: Node-callable delegation acquisition exports
    pub use crate::proto::fleetos::delegation_service_client::DelegationServiceClient;
    pub use crate::proto::fleetos::delegation_service_server::DelegationService;

    pub use crate::proto::fleetos::{
        // CR-16: Re-exported from state.proto for node-facing services
        DelegatedKeyRequest,
        DelegatedKeyResponse,
        MetricsAck,
        PeerSelector,
        PodMetrics,
        RouteEntry,
        RouteUpdate,
        SagRule,
        SagUpdate,
        ScheduleUpdate,
        SecretRotationNotification,
        StatusAck,
        SvidRotationNotification,
        WatchEvent,
        WatchRequest,
        WorkloadAssignment,
        WorkloadStatusReport,
    };

    // CR-17 (CR-CORE-4): agent-side clients for the pull/watch services.
    pub use crate::proto::fleetos::policy_service_client::PolicyServiceClient;
    pub use crate::proto::fleetos::scheduler_service_client::SchedulerServiceClient;
    pub use crate::proto::fleetos::watch_service_client::WatchServiceClient;

    // CR-CORE-8: Pod lifecycle events
    pub use crate::proto::fleetos::pod_event_service_client::PodEventServiceClient;
    pub use crate::proto::fleetos::pod_event_service_server::PodEventService;
    pub use crate::proto::fleetos::{
        PodEvent, ReportPodEventsRequest, ReportPodEventsResponse, WatchPodEventsRequest,
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

pub mod debug {
    pub use crate::proto::fleetos::agent_debug_service_client::AgentDebugServiceClient;
    pub use crate::proto::fleetos::agent_debug_service_server::AgentDebugService;
    pub use crate::proto::fleetos::operator_debug_service_client::OperatorDebugServiceClient;
    pub use crate::proto::fleetos::operator_debug_service_server::OperatorDebugService;
    pub use crate::proto::fleetos::{
        DataChunk, DebugFrame, ExecRequest, LogsRequest, PortForwardRequest, SessionAck,
        SessionEnd, SessionStart,
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
