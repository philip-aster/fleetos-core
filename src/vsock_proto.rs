//! VSOCK attestation + configuration wire protocol (CR-CORE-6 / CR-CORE-13).
//!
//! Shared between `fleetos-guest-init` (guest) and `fleetos-agent` (host).

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
pub const VSOCK_PORT: u32 = 0x4649;
pub const HOST_CID: u32 = 2;

pub const QUOTE_TYPE_TPM2: u8 = 0;
pub const QUOTE_TYPE_SEV_SNP: u8 = 1;
pub const QUOTE_TYPE_TDX: u8 = 2;
pub const QUOTE_TYPE_HOST_MEASURED: u8 = 3; // Orchestrator D1 ruling
pub const QUOTE_TYPE_DEV_SOFTWARE: u8 = 0xFF;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VsockAttestationChallenge {
    pub protocol_version: u32,
    pub nonce: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VsockAttestationProof {
    pub quote_type: u8,
    pub raw_quote: Vec<u8>,
    pub guest_x25519_pubkey: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentAttestResult {
    pub accepted: bool,
    pub reason: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WorkloadConfig {
    pub svid_cert_chain_der: Vec<Vec<u8>>,
    pub svid_private_key_der: Vec<u8>,
    pub env_vars: Vec<(String, String)>,
    pub volume_mounts: Vec<VolumeMountConfig>,
    pub dummy_ip_routes: Vec<DummyIpRouteConfig>,
    pub workload_binary_path: String,
    pub workload_args: Vec<String>,
    pub trust_domain: String,
    pub tenant_id: String,
    pub service_name: String,
    pub role: String,
    pub guest_ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VolumeMountConfig {
    pub name: String,
    pub mount_path: String,
    pub read_only: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DummyIpRouteConfig {
    pub dummy_ip: [u8; 4],
    pub service: String,
    pub role: String,
    pub tenant: String,
}

/// Framing helper: encodes a message into `[u32 LE length][postcard payload]`.
pub fn frame_msg<T: Serialize>(msg: &T) -> Result<Vec<u8>, postcard::Error> {
    let payload = postcard::to_allocvec(msg)?;
    let len = (payload.len() as u32).to_le_bytes();
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&len);
    framed.extend_from_slice(&payload);
    Ok(framed)
}

/// Framing helper: decodes a postcard payload (length prefix must be stripped by I/O layer).
pub fn decode_msg<T: serde::de::DeserializeOwned>(payload: &[u8]) -> Result<T, postcard::Error> {
    postcard::from_bytes(payload)
}
