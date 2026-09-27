#![cfg(feature = "tpm")]
//! CR-17 / CR-CORE-5: hardware-gated TPM seal/unseal round-trip.
//! Gated behind FLEETOS_TPM_TESTS=1. Backend via FLEETOS_TPM_BACKEND.
use fleetos_core::attestation::tpm::{TpmEndpoint, seal_to_pcr, unseal};
use std::sync::Mutex;

fn tpm_enabled() -> bool {
    std::env::var("FLEETOS_TPM_TESTS")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn tpm_endpoint() -> TpmEndpoint {
    match std::env::var("FLEETOS_TPM_BACKEND")
        .as_deref()
        .unwrap_or("swtpm")
    {
        "device" => TpmEndpoint::Device {
            path: std::env::var("FLEETOS_TPM_DEVICE").unwrap_or_else(|_| "/dev/tpmrm0".into()),
        },
        "mssim" => TpmEndpoint::Mssim {
            host: std::env::var("FLEETOS_TPM_HOST").unwrap_or_else(|_| "localhost".into()),
            port: std::env::var("FLEETOS_TPM_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(2321),
        },
        _ => TpmEndpoint::Swtpm {
            host: std::env::var("FLEETOS_TPM_HOST").unwrap_or_else(|_| "localhost".into()),
            port: std::env::var("FLEETOS_TPM_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(2321),
        },
    }
}

// swtpm has a limited number of transient object slots.  Tests in this
// file share a single swtpm instance, so they MUST run sequentially to
// avoid exhausting the TPM's transient object table.
static TPM_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn seal_unseal_round_trip() {
    let _guard = TPM_TEST_LOCK.lock().unwrap();
    if !tpm_enabled() {
        eprintln!("skipping TPM seal/unseal test: set FLEETOS_TPM_TESTS=1 to run");
        return;
    }
    let endpoint = tpm_endpoint();
    let plaintext: Vec<u8> = vec![0x5A; 32];
    let pcrs: Vec<u8> = vec![0, 7];
    let sealed = seal_to_pcr(&endpoint, &plaintext, &pcrs).expect("seal_to_pcr failed");
    // Persistable round-trip: serialize + deserialize the blob.
    let json = serde_json::to_vec(&sealed).expect("serialize SealedBlob");
    let sealed2: fleetos_core::attestation::tpm::SealedBlob =
        serde_json::from_slice(&json).expect("deserialize SealedBlob");
    let recovered = unseal(&endpoint, &sealed2).expect("unseal failed");
    assert_eq!(
        recovered.as_slice(),
        plaintext.as_slice(),
        "unsealed data mismatch"
    );
}

#[test]
fn seal_unseal_32byte_x25519_pcrs_0_7_9() {
    let _guard = TPM_TEST_LOCK.lock().unwrap();
    if !tpm_enabled() {
        eprintln!("skipping TPM seal/unseal test: set FLEETOS_TPM_TESTS=1 to run");
        return;
    }
    let endpoint = tpm_endpoint();

    // Exact agent payload shape: 32-byte X25519 private key
    let payload: [u8; 32] = [0xAB; 32];
    // Exact agent DEFAULT_SEAL_PCRS
    let pcrs: Vec<u8> = vec![0, 7, 9];

    let sealed = seal_to_pcr(&endpoint, &payload, &pcrs).expect("seal_to_pcr failed");

    // Persistable round-trip: serialize + deserialize the blob.
    let json = serde_json::to_vec(&sealed).expect("serialize SealedBlob");
    let sealed2: fleetos_core::attestation::tpm::SealedBlob =
        serde_json::from_slice(&json).expect("deserialize SealedBlob");

    let recovered = unseal(&endpoint, &sealed2).expect("unseal failed");
    assert_eq!(
        recovered.as_slice(),
        payload.as_slice(),
        "unsealed data mismatch"
    );
}
