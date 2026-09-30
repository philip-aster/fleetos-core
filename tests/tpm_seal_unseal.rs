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

#[test]
fn context_manager_concurrent_operations() {
    let _guard = TPM_TEST_LOCK.lock().unwrap();
    if !tpm_enabled() {
        eprintln!("skipping TPM context manager test: set FLEETOS_TPM_TESTS=1 to run");
        return;
    }
    let endpoint = tpm_endpoint();

    let mut mgr =
        fleetos_core::attestation::tpm::TpmContextManager::new(&endpoint).expect("new manager");

    // Begin attestation — creates EK + AK
    // For swtpm: contexts are saved immediately, freeing all 3 slots
    let mut session = mgr.begin_attestation().expect("begin attestation");

    // Verify public keys are available
    assert!(!session.ak_pub().is_empty(), "ak_pub must be present");
    assert!(!session.ek_pub().is_empty(), "ek_pub must be present");

    // THE KEY TEST: seal while session is active
    // This was the original failure case — AttestationSession held EK+AK (2 slots),
    // then seal_to_pcr (separate Context, same TPM) needed SRK (3rd slot) +
    // TPM2_Create headroom → TPM_RC_MEMORY.
    //
    // With TpmContextManager, EK+AK are saved (0 slots used), so seal_to_pcr
    // has all 3 slots available.
    let plaintext: [u8; 32] = [0xAB; 32];
    let sealed = mgr
        .seal_to_pcr(&plaintext, &[0, 7, 9])
        .expect("seal while session active");

    // Unseal it
    let recovered = mgr.unseal(&sealed).expect("unseal");
    assert_eq!(
        recovered.as_slice(),
        plaintext.as_slice(),
        "unsealed data mismatch"
    );

    // Quote using the session's AK
    let nonce = [0x55u8; 32];
    let quote = mgr.quote(&mut session, &nonce, &[0, 7, 9]).expect("quote");
    assert!(!quote.quote.is_empty(), "quote must be present");
    assert!(!quote.signature.is_empty(), "signature must be present");
    assert_eq!(quote.pcr_values.len(), 3, "3 PCR values requested");

    // Clean up
    mgr.finish_attestation(session).expect("finish attestation");
}

#[test]
fn context_manager_credential_activation() {
    let _guard = TPM_TEST_LOCK.lock().unwrap();
    if !tpm_enabled() {
        eprintln!("skipping TPM credential activation test: set FLEETOS_TPM_TESTS=1 to run");
        return;
    }
    let endpoint = tpm_endpoint();

    let mut mgr =
        fleetos_core::attestation::tpm::TpmContextManager::new(&endpoint).expect("new manager");

    // Begin attestation
    let mut session = mgr.begin_attestation().expect("begin attestation");

    // Server side: make_credential (uses its own context, doesn't interfere)
    let secret: [u8; 32] = [0x5A; 32];
    let (credential_blob, enc_secret) = fleetos_core::attestation::tpm::make_credential(
        &endpoint,
        session.ek_pub(),
        session.ak_pub(),
        &secret,
    )
    .expect("make_credential");

    // Node side: activate using the managed session
    // This loads EK+AK from saved contexts, does the activation, saves them back
    let recovered = mgr
        .activate(&mut session, &credential_blob, &enc_secret)
        .expect("activate");

    assert_eq!(
        recovered,
        secret.to_vec(),
        "recovered credential secret does not match"
    );

    // Can still seal/unseal after activate
    let plaintext: [u8; 32] = [0xCD; 32];
    let sealed = mgr
        .seal_to_pcr(&plaintext, &[0, 7])
        .expect("seal after activate");
    let recovered2 = mgr.unseal(&sealed).expect("unseal after activate");
    assert_eq!(recovered2.as_slice(), plaintext.as_slice());

    mgr.finish_attestation(session).expect("finish");
}
