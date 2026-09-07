#![cfg(feature = "tpm")]
//! CR-15 Part B: hardware-gated TPM credential-activation round-trip.
//!
//! Exercises the full CR-10/CR-14 credential-activation flow against a real
//! TPM or simulator:
//!   server-side `make_credential` → node-side `AttestationSession::activate`
//!   → assert the recovered secret matches.
//!
//! Gated behind `FLEETOS_TPM_TESTS=1` so default CI (no hardware) stays green.
//! Configure the backend via:
//!   FLEETOS_TPM_BACKEND=device|swtpm|mssim   (default: swtpm)
//!   FLEETOS_TPM_DEVICE=/dev/tpmrm0           (device backend)
//!   FLEETOS_TPM_HOST / FLEETOS_TPM_PORT      (swtpm/mssim, default localhost:2321)

use fleetos_core::attestation::tpm::{AttestationSession, TpmEndpoint, make_credential};

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

#[test]
fn credential_activation_round_trip() {
    if !tpm_enabled() {
        eprintln!("skipping TPM credential-activation test: set FLEETOS_TPM_TESTS=1 to run");
        return;
    }
    let endpoint = tpm_endpoint();

    // Node side: open a session (creates ephemeral restricted-signing AK + EK).
    let mut session =
        AttestationSession::begin(&endpoint).expect("AttestationSession::begin failed");
    let ak_pub = session.ak_pub().expect("ak_pub failed");
    let ek_spki = session.ek_pub().expect("ek_pub failed");

    // Server side: TPM2_MakeCredential — encrypt a secret to the EK, bound to
    // the AK name.
    let secret: [u8; 32] = [0x5A; 32];
    let (credential_blob, enc_secret) =
        make_credential(&endpoint, &ek_spki, &ak_pub, &secret).expect("make_credential failed");

    // Node side: TPM2_ActivateCredential — recover the secret.
    let recovered = session
        .activate(&credential_blob, &enc_secret)
        .expect("activate_credential failed");

    // The recovered secret MUST match what the server encrypted.
    assert_eq!(
        recovered,
        secret.to_vec(),
        "recovered credential secret does not match"
    );
}
