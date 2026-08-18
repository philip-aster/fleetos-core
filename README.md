# fleetos-core

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`fleetos-core` is the foundational, pure-primitives library for the FleetOS ecosystem. It provides the core identity model (SPIFFE), wire protocol definitions (gRPC/Protobuf), cryptographic primitives, and compile-time security invariants that govern the orchestrator.

Designed to be completely I/O free, `fleetos-core` is linked into everything from the heavy OpenRaft control plane down to kernel-adjacent eBPF userland daemons.

## Core Philosophy

**Zero Side Effects.** This crate performs no I/O, holds no global state, and does not link `std` when compiled for constrained targets. It defines the traits and types; downstream binaries are responsible for the actual network, disk, and scheduling implementations.

## Features

* **`spiffe`**: SPIFFE ID parsing and X.509 SVID management. Includes zero-allocation DER parsers for extracting custom OIDs (roles, ordinals, degraded-mode markers).
* **`hash`**: 128-bit BLAKE3 `IdentityFingerprint` optimized for eBPF integration. Uses `bytemuck` for guaranteed, static-layout memory mapping.
* **`policy`**: Compile-time safe Service Authorization Graph (SAG). Cross-tenant rules are prevented at the type level.
* **`crypto`**: HPKE-style secret sealing (X25519 + ChaCha20-Poly1305) with automatic memory zeroization.
* **`proto`**: Tonic-generated gRPC types and panic-free out-of-band identity header framing.

## Usage

Add `fleetos-core` to your `Cargo.toml`:

```toml
[dependencies]
fleetos-core = { version = "0.1", default-features = false, features = ["minimal"] }
```

### Example: Identity & Fingerprinting

```rust
use fleetos_core::{SpiffeId, IdentityFingerprint, WorkloadRole};
use fleetos_core::spiffe::IdKind;

fn main() {
    // Create a SPIFFE ID
    let id = SpiffeId::new(
        "example.com",
        "tenant-a",
        IdKind::Sa,
        "my-service"
    ).unwrap();

    // Create a validated workload role (rejects embedded NUL bytes)
    let role = WorkloadRole::try_from("primary").unwrap();

    // Generate a 16-byte eBPF-safe fingerprint
    let fingerprint = IdentityFingerprint::of(&id, Some(&role));
    
    println!("Fingerprint: {:?}", fingerprint.as_ref());
}
```

## Cargo Features

Because this crate spans everything from control planes to eBPF targets, dependencies are strictly gated.

* **`minimal`** *(default)*: Base primitives required for standard `std` compilation. Includes `std` and `alloc`.
* **`tpm`**: Enables TPM 2.0 hardware attestation traits. *(Requires system TPM2 TSS libraries)*.
* **`apple-se`**: Enables Apple Secure Enclave attestation traits.
* **`vsock-attest`**: Enables VSOCK attestation for MicroVM boundaries.
* **`ca`**: Enables Certificate Authority signing helpers.
* **`experimental-ordinal-routing`**: Unlocks `IdentityFingerprint::of_with_ordinal()`, reserved for future sharded addressing models.

### `no_std` and eBPF Support

For kernel-adjacent targets (like eBPF userland daemons), use `default-features = false`. This completely eliminates `alloc` and `std` dependencies, providing only the raw hashing and identity types required for BPF map lookups.

```toml
[dependencies]
fleetos-core = { version = "0.1", default-features = false }
```

### System Dependencies (Linux)

If you are compiling with the `tpm` feature enabled, your host machine must have the TPM2 TSS development headers installed:

```bash
# Ubuntu/Debian
sudo apt-get install tpm2-tss-dev

# Fedora/RHEL
sudo dnf install tpm2-tss-devel
```

## License

Licensed under the Apache License, Version 2.0. You may obtain a copy of the License in the [LICENSE](LICENSE) file.
