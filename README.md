# fleetos-core

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`fleetos-core` is the foundational, pure-primitives library for the FleetOS ecosystem. It defines the identity model (SPIFFE), wire protocols (gRPC/Protobuf), attestation traits, and the compile-time security invariants that govern the entire orchestrator.

It is linked into everything from the heavy OpenRaft control plane down to kernel-adjacent eBPF userland daemons.

## The Golden Rule: Zero Side Effects

`fleetos-core` is a pure library. It performs **no I/O**. It does not talk to Containerd, it does not open QUIC sockets, it does not touch `redb` or OpenRaft, and it holds **no global state**. 

If you need to persist a type from this crate, you serialize it and write it yourself. If you need to send it over the network, you use the provided `proto` types. If a trait feels incomplete, it is because the I/O implementation belongs in your downstream binary.

## Cargo Features & System Dependencies

Because this crate spans everything from control planes to eBPF targets, dependencies are strictly gated. **Never use `features = ["full"]` in a production binary.**

| Component | `Cargo.toml` Feature Configuration |
| :--- | :--- |
| **`fleetos-control`** | `features = ["production"]` (CA, TPM, Apple SE, VSOCK) |
| **`fleetos-agent`** | `features = ["tpm", "vsock-attest"]` |
| **`fleetos-router`** | `default-features = false, features = ["tpm"]` |
| **`fleetos-gateway`** | `features = ["tpm"]` |
| **`fleetos-ebpf-common`**| `default-features = false` (Pure `no_std` without `alloc`) |

### System Dependencies (Linux)
If you are compiling with the `tpm` feature enabled, your host machine must have the TPM2 TSS development headers installed:
```bash
sudo apt-get update && sudo apt-get install tpm2-tss-dev
```

### The `dev` Feature
The `dev` feature enables mock attestation for local integration testing. It is guarded by a `compile_error!` macro that halts compilation unless `RUSTFLAGS='--cfg fleetos_dev'` is explicitly passed. Use `features = ["production"]` in your release CI pipelines to build all real backends without tripping the `dev` guard.

## Architecture & Modules

### `spiffe`: Identity is the Address
There are no IPs in the FleetOS data plane. `SpiffeId` (`spiffe://<trust-domain>/ns/<tenant>/<kind>/<name>`) is the address.
* **Workload Roles**: `WorkloadRole` is carried as a custom X.509 extension under the FleetOS IANA PEN (`66561`). It explicitly rejects embedded NUL bytes to protect domain-separated hashing.
* **DER Parsing**: `extract_role`, `extract_ordinal`, and `is_degraded` use zero-allocation, strict DER TLV parsers to read custom extensions without invoking a full X.509 parser.
* **Degraded Mode**: `DelegatedSigningKey` is scoped to a specific `(node_id, target_svid_id, target_ordinal)` tuple. `ca::sign_svid_delegated` structurally enforces that the key can only renew an already-existing SVID, strictly bounding the blast radius.

### `hash`: The eBPF & Router Hot Path
Strings are too slow for the data plane. We use `IdentityFingerprint`, a 128-bit BLAKE3 hash.
* **Layout**: `#[repr(C)] pub struct IdentityFingerprint([u8; 16])`. It derives `bytemuck::Pod` and `Zeroable`, and uses compile-time assertions to guarantee a frozen 16-byte / 1-byte aligned layout for kernel BPF maps.
* **Zero-Allocation**: Hashing is performed by feeding raw string slices directly into the `blake3::Hasher` via `SpiffeId::write_uri_bytes()`.
* **Ordinal Routing**: `of_with_ordinal()` is feature-gated behind `experimental-ordinal-routing` to prevent accidental misuse in v1 role-based routing.

### `policy`: Compile-Time Multitenancy
The Service Authorization Graph (SAG) schema enforces multitenancy at compile-time.
* You cannot instantiate `SagRule` directly. You must call `tenant_id.create_rule(action, |ctx| { ... })`.
* The closure provides a `TenantCtx` that can only build `PeerSelector`s for that specific tenant.
* `SagRuleId` is deterministically generated via a BLAKE3 pipeline that places domain separators *between* every field to prevent concatenation collisions.

### `crypto`: Sealed Secrets
Control-to-agent communication uses HPKE-style sealing (X25519 + ChaCha20-Poly1305) with `blake3::derive_key` domain separation.
* `crypto::unseal()` returns `Zeroizing<Vec<u8>>`. Decrypted plaintext is securely wiped from memory on drop.
* Nonces are cryptographically randomly generated per encryption and prepended to the ciphertext.

### `proto` & Out-of-Band Framing
All gRPC messages use `tonic`. The crate includes `provisioning.proto` (for external cloud provider shims), `admin.proto` (for `fleetctl-proxy`), and `workload.proto` (the shared object model for `PodSpec`/`WorkloadSpec`).
* `proto::identity_header::read_header` is panic-free and safely handles fragmented buffer frames without desyncing the stream.
* `WatchService` provides a unified stream for `TrustBundleRotation`, `ClusterMembership`, `SecretRotationNotification`, and `RevokedDelegations`.

## Downstream Component Contracts

* **`fleetos-control`**: You are the CA, the Raft leader, and the Join Token authority. You must provide the concrete X.509 signing logic for the CA stubs (`build_csr`, `sign_svid`, `sign_svid_delegated`). You are responsible for expanding `WorkloadSpec` into individual `PodSpec` messages, injecting `pod_id` and `ordinal` during scheduling.
* **`fleetos-agent`**: You are the prover and host. Use the `tpm` feature to get your node SVID. Validate incoming SVIDs against the `TrustBundle`. Track `SecretSequence` for replay protection and enforce eBPF policies by compiling `SagRule`s into `EbpfPolicyKey`s using `IdentityFingerprint`.
* **`fleetos-router`**: You are the data plane. Your hot path consists of: parsing the out-of-band `identity_header`, converting it to an `IdentityFingerprint`, and doing an O(1) lookup in a `DashMap`. If the map misses, drop the packet (default deny).
* **`fleetos-ebpf-common`**: You are the kernel boundary. You will depend on `fleetos-core` with `default-features = false`. We have completely eliminated `alloc` from this profile. You can safely remove any dummy `#[global_allocator]` workarounds. Use `AsRef<[u8; 16]>` to write `IdentityFingerprint` directly into BPF maps.

## Error Handling & MSRV
* **No Unwrapping**: `fleetos-core` uses `thiserror` 2.0. Propagate errors using `Result`. Do not use `.unwrap()` or `.expect()` on `fleetos-core` types.
* **MSRV**: The Minimum Supported Rust Version is **1.91**.

## License
Licensed under the Apache License, Version 2.0. You may obtain a copy of the License in the [LICENSE](LICENSE) file.
