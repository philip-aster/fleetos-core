# fleetos-core

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`fleetos-core` is the foundational, pure-primitives library for the FleetOS
ecosystem. It owns the canonical identity model (SPIFFE), wire protocol
definitions (gRPC/Protobuf), cryptographic primitives, attestation contracts,
and compile-time security invariants that govern the entire platform.

Designed to be completely I/O free, `fleetos-core` is linked into everything
from the heavy OpenRaft control plane (`fleetos-control`) down to
kernel-adjacent eBPF userland daemons (`fleetos-agent`). It defines the
traits, types, and conventions; downstream binaries own the I/O.

## Core Philosophy

**Zero Side Effects.** This crate performs no I/O, holds no global state, and
does not link `std` when compiled for constrained targets. It defines the
contracts; consumers implement them.

**Core owns the convention; consumers call it and never re-implement it.**
Every canonical identity type (`EkFingerprint`, `OperatorGrantId`,
`SagRuleId`), every hashing convention (`IdentityFingerprint::of`,
`compute_activation_proof`), and every attestation primitive lives here.
Local re-implementations in downstream crates are prohibited.

**Feature-gated backends.** Hardware attestation backends (TPM, VSOCK) are
`std`+FFI and compile only under their feature flags. The `minimal`/`no_std`
profile is untouched by backend code.

## Module Map

| Module | Contents |
|---|---|
| `spiffe` | `SpiffeId`, `WorkloadRole`, `IdKind`, X.509 extension readers (role, ordinal, degraded), `DelegatedSigningKey`, CA signing stubs (`ca` feature) |
| `hash` | `IdentityFingerprint` — 128-bit BLAKE3 fingerprint, `bytemuck`-safe for eBPF maps |
| `policy` | SAG schema: `SagRule`, `PeerSelector`, `TenantCtx`, `SagRuleId` |
| `crypto` | X25519 + ChaCha20-Poly1305 secret sealing (`seal`/`unseal`), `generate_sealing_keypair` |
| `attestation` | Attestation contracts: `PcrValue`, `PcrPolicy`, `EkFingerprint`, activation proof, `HardwareAttestor`/`QuoteVerifier` traits |
| `attestation::quote` | `TpmQuote`, structural verification, software AK signature verification, PCR-digest binding (`software-quote-verify`) |
| `attestation::tpm` | TPM 2.0 client I/O + server primitives: `TpmEndpoint`, `make_credential`, `AttestationSession` (`tpm`) |
| `operator` | `OperatorGrantId` — canonical operator access grant identity |
| `tenant` | `TenantId` with validation |
| `nonce` | `Nonce` (32-byte, `rand`-backed) |
| `time` | `Ttl`, `Expiring<T>` |
| `version` | `MonotonicVersion` |
| `mesh` | `MeshAddress`, `RouteHint` |
| `proto` | Tonic-generated gRPC types + identity header framing |

## Feature Flags

| Feature | Description |
|---|---|
| `minimal` *(default)* | Base primitives: proto, crypto, identity, policy. Requires `std` + `alloc`. |
| `tpm` | TPM 2.0 client I/O (`AttestationSession`) + server primitive (`make_credential`). Requires system TPM2 TSS libraries. |
| `software-quote-verify` | Device-free AK signature verification (RSA PKCS#1v1.5 + ECDSA P-256) and PCR-digest binding. Pure Rust — no TPM hardware or system libraries required. |
| `ca` | CSR construction (`build_csr`) + CA signing helpers via `rcgen`. |
| `vsock-attest` | VSOCK attestation for MicroVM boundaries. **Declared, not yet implemented.** |
| `dev` | Mock attestation for integration tests. `compile_error!`-gated behind `RUSTFLAGS='--cfg fleetos_dev'`. Never shippable. |
| `production` | `tpm` + `vsock-attest` + `ca` + `software-quote-verify`. Everything except `dev`. |
| `full` | `production` + `dev`. |
| `experimental-ordinal-routing` | Unlocks `IdentityFingerprint::of_with_ordinal()`. Off by default. |

Individual dependency re-exports (`bytes`, `rcgen`, `x509-cert`, `der`,
`tonic`, `prost`, `tss-esapi`, `sha2`, `spki`) are available as features for
consumers that need to align dependency versions.

## Key Contracts

These are the canonical conventions owned by `fleetos-core`. Downstream crates
**must** call these — never re-implement them.

| Contract | Type / Function | Rule |
|---|---|---|
| Routing/policy fingerprint | `IdentityFingerprint::of(id, role)` | The **only** sanctioned fingerprint. `of_with_ordinal` is feature-gated and must not appear in default routing/policy paths. |
| EK identity | `EkFingerprint::of_ek_pub` / `of_ek_cert` | One EK → one fingerprint, regardless of presentation form. |
| Operator grant identity | `OperatorGrantId::of_grant` | 7-field content hash, frozen layout. |
| SAG rule identity | `SagRuleId::of_rule` | Content-derived, domain-separated. |
| Activation proof | `compute_activation_proof(S, nonce)` | `BLAKE3_keyed_hash(S, server_nonce)`. Core owns this convention. |
| PCR model | `PcrValue` / `PcrPolicy` | Canonical `Vec<PcrValue>` model. Fixed-field alternatives are prohibited. |
| Domain separation | `0x00` between every hashed field | Prevents concatenation-collision attacks. |
| Role validation | `WorkloadRole::try_from` | Rejects embedded NUL bytes to protect separator integrity. |

## Proto Surface

All gRPC types are generated via `tonic_prost_build` in `build.rs` — **not**
`tonic_build`. Both server and client codegen are enabled.

| Proto | Services |
|---|---|
| `identity.proto` | `AttestationService` (insecure join-token + secure TPM credential-activation), `CaService` |
| `admin.proto` | `AdminService` (tenants, workloads, SAG, secrets, nodes, EK registration, PCR policy, quotas, operator access, audit log, node pools) |
| `state.proto` | `PolicyService`, `SchedulerService`, `RouterAssignmentService`, `WatchService`, `WorkloadStatusService` |
| `secret.proto` | `SecretService` |
| `provisioning.proto` | `ProvisioningService` |
| `workload.proto` | Message types only (`WorkloadSpec`, `PodSpec`, `CronWorkload`, etc.) |

## `no_std` and eBPF Support

For kernel-adjacent targets, use `default-features = false`. This eliminates
`alloc` and `std`, providing only `hash`, `time`, and `version` — the raw
types needed for BPF map lookups.

```toml
[dependencies]
fleetos-core = { version = "0.1", default-features = false }
```

`IdentityFingerprint` is #[repr(C)], Pod, and Zeroable via bytemuck,
with static assertions on size (16 bytes) and alignment (1 byte) to guarantee
safe transmutation into eBPF map keys.

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
