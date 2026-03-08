# Bastion Security Documentation

Last updated: 2026-03-08

## Scope

This document covers the current implementation and verification expectations for the `crypto_bastion` crate in this repository.

Public API scope:

- `encrypt`
- `encapsulate`
- `sign`
- `hash`
- `compare`
- `layer_encrypt`
- `onion`

Everything else is internal (`pub(crate)`) and may change without public API guarantees.

## Security Objectives

- Preserve confidentiality and integrity for layered packets.
- Prevent accidental key retention through explicit zeroization.
- Minimize timing side-channel signal at the public interface level.
- Keep high-risk operations allocation-aware and measurable.
- Keep failure semantics explicit (error returns, no panic paths on expected bad input).

## Cryptographic Components

- AES-256-GCM for authenticated encryption.
- ML-KEM-1024 for key encapsulation.
- ML-DSA-87 for detached signatures.
- SHA-512 for public hashing API.

The implementation includes test vectors and behavioral tests for these components in unit tests.

## Design Controls

### 1) Restricted Public Surface

Only the seven public functions above are exposed. Internal key/scheduler/state types are not public.

### 2) Output-Buffer APIs

Public methods that produce variable data require caller-provided output buffers.

Benefits:

- avoids implicit heap allocations in public hot paths
- makes output sizes explicit and auditable
- allows deterministic allocation measurement

### 3) Zeroization

Sensitive buffers and secret intermediates are explicitly wiped in key/signing/decapsulation flows.

Controls include:

- volatile-write zeroization helpers
- explicit wipe of temporary arrays in PQC wrappers and signature logic
- defensive wipe on invalid-input branches where applicable

### 4) Constant-Time Public Wrappers

Public functions are wrapped with timing-floor normalization.

Notes:

- This is a practical interface-level mitigation.
- It is not a formal proof of microarchitectural constant-time behavior.

`compare` additionally uses a constant-time equality primitive over equal-length slices.

### 5) Timing Guard Enforcement

Timing guard controls are applied to sensitive operations.

- lower bound: prevent very-fast outliers
- bounded overshoot window: detect anomalous high-latency paths

Overshoot violations are counted and surfaced via metrics.

## Threat Model Summary

### Tampering

- GCM tag verification rejects modified ciphertext/AAD/nonce.
- Signature verification rejects modified signed layer packets.

### Oracle Abuse / DoS

- Input shape validation before expensive operations.
- Rate-limiter controls in internal layer operations.

### Information Disclosure

- Opaque public errors for sensitive internals.
- Explicit zeroization of key/intermediate data.

### Timing Analysis

- constant-time comparisons where required
- public timing-floor normalization
- timing spread measurement in benchmark reporting

## Allocation and Memory Measurement

`examples/write_results.rs` reports:

- performance (`avg_ns`, `ops/sec`)
- allocator call/byte deltas
- process RSS deltas
- timing spread checks for each public API method

Output file: `results.txt` at repository root.

## Verification Workflow

Run in this order:

```bash
cargo fmt
cargo check --all-targets
cargo test --all-targets
cargo bench --bench public_api
cargo run --example write_results
```

Fuzzing (requires `cargo-fuzz` and nightly):

```bash
cd fuzz
cargo +nightly fuzz run fuzz_hash_compare -- -max_total_time=30
cargo +nightly fuzz run fuzz_encrypt_api -- -max_total_time=30
cargo +nightly fuzz run fuzz_encaps_sign_api -- -max_total_time=30
cargo +nightly fuzz run fuzz_onion_api -- -max_total_time=30
```

## Known Limitations

- Timing-floor normalization is not a full hardware side-channel guarantee.
- Fuzz campaigns are coverage-guided and time-bounded unless explicitly extended.
- API misuse (wrong buffer sizes / malformed key material) still requires caller discipline.

## Disclosure Policy

For security issues, report privately to the maintainers before public disclosure.

Recommended report content:

- affected version/commit
- reproducible steps or PoC
- impact assessment
- suggested remediation (if available)

Do not publish exploit details before coordinated remediation.
