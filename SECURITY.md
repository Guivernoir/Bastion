# Bastion Security Documentation

Last updated: 2026-03-17

## Scope

This document covers the current `crypto_bastion` crate in this repository.

Public cryptographic API:

- `mlsigcrypt_keygen`
- `mlsigcrypt_signcrypt`
- `mlsigcrypt_unsigncrypt`

Public sizing constants:

- `MLSIGCRYPT_PUBLIC_KEY_SIZE`
- `MLSIGCRYPT_SECRET_KEY_SIZE`
- `MLSIGCRYPT_PACKET_OVERHEAD`

Everything else is internal (`pub(crate)`) and may change without public API
guarantees.

## Security Objectives

- Preserve confidentiality, integrity, and sender authenticity for
  MLSigcrypt-v3 packets.
- Zeroize secret intermediates and defensive output buffers on failure paths.
- Keep the public interface buffer-oriented and allocation-aware.
- Minimize observable timing variance at the public wrapper boundary.
- Keep failure behavior unified for packet open failures.

## Cryptographic Components

- SHAKE-256 for the MLSigcrypt-v3 payload keystream and fused challenge derivation.
- A custom algebraic encapsulation over the ML-DSA ring for packet confidentiality.
- ML-DSA-87 response/hint machinery for outsider-verifiable authenticity.
- SHA3-512 for key derivation, key identifiers, and AAD normalization.

The MLSigcrypt-v3 packet path does not use AES-256-GCM, HKDF, or ML-KEM.

## Compliance Note

- MLSigcrypt-v3 level 3 uses a custom SHAKE-256 composition plus an algebraic
  encapsulation field fused with the ML-DSA signing mask.
- The crate uses standardized PQC primitives, but the overall packet
  construction is not a FIPS 140-3 validated AEAD module.
- Consumers that require only formally validated FIPS module compositions
  should treat this crate as non-compliant for that requirement.
- Level-3 keys and packets are intentionally not compatible with earlier
  MLSigcrypt-v2 level-1 or level-2 profiles.

## Design Controls

### Restricted Public Surface

Only the three MLSigcrypt functions above are public cryptographic operations.
No standalone encryption, hash, compare, onion-routing, or primitive-wrapper
APIs are exposed.

### Output-Buffer APIs

Public methods use caller-provided output buffers for keys, packets, and
plaintext recovery.

Benefits:

- avoids implicit heap allocation in public hot paths
- makes output sizes explicit and auditable
- supports deterministic allocation measurement

### Zeroization

Sensitive buffers and secret intermediates are explicitly wiped in keygen,
signcrypt, and unsigncrypt flows.

Controls include:

- master-secret zeroization in key generation
- zeroization of temporary `matrix_seed`-derived material during level-3 key generation
- zeroize-on-drop wrappers for transcript, shared-secret copies, sponge output
  blocks, and signing randomness
- defensive wipe of public output buffers on public API failure

### Constant-Time and Ordering Controls

- `ct_eq` is used for `alg_id`, `key_id_S`, and `key_id_R` packet checks.
- Signature verification is completed before payload-key recovery.
- Public wrappers apply timing-floor normalization to reduce interface-level
  signal.

These controls are practical hardening measures, not formal
microarchitectural constant-time proofs.

### Allocation and Dependency Policy

- Runtime dependencies are restricted to the crate itself (`[dependencies]` is
  empty).
- Public cryptographic operations use caller-owned buffers instead of returning
  heap-backed containers.
- The current level-3 implementation uses an exact 23-bit encoding for the
  recipient encapsulation vector, so packet overhead is 7657 bytes rather than
  the merge draft's rough compressed estimate.
- `examples/write_results.rs` measures allocator activity, RSS deltas, and
  timing spread for the public API.

## Threat Model Summary

### Packet Tampering

- Signature verification binds sender/recipient identities, both public keys,
  `encap`, normalized AAD, ciphertext length, and ciphertext bytes into the
  fused challenge.
- Modified packets fail with a unified open error.

### Oracle Abuse / DoS

- Packet shape checks happen before expensive recovery work.
- Payload-key recovery happens only after a valid signature check.
- Public open failures collapse to a single outward error string.

### Information Disclosure

- Secret material is zeroized after use.
- Public wrappers do not expose detailed cryptographic failure causes.

### Timing Analysis

- Required packet-identity comparisons use constant-time equality.
- Public timing floors normalize the top-level wrapper behavior.
- Timing spread is measured in `results.txt` and checked in CI.

## Verification Workflow

Run in this order:

```bash
cargo fmt --all -- --check
cargo check --locked --all-targets
cargo clippy --locked --all-targets -- \
  -D clippy::correctness \
  -A clippy::unwrap_used \
  -A clippy::panic \
  -A clippy::print_stdout \
  -A clippy::print_stderr
cargo test --locked --all-targets
cargo test --locked nist --all-targets
cargo test --locked fips --all-targets
cargo test --locked sp800 --all-targets
cargo doc --locked --no-deps
cargo run --locked --example public_api_demo
cargo run --locked --example write_results
cargo bench --locked --bench public_api --no-run
```

Fuzzing (requires `cargo-fuzz` and nightly):

```bash
cd fuzz
cargo +nightly fuzz run fuzz_mlsigcrypt_api -- -max_total_time=30
```

## Known Limitations

- Timing-floor normalization is not a full side-channel proof.
- Fuzzing is coverage-guided and time-bounded unless extended by the operator.
- MLSigcrypt-v3 level 3 is not a FIPS 140-3 validated packet construction.

## Disclosure Policy

For security issues, report privately to the maintainers before public
disclosure.

Recommended report content:

- affected version or commit
- reproducible steps or proof of concept
- impact assessment
- suggested remediation, if available

Do not publish exploit details before coordinated remediation.
