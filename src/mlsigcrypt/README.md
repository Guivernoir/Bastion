# MLSigcrypt Internal Layout

This directory contains the internal MLSigcrypt-v2 protocol code plus the
primitive implementations it depends on.

## Root Modules

- `mod.rs` — MLSigcrypt-v2 module root, integration tests, and byte-buffer entry points
- `keys.rs` — unified identity key types, encoding, decoding, and deterministic key derivation
- `params.rs` — protocol constants, sizes, offsets, and packet layout
- `signcrypt.rs` — signcrypt / unsigncrypt packet processing
- `specs/` — primitive implementations and supporting spec-level helpers

## `specs/` Modules

- `sha3_512.rs` — SHA3-512 used by key derivation, key IDs, and AAD normalization
- `sha512.rs` — SHA-512 implementation retained as an internal spec module
- `mlkem1024/` — ML-KEM-1024 encapsulation internals
- `mldsa87/` — ML-DSA-87 signature internals

## Visibility Rules

All modules under `src/mlsigcrypt/` are internal (`pub(crate)`).
Public API entry points remain in `src/lib.rs`.

## Engineering Invariants

- Fixed-size arrays are preferred for secret state and wire-format fields.
- Sensitive intermediates are explicitly zeroized.
- Protocol logic is kept at the `mlsigcrypt/` root; primitive logic stays under `specs/`.
- Tests cover known-answer vectors, tamper rejection, roundtrips, and layout invariants.

## Verification Workflow

- Unit tests validate primitive correctness and protocol behavior.
- Benchmarks measure the public wrapper paths.
- Fuzzing targets exercise public APIs with malformed and random input.
- `examples/write_results.rs` records allocation, timing-spread, and RSS metrics.

For repository-wide details, see [README](../../README.md) and [SECURITY](../../SECURITY.md).
