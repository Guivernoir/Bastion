# MLSigcrypt Internal Layout

This directory contains the internal MLSigcrypt-v3 level-3 protocol code plus
the primitive implementations it depends on.

## Root Modules

- `mod.rs` — MLSigcrypt-v3 level-3 module root, integration tests, and byte-buffer entry points
- `keys.rs` — unified identity key types, level-3 encoding, and per-identity shared-matrix derivation
- `params.rs` — protocol constants, sizes, offsets, and packet layout
- `signcrypt.rs` — signcrypt / unsigncrypt packet processing
- `specs/` — primitive implementations and supporting spec-level helpers

## `specs/` Modules

- `algebraic.rs` — exact algebraic encapsulation helpers used by the level-3 packet path
- `keccak.rs` — shared Keccak sponge and SHAKE-128 helper for transcript, XOF, and keystream logic
- `sha512.rs` — consolidated SHA3-512 and SHA-512 helpers used by key derivation and spec-level hashing
- `ml/` — ML-DSA-87 signature internals and shared lattice arithmetic

## Visibility Rules

All modules under `src/mlsigcrypt/` are internal (`pub(crate)`).
Public API entry points remain in `src/lib.rs`.

## Engineering Invariants

- Fixed-size arrays are preferred for secret state and wire-format fields.
- Sensitive intermediates are explicitly zeroized.
- Protocol logic is kept at the `mlsigcrypt/` root; primitive logic stays under `specs/`.
- Level-3 key generation derives a per-identity `rho_shared` from one secret `matrix_seed`.
- The level-3 packet path uses an algebraic encapsulation field and split ML-DSA response fields (`z`, `c_tilde`, `h`).
- Tests cover known-answer vectors, tamper rejection, roundtrips, and layout invariants.

## Verification Workflow

- Unit tests validate primitive correctness and protocol behavior.
- Benchmarks measure the public wrapper paths.
- Fuzzing targets exercise public APIs with malformed and random input.
- `examples/write_results.rs` records allocation, timing-spread, and RSS metrics.

For repository-wide details, see [README](../../README.md) and [SECURITY](../../SECURITY.md).
