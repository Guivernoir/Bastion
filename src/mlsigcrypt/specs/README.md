# Primitive Specs Layout

This directory contains the internal primitive implementations consumed by
`src/mlsigcrypt/`.

## Modules

- `keccak.rs` — shared Keccak sponge and SHAKE-128 helper used across MLSigcrypt
- `sha512.rs` — consolidated SHA3-512 and SHA-512 internal hash implementations
- `ml/` — ML-DSA-87 signature implementation and shared lattice arithmetic

## Layout Rule

Protocol orchestration belongs at `src/mlsigcrypt/` root.
Reusable primitive implementations belong under `src/mlsigcrypt/specs/`.
