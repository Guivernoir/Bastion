# Primitive Specs Layout

This directory contains the internal primitive implementations consumed by
`src/mlsigcrypt/`.

## Modules

- `sha3_512.rs` — SHA3-512 sponge hashing for MLSigcrypt transcript-bound operations
- `sha512.rs` — SHA-512 retained as an internal spec-level implementation
- `mlkem1024/` — ML-KEM-1024 KEM implementation
- `mldsa87/` — ML-DSA-87 signature implementation

## Layout Rule

Protocol orchestration belongs at `src/mlsigcrypt/` root.
Reusable primitive implementations belong under `src/mlsigcrypt/specs/`.
