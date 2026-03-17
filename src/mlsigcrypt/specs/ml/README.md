# `ml` Internal Module

Implements the ML-DSA-87 key generation, signing, and verification internals.

## Core Pieces

- field arithmetic and decomposition helpers
- polynomial and NTT operations
- matrix/vector operations
- sampling and challenge generation
- key/signature packing and unpacking
- keygen/sign/verify orchestration

## Security and Memory Rules

- fixed-size key/signature buffers
- explicit zeroization of sensitive signing intermediates
- internal-only visibility (`pub(crate)`)

## Integration

`src/mlsigcrypt/` uses this module directly for key generation, signing, verification,
and shared lattice operations in the level-3 algebraic path.

## Verification Focus

- sign/verify roundtrip success
- tampered message/signature rejection
- deterministic behavior under fixed seed/randomness conditions
