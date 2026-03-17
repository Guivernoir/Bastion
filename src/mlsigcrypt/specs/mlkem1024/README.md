# ML-KEM-1024 Internal Module

Implements ML-KEM-1024 internals used by Bastion encapsulation and layered encryption.

## Core Pieces

- polynomial/NTT arithmetic
- matrix-vector operations
- packing/unpacking of encapsulation artifacts
- Keccak/SHAKE hashing primitives for KEM flow
- keygen/encaps/decaps procedures

## Security and Memory Rules

- shared-secret derivation uses fixed-size buffers
- secret intermediates are wiped after use
- decapsulation path is designed for robust invalid-input behavior

## Integration

This module is wrapped by `src/pqc.rs`, which applies timing-guard checks and maps errors into crate-level handling.

## Verification Focus

- parameter-size consistency checks
- deterministic encode/decode roundtrips
- encapsulation/decapsulation agreement properties
