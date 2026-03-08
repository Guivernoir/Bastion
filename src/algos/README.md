# Algorithms Overview

This directory contains the internal cryptographic implementations used by `src/lib.rs`.

## Modules

- `aes256gcm/` — AES-256 block cipher + GCM mode
- `mlkem1024/` — ML-KEM-1024 key encapsulation internals
- `mldsa87/` — ML-DSA-87 signature internals
- `sha512.rs` — SHA-512 implementation for public `hash`

## Visibility Rules

All algorithm modules are internal (`pub(crate)`).
Public API entry points are intentionally restricted to the crate root.

## Invariants Enforced Across Modules

- Fixed-size arrays for key and cryptographic state where practical.
- Explicit zeroization for secret intermediates and key material.
- No clone/copy semantics for secret key containers at API boundaries.
- Deterministic test coverage for known-answer vectors and tamper/failure behavior.

## Validation Strategy

- Unit tests validate algorithm correctness and edge conditions.
- Benchmarks measure timing/perf behavior for the public API wrappers.
- Fuzz targets stress public interfaces with malformed and random inputs.
- `examples/write_results.rs` records allocation/perf/RSS/timing-spread metrics.

## NIST Alignment Notes

- AES and GCM components are tested with NIST/FIPS-aligned vectors.
- ML-KEM/ML-DSA parameter sizes and behavior follow the selected NIST profiles used by this crate.

For operational details, see repository-level [README](../../README.md) and [SECURITY](../../SECURITY.md).
