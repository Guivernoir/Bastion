# AES-256-GCM Internal Module

This module provides the authenticated encryption primitive used by Bastion's layered packet construction.

## Directory Structure

- `aes/` — AES-256 key schedule and block transform logic
- `arch/` — backend dispatch (`x86` accelerated path and software fallback)
- `gcm/` — CTR stream processing and GHASH authentication
- `mod.rs` — integration of AES and GCM into a single in-place API

## Security Properties Implemented

- AES-256 confidentiality and GCM authenticity.
- Tag verification before plaintext acceptance.
- Counter increment bounds checks to prevent overflow misuse.
- State/key zeroization for sensitive internals where applicable.

## Engineering Notes

- Internal APIs are in-place to keep ownership explicit.
- Backend parity is tested so software and accelerated paths produce equivalent results.
- Module visibility is restricted to `pub(crate)`.

## Test Coverage Themes

- FIPS/NIST vector checks
- tampered ciphertext/AAD/tag rejection
- wrong-key/wrong-nonce rejection
- deterministic behavior for identical inputs
