# GCM Layer (Internal)

Implements AES-GCM authentication/encryption composition.

## Components

- `ctr.rs` — counter-mode stream generation and in-place XOR
- `ghash.rs` — GHASH multiplication/accumulation in GF(2^128)
- `mod.rs` — high-level seal/open orchestration

## Security Behavior

- verification rejects any ciphertext/AAD/tag mismatch
- authentication is checked before accepting decrypted output
- counter logic enforces bounds and overflow handling

## Data Handling

- sensitive intermediate state is explicitly zeroized
- no public exposure; consumed via crate-level wrapper only
