# AES Architecture Backends

Backend implementations for AES block operations.

## Backends

- `x86.rs` — accelerated path for supported x86/x86_64 CPUs
- `soft.rs` — portable software implementation

## Dispatch Requirements

- identical cryptographic output across backends
- deterministic backend selection behavior
- no behavioral drift between accelerated and software paths

## Verification

Dispatch tests compare backend output equivalence and known vectors.
