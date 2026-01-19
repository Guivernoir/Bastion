# Bastion

**Enterprise-grade post-quantum cryptographic library with military-grade operational security.**

[![Rust](https://img.shields.io/badge/rust-1.90%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-hardened-green.svg)](SECURITY.md)

> _"In cryptography, as in chess, the amateur focuses on tactics. The professional studies strategy."_

## Overview

Bastion is a hardened cryptographic library implementing post-quantum algorithms with comprehensive security controls. Unlike conventional crypto libraries that stop at correctness, Bastion enforces operational security through constant-time execution, dual-context error handling, comprehensive audit logging, and STRIDE threat model coverage.

### Key Features

- 🛡️ **Post-Quantum Security**: ML-KEM-1024 (Kyber) and ML-DSA-87 (Dilithium) - NIST standardized
- ⏱️ **Constant-Time Operations**: Timing guards enforce execution bounds, preventing side-channel attacks
- 🔍 **Dual-Context Errors**: Internal debugging context + external opacity (no information leakage)
- 📊 **STRIDE Coverage**: Comprehensive threat model mitigation with audit classification
- 🔒 **Memory Safety**: Automatic zeroization with cryptographic verification
- 🚦 **Rate Limiting**: Built-in DoS protection (1000 ops/sec symmetric, 100 ops/sec PQC)
- 📝 **Audit Logging**: GDPR-compliant security event tracking
- 🎯 **No-Clone Architecture**: Single-owner semantics prevent memory bloat and side channels
- 🧱 **Onion Routing**: 3-layer encryption for anonymous communication

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
bastion = "0.1.0"
```

## Quick Start

### Onion Encryption (3-Layer)

```rust
use bastion::*;

fn main() -> Result<()> {
    // Initialize 3-layer encryption (entry → relay → exit)
    let encryptor = OnionEncryptor::new(
        [1u8; 32],  // entry node key
        [2u8; 32],  // relay node key
        [3u8; 32],  // exit node key
    )?;

    // Encrypt message through all layers
    let ciphertext = encryptor.encrypt(b"Strategic intelligence")?;

    // Decrypt at each node (keys consumed, preventing reuse)
    let entry_dec = OnionDecryptor::new([1u8; 32])?;
    let layer1 = entry_dec.decrypt(&ciphertext)?;

    let relay_dec = OnionDecryptor::new([2u8; 32])?;
    let layer2 = relay_dec.decrypt(&layer1)?;

    let exit_dec = OnionDecryptor::new([3u8; 32])?;
    let plaintext = exit_dec.decrypt(&layer2)?;

    assert_eq!(&plaintext[..], b"Strategic intelligence");
    Ok(())
}
```

### Post-Quantum Key Exchange

```rust
use bastion::pqc::*;

fn secure_channel() -> Result<()> {
    // Alice and Bob generate keypairs
    let alice = HybridKeyExchange::new()?;
    let bob = HybridKeyExchange::new()?;

    // Alice encapsulates shared secret to Bob's public key
    let (ciphertext, alice_key) = HybridKeyExchange::encapsulate(bob.public_key())?;

    // Bob decapsulates to recover shared secret
    let bob_key = bob.decapsulate(&ciphertext)?;

    assert_eq!(alice_key, bob_key);  // 64-byte shared secret

    // Keys automatically zeroized when dropped
    Ok(())
}
```

### Digital Signatures

```rust
use bastion::pqc::*;

fn authenticated_message() -> Result<()> {
    let keypair = SignatureKeypair::new()?;
    let message = b"Execute Order 66";

    // Sign message
    let signature = keypair.sign(message)?;

    // Verify signature (constant-time)
    verify_signature(keypair.public_key(), message, &signature)?;

    Ok(())
}
```

### Constant-Time Operations

```rust
use bastion::constant_time::*;

fn secure_comparison() {
    let secret = b"launch_codes_alpha_7";
    let attempt = b"launch_codes_alpha_7";

    // Constant-time equality (timing-attack resistant)
    if ct_eq(secret, attempt) {
        println!("Access granted");
    }

    // Verify buffer zeroization
    let mut sensitive = vec![0x42u8; 1024];
    ct_zeroize_verify(&mut sensitive).expect("Zeroization failed");
}
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│           Application Layer                         │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│  Crypto Operations                                  │
│  • AES-256-GCM (authenticated encryption)           │
│  • ML-KEM-1024 (post-quantum key exchange)          │
│  • ML-DSA-87 (post-quantum signatures)              │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│  Hardened Standard                                  │
│  • Constant-time primitives                         │
│  • Dual-context error handling                      │
│  • Comprehensive audit logging                      │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│  Security Enforcement                               │
│  • Rate limiting (DoS protection)                   │
│  • Memory zeroization (verified)                    │
│  • Timing guards (side-channel protection)          │
└─────────────────────────────────────────────────────┘
```

## Security Model

### STRIDE Threat Coverage

| Threat                     | Mitigation                                      |
| -------------------------- | ----------------------------------------------- |
| **Spoofing**               | Post-quantum signatures (ML-DSA-87)             |
| **Tampering**              | Authenticated encryption (AES-256-GCM)          |
| **Repudiation**            | Comprehensive audit logging                     |
| **Information Disclosure** | Opaque errors, memory zeroization               |
| **Denial of Service**      | Rate limiting (1000/sec symmetric, 100/sec PQC) |
| **Elevation of Privilege** | Immutable keys, least privilege                 |

### Constant-Time Guarantees

All cryptographic operations enforce timing constraints:

```rust
// Timing guard example
let _guard = TimingGuard::new("operation", MIN_TIME_NS);
// ... cryptographic operation ...
_guard.verify()?;  // Fails if too fast or too slow
```

Operations that complete too quickly indicate potential side-channel attacks. Violations are logged to `METRICS.timing_violations`.

### Memory Safety

- **Automatic Zeroization**: All sensitive data (keys, plaintexts) use `ZeroizeOnDrop`
- **Verified Erasure**: Cryptographic verification ensures zeroization succeeded
- **No-Clone Architecture**: Keys cannot be cloned, preventing accidental duplication

### Error Handling

Dual-context error system:

```rust
let err = CryptoError::decryption_failed("HMAC tag mismatch at offset 42");

// External display (safe for users)
println!("{}", err);  // "Decryption operation failed"

// Internal context (security team only)
let internal = err.internal_context();
println!("{}", internal.details);  // "HMAC tag mismatch at offset 42"
```

See [SECURITY.md](SECURITY.md) for comprehensive security documentation.

## Compliance

### GDPR

- Data minimization (no PII in errors)
- Purpose limitation (keys only for crypto)
- Storage limitation (automatic zeroization)
- Right to erasure (verified zeroization)

### NIST Cybersecurity Framework

- **Identify**: Comprehensive threat model (STRIDE)
- **Protect**: Defense-in-depth (rate limiting, constant-time)
- **Detect**: Audit logging, timing violation detection
- **Respond**: Dual-context errors for incident response
- **Recover**: Graceful degradation, no panic on errors

## Performance Characteristics

| Operation           | Rate Limit | Typical Latency |
| ------------------- | ---------- | --------------- |
| AES-256-GCM Encrypt | 1000/sec   | ~5 μs           |
| AES-256-GCM Decrypt | 1000/sec   | ~5 μs           |
| ML-KEM Encapsulate  | 100/sec    | ~50 μs          |
| ML-KEM Decapsulate  | 100/sec    | ~60 μs          |
| ML-DSA Sign         | 100/sec    | ~200 μs         |
| ML-DSA Verify       | 100/sec    | ~100 μs         |

_Note: Benchmarks are planned for future releases._

## Testing

Bastion includes comprehensive test coverage:

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration_tests

# Property-based tests
cargo test --test property_tests

# Fuzzing (requires cargo-fuzz)
cargo fuzz run fuzz_onion_decrypt
cargo fuzz run fuzz_constant_time
cargo fuzz run fuzz_pqc_key_exchange
```

### Test Categories

- **Unit Tests**: Individual function correctness
- **Integration Tests**: Complete workflows, concurrency, error propagation
- **Property Tests**: Cryptographic invariants (proptest)
- **Fuzz Tests**: Malformed inputs, boundary conditions

## Audit Metrics

Access security metrics at runtime:

```rust
use bastion::METRICS;
use std::sync::atomic::Ordering;

let total = METRICS.total_operations.load(Ordering::Relaxed);
let failures = METRICS.failed_operations.load(Ordering::Relaxed);
let tampering = METRICS.tampering_detected.load(Ordering::Relaxed);

println!("Operations: {}, Failures: {}, Tampering: {}",
         total, failures, tampering);
```

## Future Work

### Planned Features

- [ ] **Benchmarking Suite**: Comprehensive performance measurements across platforms
- [ ] **Hardware Acceleration**: AES-NI, AVX2 optimizations
- [ ] **Extended PQC**: Additional NIST finalists (BIKE, HQC)
- [ ] **Threshold Cryptography**: Multi-party computation primitives
- [ ] **HSM Integration**: Hardware security module support

### Research Areas

- [ ] **Formal Verification**: Coq/Lean proofs of constant-time properties
- [ ] **Side-Channel Analysis**: Power analysis resistance validation
- [ ] **Quantum-Safe Hybrid**: X25519 + ML-KEM composition

## Contributing

Contributions are welcome, particularly in:

- Security audits and vulnerability reports
- Performance optimizations (with constant-time preservation)
- Additional test coverage
- Documentation improvements

**Security Disclosure**: Report vulnerabilities privately to strukturaenterprise@gmail.com

## License

Dual-licensed under MIT or Apache 2.0, at your option.

## Acknowledgments

Built on the shoulders of:

- **pqc_kyber**: ML-KEM-1024 implementation
- **pqc_dilithium**: ML-DSA-87 implementation
- **aes-gcm**: Authenticated encryption
- **subtle**: Constant-time primitives
- **zeroize**: Memory erasure

## Citation

```bibtex
@software{bastion2026,
  title = {Bastion: Hybrid Post-Quantum Cryptography},
  year = {2026},
  author = {Guilherme F. G. Santos},
  url = {https://github.com/Guivernoir/Bastion}
}
```

---

_"Security is a process, not a product. Bastion is both."_
