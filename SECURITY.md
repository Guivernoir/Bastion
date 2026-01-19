# Bastion Security Documentation

**Last Updated**: January 2026  
**Version**: 0.1.0  
**Classification**: Public

> _"In battle, there are not more than two methods of attack: the direct and the indirect. Yet these two in combination give rise to an endless series of maneuvers."_ — Sun Tzu

## Table of Contents

1. [Security Model](#security-model)
2. [Threat Model (STRIDE)](#threat-model-stride)
3. [Cryptographic Specifications](#cryptographic-specifications)
4. [Side-Channel Protections](#side-channel-protections)
5. [Memory Safety](#memory-safety)
6. [Compliance](#compliance)
7. [Attack Surface Analysis](#attack-surface-analysis)
8. [Operational Security](#operational-security)
9. [Vulnerability Disclosure](#vulnerability-disclosure)
10. [Security Assumptions](#security-assumptions)

---

## Security Model

Bastion operates under a **defense-in-depth** security model with the following principles:

### Core Principles

1. **Constant-Time Execution**: All cryptographic operations enforce timing constraints
2. **Information Hiding**: External errors are opaque; internal context is privileged
3. **Fail-Secure**: All failures result in secure error states, never undefined behavior
4. **Audit-First**: Every security-relevant event is logged before execution
5. **Memory Isolation**: No key material can be accidentally duplicated or retained

### Security Boundaries

```
┌─────────────────────────────────────────────────────┐
│  Untrusted External Input                          │
│  • Network packets                                  │
│  • User-provided keys                               │
│  • Configuration data                               │
└─────────────────┬───────────────────────────────────┘
                  │
                  ↓ Validation & Rate Limiting
┌─────────────────────────────────────────────────────┐
│  Trusted Cryptographic Operations                   │
│  • Constant-time primitives                         │
│  • Authenticated encryption                         │
│  • Post-quantum algorithms                          │
└─────────────────┬───────────────────────────────────┘
                  │
                  ↓ Audit Logging
┌─────────────────────────────────────────────────────┐
│  Secure Output                                      │
│  • Opaque error messages                            │
│  • Zeroized memory                                  │
│  • Audit trails                                     │
└─────────────────────────────────────────────────────┘
```

---

## Threat Model (STRIDE)

Bastion is designed to mitigate threats across the full STRIDE spectrum.

### S - Spoofing Identity

**Threat**: Attacker impersonates legitimate parties

**Mitigations**:

- Post-quantum digital signatures (ML-DSA-87)
- Constant-time public key verification
- Authentication failures logged to audit trail
- Rate limiting prevents brute-force attacks

**Attack Scenarios Defended**:

- ✅ Man-in-the-middle during key exchange
- ✅ Replay attacks (unique nonces per encryption)
- ✅ Public key substitution
- ✅ Signature forgery attempts

### T - Tampering with Data

**Threat**: Attacker modifies data in transit or at rest

**Mitigations**:

- Authenticated encryption (AES-256-GCM with 128-bit tags)
- Constant-time tag verification
- Tampering detected and logged before plaintext exposure
- IND-CCA2 secure key exchange (ML-KEM-1024)

**Attack Scenarios Defended**:

- ✅ Ciphertext modification
- ✅ Bit-flipping attacks
- ✅ Packet truncation/extension
- ✅ Malleability attacks

### R - Repudiation

**Threat**: Attacker denies performing actions

**Mitigations**:

- Comprehensive audit logging (sequence numbers, timestamps)
- Non-repudiable digital signatures
- Monotonic error sequence counters
- GDPR-compliant audit trails

**Attack Scenarios Defended**:

- ✅ Denial of signature creation
- ✅ Audit log manipulation (sequence numbers prevent)
- ✅ Timestamp manipulation (nanosecond precision)

### I - Information Disclosure

**Threat**: Unauthorized access to sensitive information

**Mitigations**:

- Dual-context error system (opaque external, detailed internal)
- Automatic memory zeroization with verification
- No PII in logs or error messages
- Constant-time operations prevent timing leaks
- No-clone architecture prevents accidental key copies

**Attack Scenarios Defended**:

- ✅ Timing attacks (constant-time primitives)
- ✅ Error message analysis (opaque errors)
- ✅ Memory dumps (zeroized keys)
- ✅ Log file analysis (no PII, sanitized contexts)
- ✅ Side-channel attacks (timing guards, fixed iteration counts)

**Critical**: Bastion's dual-context errors mean sensitive debugging information (internal context) must **never** be:

- Displayed to untrusted users
- Logged to public-facing systems
- Transmitted over untrusted networks
- Included in user-facing error messages

### D - Denial of Service

**Threat**: Attacker exhausts system resources

**Mitigations**:

- Rate limiting (1000 ops/sec symmetric, 100 ops/sec PQC)
- Packet size validation before expensive operations
- Early rejection of malformed inputs
- Timing violations trigger automatic throttling
- No unbounded memory allocations

**Attack Scenarios Defended**:

- ✅ Decryption oracle attacks
- ✅ Signature oracle attacks
- ✅ CPU exhaustion (rate limiting)
- ✅ Memory exhaustion (bounded allocations)
- ✅ Amplification attacks (early validation)

### E - Elevation of Privilege

**Threat**: Attacker gains unauthorized capabilities

**Mitigations**:

- Immutable cryptographic keys (no mutation after creation)
- Single-owner architecture (keys cannot be cloned)
- Principle of least privilege (minimal API surface)
- No unsafe code (`#![deny(unsafe_code)]`)
- Type-safe error handling (no panics in crypto operations)

**Attack Scenarios Defended**:

- ✅ Key extraction via cloning
- ✅ Permission escalation via error conditions
- ✅ Capability leak via shared references
- ✅ Unsafe memory access (forbidden by compiler)

---

## Cryptographic Specifications

### Symmetric Encryption: AES-256-GCM

**Algorithm**: AES-256 in Galois/Counter Mode  
**Key Size**: 256 bits  
**Nonce Size**: 96 bits (random, never reused)  
**Tag Size**: 128 bits  
**Security Level**: 256-bit confidentiality, 128-bit authenticity

**Properties**:

- IND-CPA secure (indistinguishability under chosen-plaintext attack)
- INT-CTXT secure (integrity of ciphertexts)
- Combined: AEAD (authenticated encryption with associated data)

**Packet Format**:

```
┌──────────┬─────────────────┬────────────┐
│  Nonce   │   Ciphertext    │    Tag     │
│  12 B    │    variable     │    16 B    │
└──────────┴─────────────────┴────────────┘
```

**Threat Resistance**:

- ✅ Chosen-plaintext attacks (CPA)
- ✅ Chosen-ciphertext attacks (CCA)
- ✅ Forgery attacks (128-bit authentication tag)
- ✅ Replay attacks (random nonces)

### Post-Quantum Key Exchange: ML-KEM-1024

**Algorithm**: Module-Lattice-Based Key Encapsulation Mechanism (Kyber-1024)  
**NIST Standard**: FIPS 203  
**Security Level**: NIST Level 5 (AES-256 equivalent)  
**Public Key**: 1568 bytes  
**Ciphertext**: 1568 bytes  
**Shared Secret**: 32 bytes (expanded to 64 via SHA3-512)

**Properties**:

- IND-CCA2 secure (indistinguishability under adaptive chosen-ciphertext attack)
- Quantum-resistant (based on Module-LWE problem)
- Forward secrecy (each exchange uses unique ephemeral keys)

**Hardness Assumption**: Module Learning With Errors (Module-LWE)

**Threat Resistance**:

- ✅ Quantum attacks (Shor's algorithm ineffective)
- ✅ Classical attacks (lattice reduction intractable)
- ✅ Adaptive chosen-ciphertext attacks (CCA2 secure)
- ✅ Man-in-the-middle (when combined with authentication)

### Post-Quantum Signatures: ML-DSA-87

**Algorithm**: Module-Lattice-Based Digital Signature Algorithm (Dilithium-5)  
**NIST Standard**: FIPS 204  
**Security Level**: NIST Level 5 (SHA3-512 equivalent)  
**Public Key**: 2592 bytes  
**Signature**: 4627 bytes

**Properties**:

- EUF-CMA secure (existentially unforgeable under chosen-message attack)
- Quantum-resistant (based on Module-LWE and Module-SIS problems)
- Deterministic signatures (no randomness required)

**Hardness Assumptions**:

- Module Learning With Errors (Module-LWE)
- Module Short Integer Solution (Module-SIS)

**Threat Resistance**:

- ✅ Quantum attacks (Shor's algorithm ineffective)
- ✅ Forgery attacks (EUF-CMA secure)
- ✅ Signature malleability (prevented by design)
- ✅ Chosen-message attacks (CMA secure)

### Key Derivation: SHA3-512

**Algorithm**: Keccak-based SHA3  
**NIST Standard**: FIPS 202  
**Output Size**: 512 bits (64 bytes)

**Properties**:

- Preimage resistance
- Second preimage resistance
- Collision resistance
- Immune to length-extension attacks

---

## Side-Channel Protections

### Timing Attack Resistance

**Implementation**:

```rust
pub struct TimingGuard {
    start: Instant,
    expected_min_ns: u64,
    expected_max_ns: u64,
    operation_name: &'static str,
}
```

**Enforcement**:

1. All cryptographic operations wrapped in `TimingGuard`
2. Operations completing too fast → logged as `TimingViolation`
3. Operations exceeding bounds → logged as potential DoS
4. Violations increment global counter: `TIMING_VIOLATIONS`

**Monitored Operations**:

- AES-256-GCM encryption: min 5 μs
- AES-256-GCM decryption: min 5 μs
- ML-KEM encapsulation: min 50 μs
- ML-KEM decapsulation: min 60 μs
- ML-DSA signing: min 200 μs
- ML-DSA verification: min 100 μs

**Defense Against**:

- ✅ Timing attacks via response time analysis
- ✅ Cache-timing attacks (fixed iteration counts)
- ✅ Branch prediction attacks (no data-dependent branches)

### Constant-Time Primitives

All comparisons use constant-time operations from the `subtle` crate:

```rust
// Standard comparison (VULNERABLE to timing attacks)
if secret_key == user_input {  // ❌ NEVER DO THIS
    grant_access();
}

// Constant-time comparison (SECURE)
if ct_eq(&secret_key, &user_input) {  // ✅ ALWAYS DO THIS
    grant_access();
}
```

**Operations**:

- `ct_eq()`: Constant-time equality
- `ct_less_than()`: Constant-time comparison
- `ct_copy_if()`: Conditional copy without branches
- `ct_select()`: Branch-free selection
- `ct_xor()`: Fixed-iteration XOR
- `ct_mod_reduce()`: Constant-time modular reduction
- `ct_hamming_weight()`: Fixed-iteration bit counting

**Guarantees**:

- Fixed iteration counts (no early exits)
- Constant memory access patterns
- No data-dependent branches
- Compiler-barrier protected (via `subtle` primitives)

### Power Analysis Resistance

While Bastion is software-based and cannot provide complete power analysis resistance (which requires hardware support), it minimizes vulnerability through:

1. **Constant-time execution**: No data-dependent branching
2. **Fixed iteration counts**: Uniform power consumption profiles
3. **No table lookups**: Prevents cache-timing side channels

**Note**: For scenarios requiring DPA/SPA resistance, deploy on hardware with:

- Power randomization (noise injection)
- Dual-rail logic
- Hardware security modules (HSMs)

---

## Memory Safety

### Automatic Zeroization

All sensitive data types use `ZeroizeOnDrop`:

```rust
#[derive(ZeroizeOnDrop)]
pub struct OnionLayer {
    cipher: Aes256Gcm,      // Zeroized on drop
    rate_limiter: ...,      // #[zeroize(skip)]
}
```

**Zeroized Types**:

- Symmetric keys (32 bytes)
- Post-quantum private keys (ML-KEM, ML-DSA)
- Shared secrets (64 bytes)
- Plaintext buffers (after encryption)
- Error internal contexts (sensitive debugging info)

### Verified Zeroization

Bastion doesn't just zeroize—it **verifies** zeroization succeeded:

```rust
pub fn ct_zeroize_verify(buffer: &mut [u8]) -> Result<()> {
    buffer.zeroize();

    // Cryptographic verification
    let mut all_zero = Choice::from(1u8);
    for i in 0..buffer.len() {
        all_zero &= buffer[i].ct_eq(&0u8);
    }

    if bool::from(all_zero) {
        Ok(())
    } else {
        Err(CryptoError::sanitization_failed("Zeroization failed"))
    }
}
```

**Defense Against**:

- ✅ Compiler optimizations removing "dead" zeroization
- ✅ Memory dumps containing keys
- ✅ Core dumps exposing secrets
- ✅ Swap file leakage

### No-Clone Architecture

Keys cannot be cloned (preventing accidental duplication):

```rust
// This compiles ✅
let key = [0x42u8; 32];
let layer = OnionLayer::from_key(key);  // key is moved, not copied

// This fails to compile ❌
let layer2 = OnionLayer::from_key(key);  // Error: value used after move
```

**Benefits**:

- Single memory location for key material
- Guaranteed cleanup on scope exit
- No hidden copies in unexpected locations
- Reduced attack surface for memory extraction

---

## Compliance

### GDPR (General Data Protection Regulation)

Bastion is designed for GDPR compliance:

#### Article 5: Principles

| Principle                       | Implementation                                  |
| ------------------------------- | ----------------------------------------------- |
| **Data Minimization**           | No PII in errors, logs, or audit trails         |
| **Purpose Limitation**          | Keys used only for cryptographic operations     |
| **Storage Limitation**          | Automatic zeroization ensures no data retention |
| **Integrity & Confidentiality** | Authenticated encryption, constant-time ops     |

#### Article 17: Right to Erasure

```rust
// Verified zeroization ensures compliance
let mut user_data = vec![0x42u8; 1024];
ct_zeroize_verify(&mut user_data)?;  // Cryptographically verified
```

#### Article 25: Privacy by Design

- Default-secure error handling (external errors opaque)
- Minimal API surface (principle of least privilege)
- No opt-in required for security features (always enabled)

#### Article 32: Security of Processing

- State-of-the-art cryptography (NIST post-quantum standards)
- Pseudonymization (no user identifiers in audit logs)
- Confidentiality through authenticated encryption
- Integrity through digital signatures

### NIST Cybersecurity Framework

| Function     | Implementation                                                       |
| ------------ | -------------------------------------------------------------------- |
| **Identify** | STRIDE threat model, comprehensive attack surface analysis           |
| **Protect**  | Rate limiting, constant-time ops, authenticated encryption           |
| **Detect**   | Audit logging, timing violation detection, tampering alerts          |
| **Respond**  | Dual-context errors for incident response, monotonic error sequences |
| **Recover**  | Graceful degradation, no panics, fail-secure defaults                |

### SOC 2 Compliance

Relevant Trust Service Criteria:

- **CC6.1**: Logical and physical access controls (rate limiting, immutable keys)
- **CC6.6**: Encryption of confidential information (AES-256-GCM)
- **CC7.2**: Detection of security events (audit logging, METRICS)

---

## Attack Surface Analysis

### Network Attack Surface

**Input Validation**:

- Packet size checks before decryption
- Public key length validation
- Ciphertext length validation
- Signature length validation

**Rate Limiting**:

- Symmetric operations: 1000/sec (prevents decryption oracles)
- PQC operations: 100/sec (prevents CPU exhaustion)
- Configurable per-instance limits supported

**Amplification Prevention**:

- Early rejection of malformed packets
- Bounded memory allocations
- No recursive processing

### Cryptographic Attack Surface

**Nonce Management**:

- ✅ Random nonces (never sequential)
- ✅ No nonce reuse (unique per encryption)
- ✅ Sufficient size (96 bits = 2^96 space)

**Key Management**:

- ✅ Keys consumed on use (move semantics)
- ✅ Immediate zeroization (verified)
- ✅ No key cloning (compile-time enforced)

**Error Handling**:

- ✅ No error-based timing leaks (constant-time verification)
- ✅ No information disclosure (opaque errors)
- ✅ No panics in crypto paths (Result types)

### Code Audit Surface

**Safe Rust Only**:

```rust
#![deny(unsafe_code)]  // Compile error on unsafe blocks
```

**Lints Enforced**:

```rust
#![warn(
    missing_docs,
    clippy::unwrap_used,    // No panics
    clippy::expect_used,    // No panics
    clippy::panic,          // No panics
    clippy::clone_on_ref_ptr
)]
```

**Test Coverage**:

- Unit tests: Individual function correctness
- Integration tests: Complete workflows, concurrency
- Property tests: Cryptographic invariants (proptest)
- Fuzz tests: Malformed inputs, boundary conditions

---

## Operational Security

### Deployment Checklist

- [ ] **Entropy Source**: Verify system RNG has sufficient entropy
- [ ] **Rate Limits**: Configure appropriate limits for your threat model
- [ ] **Monitoring**: Set up alerts for `METRICS.tampering_detected`
- [ ] **Audit Logs**: Configure secure storage for audit trails
- [ ] **Key Rotation**: Implement periodic keypair regeneration
- [ ] **Memory Limits**: Set bounds to prevent swap file usage
- [ ] **Error Handling**: Route internal context only to privileged systems

### Monitoring Metrics

```rust
use bastion::METRICS;
use std::sync::atomic::Ordering;

// Monitor these in production
let total = METRICS.total_operations.load(Ordering::Relaxed);
let failures = METRICS.failed_operations.load(Ordering::Relaxed);
let rate_limits = METRICS.rate_limit_hits.load(Ordering::Relaxed);
let timing = METRICS.timing_violations.load(Ordering::Relaxed);
let auth_failures = METRICS.auth_failures.load(Ordering::Relaxed);
let tampering = METRICS.tampering_detected.load(Ordering::Relaxed);
```

**Alert Thresholds**:

- `timing_violations > 0`: Investigate immediately (potential attack)
- `tampering_detected > threshold`: Analyze packet sources
- `rate_limit_hits` spike: Potential DoS attack
- `auth_failures` spike: Credential stuffing or brute force

### Secure Coding Guidelines

#### ✅ DO

```rust
// Use constant-time comparisons
if ct_eq(&expected, &actual) { ... }

// Return Results, not panics
pub fn operation() -> Result<Output> { ... }

// Zeroize sensitive data
let mut key = [0u8; 32];
ct_zeroize_verify(&mut key)?;

// Use external error context only
log::error!("{}", error);  // Opaque

// Check rate limits
rate_limiter.check().map_err(|_| ...)?;
```

#### ❌ DON'T

```rust
// Never use timing-vulnerable comparisons
if secret == input { ... }  // ❌ TIMING LEAK

// Never panic in crypto operations
assert!(condition);  // ❌ PANIC

// Never log internal error context publicly
log::error!("{:?}", error.internal_context());  // ❌ INFO LEAK

// Never clone keys
let key2 = key.clone();  // ❌ Won't compile (good!)

// Never skip rate limiting
operation_without_rate_limit();  // ❌ DOS RISK
```

---

## Vulnerability Disclosure

### Reporting Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

**Report privately to**: `strukturaenterprise@gmail.com`

### What to Include

1. **Description**: Clear explanation of the vulnerability
2. **Impact**: STRIDE category and severity assessment
3. **Reproduction**: Minimal code to reproduce
4. **Affected Versions**: Which releases are vulnerable
5. **Proposed Fix**: If you have one (optional)

### Response Timeline

- **24 hours**: Acknowledgment of receipt
- **72 hours**: Initial severity assessment
- **7 days**: Detailed analysis and response
- **30 days**: Coordinated disclosure (if critical)

### Hall of Fame

Security researchers who responsibly disclose vulnerabilities will be credited (with permission) in:

- SECURITY.md
- Release notes
- Project homepage

### Scope

**In Scope**:

- Timing attacks on cryptographic operations
- Memory safety violations
- Authentication bypasses
- Rate limit bypasses
- Information disclosure via errors

**Out of Scope**:

- Denial of service via resource exhaustion (by design, rate limited)
- Social engineering
- Physical access attacks
- Issues in dependencies (report upstream)

---

## Security Assumptions

Bastion's security guarantees depend on these assumptions:

### Cryptographic Assumptions

1. **AES-256 Security**: AES-256 provides 256-bit security
2. **SHA3 Security**: SHA3-512 provides 512-bit security
3. **Lattice Hardness**: Module-LWE and Module-SIS are quantum-hard
4. **RNG Entropy**: System RNG provides cryptographically secure randomness

### Operational Assumptions

1. **Memory Protection**: OS provides process memory isolation
2. **No Memory Inspection**: Attacker cannot read process memory
3. **No Physical Access**: Attacker has remote access only
4. **Trusted Compiler**: Rust compiler doesn't introduce backdoors
5. **Trusted Dependencies**: Crates from crates.io are not malicious

### Implementation Assumptions

1. **No Compiler Bugs**: Rust compiler correctly implements language spec
2. **No Hardware Bugs**: CPU executes instructions correctly (no Spectre-class)
3. **Zeroization Works**: Memory writes are not optimized away
4. **Timing Accurate**: `Instant::now()` provides reliable timing

### Threat Model Assumptions

**Attacker Capabilities**:

- ✅ Network access (can intercept/modify packets)
- ✅ Timing measurements (can measure response times)
- ✅ Chosen-plaintext attacks (can encrypt chosen data)
- ✅ Chosen-ciphertext attacks (can attempt decryption)
- ✅ Quantum computer (post-quantum algorithms resist)

**Attacker Limitations**:

- ❌ No process memory access
- ❌ No physical access to hardware
- ❌ No privileged OS access
- ❌ No side-channel measurement equipment (DPA/SPA)

---

## Conclusion

Bastion provides defense-in-depth security through:

1. **Cryptographic Strength**: NIST-standardized post-quantum algorithms
2. **Implementation Rigor**: Constant-time operations, verified zeroization
3. **Operational Resilience**: Rate limiting, audit logging, graceful degradation
4. **Compliance Alignment**: GDPR, NIST CSF, SOC 2 ready

**However**: No cryptographic library can guarantee security if:

- Keys are poorly managed
- Entropy sources are weak
- Dependencies are compromised
- Operational procedures are inadequate

Security is a **shared responsibility** between Bastion and its operators.

---

_"The general who wins a battle makes many calculations before the battle is fought."_ — Sun Tzu

_"Bastion makes those calculations for you."_

**Questions?** strukturaenterprise@gmail.com
