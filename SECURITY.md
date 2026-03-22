# Security Documentation — Bastion / MLSigcrypt-v3

Last updated: 2026-03-22

---

## Preamble

This document describes the security model, design controls, threat model,
and known limitations of the MLSigcrypt-v3 scheme implemented in this crate.

It is written to be useful to someone evaluating whether this crate is
appropriate for a particular deployment. It tries to be specific about what
is known, what is unknown, and where informal reasoning ends and formal proof
begins.

**The headline conclusion**: the implementation is hardened and most previously
listed design gaps have been narrowed, but the scheme still has one unresolved
theoretical issue and one unresolved external-validation issue:

- the coupling between the signing mask `y` and the encapsulation randomness,
- the current ML-DSA implementation does not yet match official ACVP example
  outputs.

Deployments that require provable or standards-conformant guarantees should not
use Level 3 until both are resolved.

---

## Security Objectives

The scheme aims to provide the following properties for a packet sent from
sender S to recipient R:

**Confidentiality**: A party that is not R cannot recover the plaintext, even
given the ciphertext, the sender's public key, and any other packets between S
and R.

**Authenticity**: A party that is not S cannot produce a packet that R will
accept as originating from S, even given S's public key and any other packets.

**AAD binding**: The associated data `aad` is cryptographically bound to the
packet. A packet produced with `aad = X` will not verify under any other value
of `aad`.

**Sender binding**: The sender's key identity is bound into the packet challenge.
A packet produced by S for R cannot be re-attributed to a different sender S'
without invalidating the challenge.

**Recipient binding**: The recipient's encapsulation key is bound into the
challenge. A packet produced for R cannot be decrypted by a different recipient
R' without the challenge failing.

**Unified failure**: All packet-open failures return the same error string with
no detail. The implementation does not distinguish between wrong key, tampered
ciphertext, tampered encap, wrong AAD, or malformed packet at the public API
boundary.

---

## Cryptographic Components

### Shared Lattice Matrix

A single 8×8 polynomial matrix `A` over `R_q = Z_q[X]/(X^256+1)`, `q = 8380417`,
is generated per identity from the seed `ρ_shared = SHAKE-128(matrix_seed)`.

This matrix is used for both the signing component (ML-DSA rows 0..7 × columns 0..6)
and the encapsulation component (4×4 top-left submatrix). The security assumption
is that an adversary who sees `A` gains no structural advantage — this is consistent
with how both ML-DSA and the algebraic encapsulation are defined, since `A` is
public in both primitives independently.

### Algebraic Encapsulation

The encapsulation is a Regev-style construction:

```
Key generation:
  s_R, e_R ← small distributions (seed from sk_enc_seed)
  t_R = A · s_R + e_R           (encapsulation public key)

Encapsulation:
  r, e₁, e₂ ← small distributions (seed from SHAKE256(ENCAP_MASK_DOMAIN ‖ packed_y))
  u = Aᵀ · r + e₁
  v = t_Rᵀ · r + e₂ + encode(mkey)
  encap = u ‖ v

Decapsulation:
  v - s_Rᵀ · u
    = t_Rᵀ · r + e₂ + encode(mkey) - s_Rᵀ · (Aᵀ · r + e₁)
    = (A · s_R + e_R)ᵀ · r + e₂ + encode(mkey) - s_Rᵀ · Aᵀ · r - s_Rᵀ · e₁
    = s_Rᵀ · Aᵀ · r + e_Rᵀ · r + e₂ + encode(mkey) - s_Rᵀ · Aᵀ · r - s_Rᵀ · e₁
    = e_Rᵀ · r + e₂ - s_Rᵀ · e₁ + encode(mkey)
```

The noise term `e_Rᵀ · r + e₂ - s_Rᵀ · e₁` is small (all vectors have small
coefficients). The decapsulation threshold-decodes each coefficient: values close
to 0 decode as bit 0, values close to q/2 decode as bit 1. The scheme is
correct when the noise term does not push a coefficient across the decoding
threshold.

The security of this construction against a passive adversary (IND-CPA) follows
from the standard Module-LWE assumption under the distribution of `(A, t_R, u, v)`
when `r, e₁, e₂` are freshly sampled. The full IND-CCA2 argument for the
signcryption scheme additionally requires showing that the challenge binds the
encapsulation to the signing component in a way that prevents adaptive attacks —
this is part of the unwritten proof (see OPEN_PROBLEMS.md).

### Signing Component

The signing component follows the ML-DSA-87 rejection-sampling structure
(FIPS 204 Algorithm 2), with one modification: the challenge incorporates
the encryption context.

Standard ML-DSA computes `c̃ = H(µ ‖ w₁_packed)` where `µ = H(tr ‖ msg)`.
MLSigcrypt-v3 computes:

```
c̃ = SHAKE256(DOMAIN_CHAL ‖ w₁_packed ‖ encap ‖ aad_digest
             ‖ tr_S ‖ pk_enc_R ‖ ct_len ‖ ct)
```

This construction binds the ciphertext and encapsulation into the signing
transcript. The consequence is that the ciphertext cannot be replaced without
invalidating `c̃`. It also means the sender implicitly signs the encryption
— a packet signed by S for R under key `mkey` cannot be re-encrypted under
a different `mkey` and remain valid.

The sender binding now uses the standard ML-DSA transcript hash
`tr_S = SHAKE256(pk_sig_S)` rather than the raw public-key blob. The remaining
proof work is therefore not about sender-key binding anymore; it is about the
shared-randomness coupling described in [OPEN_PROBLEMS.md](OPEN_PROBLEMS.md).

### Keystream

Payload encryption uses a SHAKE-256 duplex sponge:

```
S_E.absorb("MLSigcrypt-v3/enc\x03")
S_E.absorb(mkey)
S_E.absorb(key_id_S)
S_E.absorb(key_id_R)
S_E.absorb(encap)
keystream = S_E.squeeze(len(plaintext))
ciphertext = plaintext XOR keystream
```

The message key `mkey` is 32 bytes sampled from the OS. It is not derived from
`y` or any signing intermediate. `encap` binds the keystream to the specific
encapsulation used in this packet.

### Hash and XOF Primitives

All hash and XOF operations use a single internal Keccak-f[1600] implementation.
Specific constructions:

| Purpose | Construction |
|---------|--------------|
| Key derivation | SHA3-512 (rate 72 bytes, suffix 0x06) |
| Matrix generation | SHAKE-128 (rate 168 bytes, suffix 0x1F) |
| AAD normalisation | SHA3-512 with domain prefix |
| Mask sampling | SHAKE-256 (rate 136 bytes, suffix 0x1F) |
| Challenge derivation | SHAKE-256 |
| Keystream | SHAKE-256 duplex |
| Encap randomness | SHAKE-256 with domain prefix |

Domain separation is enforced by distinct ASCII prefixes on every sponge
invocation. No two protocol contexts share a prefix.

---

## Implementation Controls

### Zeroization

Sensitive material is explicitly overwritten using `core::ptr::write_volatile`
followed by a `compiler_fence(SeqCst)`. This is intended to prevent the
compiler from treating the writes as dead stores. The `#[inline(never)]`
annotation on the core `zeroize_mem` function is mandatory — inlining would
allow the surrounding optimisation context to re-examine observability and
potentially eliminate the stores.

Material zeroed includes:

- Master secret after key derivation.
- `matrix_seed` and derived seeds after the matrix is generated.
- `y`, `cs1`, `cs2`, `ct0`, `z`, `h` after the signing loop.
- `mkey` and all sponge states after keystream generation.
- `aad_digest` and `rho_prime` after use.
- The plaintext output buffer if `unsigncrypt` fails.

The `Secret<N>` RAII wrapper in `signcrypt.rs` provides a fallback zeroize-on-drop
for critical values that might be dropped early in an error path.

**Limitation**: Zeroization by volatile write is a compiler-level defence, not
a hardware-level guarantee. Cache lines, register spills, and CPU microarchitectural
state may retain copies of sensitive material beyond the software wipe. This is
a known limitation of software-only zeroization on commodity hardware. It is not
addressed by this crate.

### Constant-Time Operations

The following comparisons use `ct_eq`, which reads all bytes via `read_volatile`
and accumulates differences without branching:

- `alg_id` check in `unsigncrypt`.
- `key_id_S` check in `unsigncrypt`.
- `key_id_R` check in `unsigncrypt`.
- `c_tilde` comparison in `verify_signature_challenge`.

The ML-DSA signing loop contains a rejection branch whose execution time leaks
the number of iterations. This is not a vulnerability in the context of this
scheme — the iteration count has a geometric distribution independent of secret
material — but it does mean the per-call timing of `signcrypt` is variable. The
public API timing floor reduces small iteration-count variance but is not a hard
constant-time bound.

**Limitation**: The `ct_eq` helper uses `read_volatile` and a `compiler_fence`
to prevent compiler-level short-circuits. It does not constitute a formal
constant-time proof against hardware side-channels (cache timing, power analysis,
branch predictors). Side-channel analysis of a hardware implementation is not in
scope for this document.

### Timing Floors

Public API wrappers spin-loop until a floor time has elapsed:

| Operation      | Floor    |
|----------------|----------|
| Key generation | 0 ns     |
| Signcrypt      | 20 000 000 ns (20 ms) by default |
| Unsigncrypt    | 10 000 000 ns (10 ms) by default |

Key generation has no floor because it has no adversary-controlled input at the
public boundary. The signcrypt floor is set above the expected signing time to
absorb typical iteration-count variance. The unsigncrypt floor is set above the
expected verification time to reduce early-exit timing signals on invalid packets.

These floors are heuristic defaults and are configurable with the environment
variables `BASTION_MLSIGCRYPT_KEYGEN_FLOOR_NS`,
`BASTION_MLSIGCRYPT_SIGNCRYPT_FLOOR_NS`, and
`BASTION_MLSIGCRYPT_UNSIGNCRYPT_FLOOR_NS`.

They may not hold on significantly faster or slower hardware and should be tuned
for the target deployment environment.

### Allocation and Dependency Policy

Runtime dependencies are empty. The crate has no `[dependencies]` entries. All
operations use caller-provided output buffers. The public API does not allocate
heap memory in hot paths.

This policy has two purposes: it keeps the supply-chain attack surface minimal,
and it makes heap allocation measurable — the `write_results` example tracks
allocator calls, and CI fails if any appear in the hot path.

### Unified Failure Semantics

All packet-open failures produce a single error string: `"mlsigcrypt-v3 open failed"`.
No internal state, failure cause, or field offset is disclosed. This prevents oracle
attacks where an adversary infers partial information about a secret by observing
which specific check failed.

---

## Threat Model

### In Scope

- An active network adversary who can observe, replay, modify, and inject packets.
- An adversary who can adaptively query signcrypt and unsigncrypt on messages and
  packets of their choice (CCA2 model), subject to the usual game restrictions.
- A colluding adversary who obtains one party's secret key after the session
  (forward secrecy is not claimed — keys are long-lived).
- An adversary running a classical or quantum computer. The hardness assumptions
  (Module-LWE and Module-SIS) are believed to be post-quantum secure under current
  understanding.

### Out of Scope

- **Key management**: the crate does not address key distribution, revocation,
  or storage. Keys are raw byte buffers; protecting them is the caller's responsibility.
- **Side-channel attacks on hardware**: power analysis, electromagnetic analysis,
  fault injection, or cache-timing attacks at the microarchitectural level are not
  addressed.
- **Metadata leakage**: packet lengths reveal the plaintext length. Traffic
  analysis is not addressed.
- **Forward secrecy**: keys are long-lived. Compromising a secret key after the
  fact allows decryption of all previously captured packets sent to that identity.
- **Multi-user security with related keys**: if two identities share a master secret,
  they share the same matrix `A`. The security of this configuration has not been
  analysed.
- **Denial of service via expensive operations**: the signing loop is bounded but
  variable. An adversary who can trigger unsigncrypt on adversarially crafted packets
  will always hit the cheap path (header checks fail early), but a malicious caller
  who generates valid-looking packets with the intent of maximising signing iterations
  is not specifically addressed.

---

## Compliance Note

MLSigcrypt-v3 reuses ML-DSA-87 parameter sets (FIPS 204) but the overall packet
construction is not a validated FIPS 140-3 module. The custom SHAKE-256 AEAD
construction and the algebraic encapsulation are not covered by any existing
validation.

Additionally, the embedded ML-DSA implementation does not currently reproduce
official ACVP example outputs, so FIPS-conformant ML-DSA behavior has not been
established even at the primitive-validation level.

Deployments that require FIPS 140-3 validated cryptography should use Level 1
of the MLSigcrypt specification (ML-KEM-1024 + ML-DSA-87 + AES-256-GCM + HKDF),
which composes validated primitives, or a separately validated implementation.

---

## Disclosure Policy

Security issues should be reported privately to the maintainers before public
disclosure. Coordinated disclosure is preferred.

Useful report content:

- Affected version or commit hash.
- A minimal reproducible example or proof of concept.
- An assessment of impact and affected configurations.
- A suggested remediation if available.

Public exploit details should not be disclosed until a fix has been coordinated.
