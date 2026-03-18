# Bastion — MLSigcrypt-v3

Bastion is a Rust crate implementing MLSigcrypt-v3, an experimental post-quantum
signcryption scheme. It combines confidentiality, integrity, and sender authenticity
into a single packet operation built on top of ML-DSA-87 (FIPS 204) lattice
arithmetic.

> **Status: Experimental.** The construction has not been formally proven secure.
> It is suitable for research, prototyping, and internal evaluation. It is not
> recommended for production systems handling sensitive data until a formal security
> proof is available. See [OPEN_PROBLEMS.md](OPEN_PROBLEMS.md) for a detailed
> account of what remains unresolved.

---

## What This Is

MLSigcrypt-v3 is a signcryption scheme — a primitive that simultaneously encrypts
a message and authenticates its sender, producing a single packet that can only be
opened by the intended recipient and carries a verifiable sender identity.

The scheme is described in three levels:

- **Level 1**: ML-KEM-1024 + ML-DSA-87 + SHAKE-256 (two-sponge design). Closest to
  standard composable primitives. Not FIPS 140-3 validated as a composition, but uses
  standardised FIPS 203/204 components.
- **Level 2**: Level 1 with a shared lattice matrix between the KEM and DSA components,
  reducing redundant NTT work during key generation.
- **Level 3** (this codebase): Algebraic signcryption. The separate ML-KEM encapsulation
  is replaced by a Regev-style encapsulation driven by the same mask vector `y` used in
  the ML-DSA signing loop. This halves the number of large NTT pipelines during
  signcrypt and unsigncrypt.

This repository implements Level 3 only.

---

## What This Is Not

- **Not a drop-in replacement for TLS, Signal, or any FIPS-validated scheme.** This
  is a research-grade primitive at an early maturity level.
- **Not formally proven secure.** The construction is plausible and the implementation
  is hardened, but the security proof reducing confidentiality and authenticity to
  Module-LWE and Module-SIS respectively has not been written or peer-reviewed.
- **Not FIPS 140-3 compliant.** The underlying ML-DSA-87 parameters are reused, but
  the overall packet construction is custom and not validated.
- **Not compatible** with Level 1 or Level 2 keys or packets.

---

## Public API

The crate exposes exactly three public cryptographic operations and three sizing
constants. Nothing else is public.

```rust
pub fn mlsigcrypt_keygen(
    pk_user_out: &mut [u8; MLSIGCRYPT_PUBLIC_KEY_SIZE],
    sk_user_out: &mut [u8; MLSIGCRYPT_SECRET_KEY_SIZE],
) -> Result<(), &'static str>;

pub fn mlsigcrypt_signcrypt(
    sk_user_sender: &[u8],
    pk_user_recipient: &[u8],
    aad: &[u8],
    message: &[u8],
    packet_out: &mut [u8],
) -> Result<usize, &'static str>;

pub fn mlsigcrypt_unsigncrypt(
    sk_user_recipient: &[u8],
    pk_user_sender: &[u8],
    aad: &[u8],
    packet: &[u8],
    plaintext_out: &mut [u8],
) -> Result<usize, &'static str>;
```

```rust
pub const MLSIGCRYPT_PUBLIC_KEY_SIZE: usize;   // 5600 bytes
pub const MLSIGCRYPT_SECRET_KEY_SIZE: usize;   // 13024 bytes
pub const MLSIGCRYPT_PACKET_OVERHEAD: usize;   // 8393 bytes (fixed per-packet cost)
```

All operations take caller-provided output buffers. No heap allocation occurs in
the hot path. All operations return a unified error string on failure with no
implementation detail.

---

## Quick Start

Add to `Cargo.toml`:

```toml
[dependencies]
crypto_bastion = "0.8.0"
```

```rust
use crypto_bastion::{
    MLSIGCRYPT_PACKET_OVERHEAD, MLSIGCRYPT_PUBLIC_KEY_SIZE, MLSIGCRYPT_SECRET_KEY_SIZE,
    mlsigcrypt_keygen, mlsigcrypt_signcrypt, mlsigcrypt_unsigncrypt,
};

let aad = b"session-context";
let msg = b"hello from alice";

let mut sender_pk = [0u8; MLSIGCRYPT_PUBLIC_KEY_SIZE];
let mut sender_sk = [0u8; MLSIGCRYPT_SECRET_KEY_SIZE];
let mut recipient_pk = [0u8; MLSIGCRYPT_PUBLIC_KEY_SIZE];
let mut recipient_sk = [0u8; MLSIGCRYPT_SECRET_KEY_SIZE];

mlsigcrypt_keygen(&mut sender_pk, &mut sender_sk)?;
mlsigcrypt_keygen(&mut recipient_pk, &mut recipient_sk)?;

let mut packet = vec![0u8; MLSIGCRYPT_PACKET_OVERHEAD + msg.len()];
let packet_len =
    mlsigcrypt_signcrypt(&sender_sk, &recipient_pk, aad, msg, &mut packet)?;

let mut plaintext = vec![0u8; msg.len()];
let plain_len = mlsigcrypt_unsigncrypt(
    &recipient_sk, &sender_pk, aad, &packet[..packet_len], &mut plaintext,
)?;

assert_eq!(&plaintext[..plain_len], msg);
```

---

## Packet Format

Every packet has a fixed-overhead prefix followed by a variable-length ciphertext:

```
[13 bytes]   alg_id = "MLSigcrypt-v3" (ASCII, no null terminator)
[1 byte]     version = 0x03
[32 bytes]   key_id_S (sender key identifier)
[32 bytes]   key_id_R (recipient key identifier)
[3680 bytes] encap = u ‖ v  (algebraic encapsulation of the message key)
[4480 bytes] z              (ML-DSA response vector, l=7 polynomials)
[64 bytes]   c̃              (challenge digest)
[83 bytes]   h              (hint bits for high-bit reconstruction)
[8 bytes]    ct_len         (ciphertext length, big-endian u64)
[N bytes]    ct             (SHAKE-256 keystream XOR plaintext)
─────────────────────────────
Fixed overhead: 8393 bytes
```

The overhead is larger than Level 1 (6281 bytes) and Level 2 (6281 bytes) because
the encapsulation `u ‖ v` uses exact 23-bit coefficient encoding (5 × 736 bytes =
3680 bytes) rather than ML-KEM's compressed 11-bit encoding. A compressed encoding
is planned for a future revision once the security proof is in place.

---

## Key Hierarchy

Each identity is derived deterministically from a 32-byte master secret:

```
msk  (32 bytes, uniform random from OS)
  │
  ├─ SHA3-512("MLSigcrypt-v3/matrix_seed" ‖ msk)[0..32]  → matrix_seed
  │         └─ SHAKE-128(matrix_seed)[0..32]              → ρ_shared
  │                  └─ expand_a(ρ_shared)                → A (shared 8×8 matrix)
  │
  ├─ SHA3-512("MLSigcrypt-v3/kem_seed" ‖ msk)[0..32]     → sk_enc_seed
  │         └─ A · s + e  (s, e derived from sk_enc_seed) → pk_enc = t_R
  │
  └─ SHA3-512("MLSigcrypt-v3/sig_seed" ‖ msk)[0..32]     → sig_seed
            └─ ML-DSA-87.KeyGen(sig_seed, A)              → (sk_sig, pk_sig = t_S)

key_id = SHA3-512("MLSigcrypt-v3/key_id" ‖ pk_enc ‖ pk_sig ‖ ρ_shared)[0..32]
```

The shared matrix `A` is generated once per identity and used for both the
encapsulation key and the signing key. This is the core optimisation introduced in
Level 2 and retained in Level 3.

Key sizes:

| Component          | Size      |
|--------------------|-----------|
| Public key         | 5600 bytes (32 key_id + 32 ρ_shared + 2944 pk_enc + 2592 pk_sig) |
| Secret key         | 13024 bytes (32 matrix_seed + 32 sk_enc_seed + 4896 sk_sig + 5600 pk embedded) |

---

## Signcrypt Algorithm (Level 3)

At a high level, signcrypt performs the following steps:

1. **Validate** both sender and recipient keys for internal consistency.
2. **Derive AAD digest**: `aad_digest = SHA3-512("MLSigcrypt-v3/aad\x03" ‖ aad)`.
3. **Derive signing randomness**: `ρ' = SHAKE256(k_seed ‖ rnd ‖ aad_digest ‖ key_id_S ‖ key_id_R)`, where `rnd` is 32 fresh bytes from the OS (hedged signing).
4. **Sample message key** `mkey` from the OS (32 bytes independent of `y`).
5. **Rejection-sampling loop**:
   - Sample mask `y` from `ρ'` and counter `κ`.
   - Compute `w = A · y`; decompose into high bits `w₁` and low bits `w₀`.
   - Compute the algebraic encapsulation: derive `r, e₁, e₂` from `SHAKE256(ENCAP_MASK_DOMAIN ‖ packed_y)`, then `u = Aᵀ · r + e₁`, `v = tᵣᵀ · r + e₂ + encode(mkey)`. Encode as `encap = u ‖ v`.
   - Encrypt the plaintext using `S_E = SHAKE256("MLSigcrypt-v3/enc\x03" ‖ mkey ‖ key_id_S ‖ key_id_R ‖ encap)`.
   - Compute challenge: `c̃ = SHAKE256(DOMAIN_CHAL ‖ w₁_packed ‖ encap ‖ aad_digest ‖ pk_sig_S ‖ pk_enc_R ‖ ct_len ‖ ct)`.
   - Compute response `z = y + c · s₁` and hint `h`. Reject if norm bounds are exceeded or hint weight exceeds `ω`.
6. **Write packet** in the layout above.
7. **Zeroize** all sensitive intermediates.

The encapsulation randomness `r, e₁, e₂` is derived from `y` but is computationally
independent of `y` from the adversary's perspective (under the assumption that
SHAKE-256 behaves as a random oracle). This decoupling was introduced specifically
to avoid the security issue present in an earlier version where `y` was used
directly as the encapsulation vector.

---

## Unsigncrypt Algorithm

1. **Parse and validate** packet header fields using constant-time comparisons.
2. **Verify signature challenge**: reconstruct `w' = A·z − c̃·t_S`, apply hints, repack `w₁'`, recompute challenge, compare in constant time. Reject if mismatch.
3. **Decapsulate**: recover `mkey` from `encap = u ‖ v` using `s_R`: compute `v − sᵣᵀ · u ≈ encode(mkey)`, threshold-decode to recover `mkey`.
4. **Decrypt**: reconstruct `S_E` from `mkey`, `key_id_S`, `key_id_R`, `encap`; XOR keystream with ciphertext.
5. **Zeroize** all sensitive intermediates on both success and failure paths.

Signature verification is always completed before decapsulation. This ordering
prevents unauthenticated decryption oracles.

---

## Performance

The following figures are from the `write_results` harness on a developer machine.
They should be treated as indicative rather than definitive; results vary with
hardware, OS scheduling, and the rejection-sampling loop's geometric distribution.

| Operation      | Approximate time | Notes |
|----------------|-----------------|-------|
| Key generation | < 1 ms           | Floor = 0 ns (no padding) |
| Signcrypt      | ~3–5 ms          | Floor = 7 ms (padded to floor) |
| Unsigncrypt    | ~1–2 ms          | Floor = 1.5 ms (padded to floor) |

The performance improvement over Level 1/2 comes from eliminating the separate
ML-KEM encapsulation pipeline. The single shared matrix `A` computed during key
generation is reused across the signing and encapsulation paths.

Timing floors are applied at the public API boundary to reduce observable variance.
They are not a formal constant-time guarantee — see [SECURITY.md](SECURITY.md).

---

## Repository Layout

```
src/
  lib.rs                     — public API and timing floors
  mlsigcrypt/
    mod.rs                   — module root, public entry points
    keys.rs                  — key types, derivation, encoding
    params.rs                — protocol constants, packet offsets
    signcrypt.rs             — signcrypt / unsigncrypt algorithms
    kat.rs                   — known-answer test vectors
    specs/
      algebraic.rs           — noisy algebraic encapsulation (u‖v)
      keccak.rs              — Keccak-f[1600], SHAKE-128/256 sponge
      sha512.rs              — SHA3-512 and SHA-512
      ml/
        mod.rs               — ML-DSA-87 public API
        params.rs            — ML-DSA-87 parameter constants
        field.rs             — Z_q arithmetic (Montgomery, Barrett)
        ntt.rs               — 256-point NTT
        poly.rs              — Polynomial type
        vec.rs               — PolyVec<M> generic vector
        matrix.rs            — K×L polynomial matrix
        sampling.rs          — ExpandA, ExpandS, ExpandMask, SampleInBall
        packing.rs           — bit-packing for pk, sk, sig
        keygen.rs            — ML-DSA.KeyGen (FIPS 204 Algorithm 1)
        sign.rs              — ML-DSA.Sign (FIPS 204 Algorithm 2)
        verify.rs            — ML-DSA.Verify (FIPS 204 Algorithm 3)
  constant_time.rs           — constant-time comparison helpers
  zeroize.rs                 — volatile-write zeroization
  os_random.rs               — OS entropy (no external crates)
  error.rs                   — opaque error types
benches/public_api.rs        — Criterion benchmarks
examples/
  public_api_demo.rs         — basic roundtrip demo
  write_results.rs           — allocation + timing spread report
fuzz/fuzz_targets/           — libFuzzer targets
```

---

## Verification Workflow

```bash
# Format, check, lint
cargo fmt --all -- --check
cargo check --locked --all-targets
cargo clippy --locked --all-targets -- -D clippy::correctness

# Tests (includes known-answer and integration tests)
cargo test --locked --all-targets

# Primitive vector gates
cargo test --locked nist --all-targets
cargo test --locked fips --all-targets

# Generate known-answer test vectors (prints hex intermediates)
cargo test kat::tests::generate_test_vectors -- --nocapture --ignored

# Allocation + timing spread report
cargo run --locked --example write_results

# Benchmarks
cargo bench --locked --bench public_api

# Fuzzing (requires nightly + cargo-fuzz)
cd fuzz && cargo +nightly fuzz run fuzz_mlsigcrypt_api -- -max_total_time=60
```

---

## Dependencies

**Runtime**: none. The `[dependencies]` table is empty. All cryptographic
primitives are implemented from scratch within the crate.

**Dev/test only**: `proptest`, `criterion`, `hex`.

---

## Minimum Rust Version

`rust-version = "1.92"` (required for `edition = "2024"` and const generics
features used in `PolyVec<M>`).

---

## License

Licensed under MIT OR Apache-2.0.