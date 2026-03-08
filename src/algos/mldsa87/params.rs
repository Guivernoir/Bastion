/// ML-DSA-87 parameters — FIPS 204, Table 1.
///
/// Every numeric constant lives here. ML-DSA-87 targets NIST security level 5.
///
/// Key differences from ML-KEM that downstream modules must respect:
///   • q = 8380417 (23-bit prime), not 3329.
///   • Coefficients are i32, not i16.
///   • NTT is a full 256-point transform (no basemul pairing).
///   • Signing uses a rejection loop — timing is NOT constant w.r.t. iterations.
///   • Verification IS constant-time w.r.t. the signature check.

// ── Module dimensions ─────────────────────────────────────────────────────────

/// Rows of the public matrix A (also length of s2, t0, t1 vectors).
pub(crate) const K: usize = 8;

/// Columns of A (also length of s1, y, z vectors).
pub(crate) const L: usize = 7;

/// Polynomial degree.
pub(crate) const N: usize = 256;

// ── Modulus ───────────────────────────────────────────────────────────────────

/// Prime modulus q = 2^23 − 2^13 + 1.
/// This special form enables efficient reduction: 2^23 ≡ 2^13 − 1 (mod q).
pub(crate) const Q: u32 = 8_380_417;
pub(crate) const Q32: i32 = 8_380_417;
pub(crate) const Q64: i64 = 8_380_417;

// ── Signing parameters ────────────────────────────────────────────────────────

/// Number of ±1 entries in the challenge polynomial c ← SampleInBall(ρ, τ).
pub(crate) const TAU: usize = 60;

/// Security parameter (bits). The commitment hash c̃ has 2λ = 512 bits = 64 bytes.
pub(crate) const LAMBDA: usize = 256;

/// Commitment hash byte length = 2λ / 8.
pub(crate) const LAMBDA2_BYTES: usize = LAMBDA / 4; // 64

/// Infinity-norm bound on y coefficients: γ₁ = 2^19.
pub(crate) const GAMMA1: i32 = 1 << 19; // 524288

/// Half the rounding modulus: γ₂ = (q − 1)/32 = 261888.
pub(crate) const GAMMA2: i32 = (Q32 - 1) / 32; // 261888

/// Secret polynomial coefficient range: η = 2.
pub(crate) const ETA: i32 = 2;

/// Rejection threshold: β = τ × η = 120.
pub(crate) const BETA: i32 = TAU as i32 * ETA; // 120

/// Maximum number of 1-bits across all k hint polynomials: ω = 75.
pub(crate) const OMEGA: usize = 75;

/// Dropped bits from t in the public key: d = 13.
pub(crate) const D: u32 = 13;

// ── Derived rounding constants ────────────────────────────────────────────────

/// Full rounding modulus: α = 2γ₂ = (q − 1) / 16.
pub(crate) const ALPHA: i32 = 2 * GAMMA2; // 523776

// ── Coefficient encoding bit-widths ───────────────────────────────────────────

/// Bits per coefficient for t1 (high bits of t = Power2Round(t, d)).
/// t1 ∈ [0, 2^{23-13}) = [0, 1024) → 10 bits.
pub(crate) const T1_BITS: usize = 10;

/// Bits per coefficient for t0 (low bits of t): d = 13 bits (range -(2^12), 2^12]).
pub(crate) const T0_BITS: usize = D as usize; // 13

/// Bits per coefficient for s1, s2 ∈ {-η, …, η}: ceil(log2(2η+1)) → 3 bits for η=2.
pub(crate) const ETA_BITS: usize = 3;

/// Bits per coefficient for z ∈ (-γ₁, γ₁): ceil(log2(2*γ₁)) = 20 bits.
pub(crate) const Z_BITS: usize = 20;

/// Bits per coefficient for w1 = HighBits(w, α). For γ₂=(q-1)/32: w1 ∈ [0, 15] → 4 bits.
pub(crate) const W1_BITS: usize = 4;

// ── Serialised byte sizes ─────────────────────────────────────────────────────

/// Bytes for one 12-bit-per-coefficient polynomial (key material baseline).
pub(crate) const POLY_BYTES: usize = N * 12 / 8; // 384 (unused directly; T1/T0 differ)

/// Bytes for one t1-encoded polynomial (10 bits/coeff).
pub(crate) const POLYT1_BYTES: usize = N * T1_BITS / 8; // 320

/// Bytes for one t0-encoded polynomial (13 bits/coeff).
pub(crate) const POLYT0_BYTES: usize = N * T0_BITS / 8; // 416

/// Bytes for one s1 or s2 polynomial (3 bits/coeff for η=2).
pub(crate) const POLYETA_BYTES: usize = N * ETA_BITS / 8; // 96

/// Bytes for one z polynomial (20 bits/coeff for γ₁=2^19).
pub(crate) const POLYZ_BYTES: usize = N * Z_BITS / 8; // 640

/// Bytes for one w1 polynomial (4 bits/coeff).
pub(crate) const POLYW1_BYTES: usize = N * W1_BITS / 8; // 128

// ── Key and signature sizes ───────────────────────────────────────────────────

/// Public key: ρ (32 B) + t1 (k × POLYT1_BYTES).
pub(crate) const PK_BYTES: usize = 32 + K * POLYT1_BYTES;
// = 32 + 8 × 320 = 2592 ✓

/// Secret key: ρ (32) + K (32) + tr (64) + s1 (l×POLYETA) + s2 (k×POLYETA) + t0 (k×POLYT0).
pub(crate) const SK_BYTES: usize =
    32 + 32 + 64 + L * POLYETA_BYTES + K * POLYETA_BYTES + K * POLYT0_BYTES;
// = 128 + 7×96 + 8×96 + 8×416 = 128 + 672 + 768 + 3328 = 4896 ✓

/// Signature: c̃ (LAMBDA2_BYTES) + z (l×POLYZ) + packed hints (ω + k).
pub(crate) const SIG_BYTES: usize = LAMBDA2_BYTES + L * POLYZ_BYTES + OMEGA + K;
// = 64 + 7×640 + 75 + 8 = 64 + 4480 + 83 = 4627 ✓

// ── Byte offsets within the public key ───────────────────────────────────────

pub(crate) const PK_RHO_OFF: usize = 0;
pub(crate) const PK_T1_OFF: usize = 32;

// ── Byte offsets within the secret key ───────────────────────────────────────

pub(crate) const SK_RHO_OFF: usize = 0;
pub(crate) const SK_K_OFF: usize = 32;
pub(crate) const SK_TR_OFF: usize = 64;
pub(crate) const SK_S1_OFF: usize = 128;
pub(crate) const SK_S2_OFF: usize = SK_S1_OFF + L * POLYETA_BYTES; // 128 + 672 = 800
pub(crate) const SK_T0_OFF: usize = SK_S2_OFF + K * POLYETA_BYTES; // 800 + 768 = 1568

// ── Byte offsets within the signature ────────────────────────────────────────

pub(crate) const SIG_CTILDE_OFF: usize = 0;
pub(crate) const SIG_Z_OFF: usize = LAMBDA2_BYTES;
pub(crate) const SIG_H_OFF: usize = SIG_Z_OFF + L * POLYZ_BYTES; // 64 + 4480 = 4544

// ── Compile-time sanity checks ────────────────────────────────────────────────

const _: () = {
    assert!(PK_BYTES == 2592, "ML-DSA-87 public key must be 2592 bytes");
    assert!(SK_BYTES == 4896, "ML-DSA-87 secret key must be 4896 bytes");
    assert!(SIG_BYTES == 4627, "ML-DSA-87 signature must be 4627 bytes");
    assert!(
        SK_T0_OFF + K * POLYT0_BYTES == SK_BYTES,
        "SK layout mismatch"
    );
};
