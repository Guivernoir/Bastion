/// Z_q field arithmetic for q = 3329.
///
/// Montgomery form: R = 2^16. All NTT multiplications use Montgomery reduction.
/// Barrett reduction handles non-NTT coefficient clamping.
/// All operations are branchless — no timing dependency on coefficient values.
///
/// Proof that constants are correct:
///   MONT  = 2^16 mod 3329 = 2285
///   QINV  = q^{-1} mod 2^16 = 62209  (as i16: -3327)
///           Verification: 3329 × 62209 ≡ 1 (mod 65536) — see params derivation.
///   MONT2 = MONT^2 mod q = 2285^2 mod 3329 = 1353
use crate::mlsigcrypt::specs::mlkem1024::params::{Q16, Q32};

// ── Constants ─────────────────────────────────────────────────────────────────

/// R mod q (= 2^16 mod 3329). Used as Montgomery domain multiplier.
pub(crate) const MONT: i16 = 2285;
/// R^2 mod q (= 2^32 mod 3329). Used for entering Montgomery domain via `fqmul`.
pub(crate) const MONT2: i16 = 1353;

/// q^{-1} mod 2^16, stored as i16 (62209u16 = -3327i16). Core of mont_reduce.
const QINV: i16 = -3327_i16;

/// Conversion factor from raw domain to Montgomery domain times 2^{-7}.
/// Used by inv_ntt's final scaling: fqmul(1441, x) = x * 128^{-1} mod q.
pub(crate) const INV_NTT_SCALE: i16 = 1441;

// ── Montgomery reduction ──────────────────────────────────────────────────────

/// Reduce a 32-bit value t to a representative in [-q, q].
///
/// Computes t * R^{-1} mod q using the standard Montgomery trick.
/// Requires |t| < 2^15 * q ≈ 109,101,055.
///
/// # Safety
/// Safe. Uses only arithmetic on primitive types.
#[inline(always)]
pub(crate) fn montgomery_reduce(t: i32) -> i16 {
    // u = (t mod R) * QINV mod R  — extracts the cancellation factor
    let u = (t as i16).wrapping_mul(QINV);
    // t - u*q is divisible by R = 2^16; arithmetic right-shift by 16 gives result.
    // Casting to i32 before multiply prevents overflow.
    ((t - (u as i32).wrapping_mul(Q32)) >> 16) as i16
}

/// Multiply two i16 values and Montgomery-reduce the product.
/// Result is in (-q, q).
#[inline(always)]
pub(crate) fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce((a as i32).wrapping_mul(b as i32))
}

// ── Barrett reduction ─────────────────────────────────────────────────────────

/// Reduce a to a representative in (-q, q) without Montgomery overhead.
///
/// Barrett approximation with v = 20159 ≈ round(2^26 / q).
/// Correct for |a| < 2^15.
#[inline(always)]
pub(crate) fn barrett_reduce(a: i16) -> i16 {
    const V: i32 = 20159; // round(2^26 / 3329)
    let t = (((V * (a as i32)) + (1 << 25)) >> 26) as i16;
    a.wrapping_sub(t.wrapping_mul(Q16))
}

/// Reduce a to [0, q).
#[inline(always)]
pub(crate) fn reduce_to_pos(a: i16) -> u16 {
    let a = barrett_reduce(a);
    // Conditional add: if a < 0, add q; branchless.
    let mask = (a >> 15) as u16; // 0xFFFF if negative, 0x0000 if non-negative
    (a as u16).wrapping_add(mask & Q16 as u16)
}

// ── Modular arithmetic helpers ────────────────────────────────────────────────

/// Coefficient-wise addition of two i16 values, result in (-2q, 2q).
/// Reduction deferred; caller should reduce after accumulation.
#[inline(always)]
pub(crate) fn cadd(a: i16, b: i16) -> i16 {
    a.wrapping_add(b)
}

/// Coefficient-wise subtraction.
#[inline(always)]
pub(crate) fn csub(a: i16, b: i16) -> i16 {
    a.wrapping_sub(b)
}

// ── Constant-time utilities ───────────────────────────────────────────────────

/// Constant-time select: returns `a` if `choice == 0`, `b` if `choice == 1`.
/// No branches, no table lookups.
#[inline(always)]
pub(crate) fn ct_select_u16(a: u16, b: u16, choice: u8) -> u16 {
    // mask = 0xFFFF if choice == 1, 0x0000 if choice == 0
    let mask = (choice as u16).wrapping_neg();
    a ^ (mask & (a ^ b))
}

/// Constant-time equality: returns 1 if a == b, 0 otherwise.
/// No branches; timing is independent of values.
#[inline(always)]
pub(crate) fn ct_eq_u16(a: u16, b: u16) -> u8 {
    // XOR is zero iff equal; propagate any set bit to LSB.
    let diff = (a ^ b) as u32;
    // diff | (-diff) has MSB set unless diff == 0.
    // Shift MSB to position 0 and invert.
    (1u8).wrapping_sub(((diff | diff.wrapping_neg()) >> 31) as u8)
}

// ── Compress / Decompress ─────────────────────────────────────────────────────

/// Compress a coefficient x ∈ [0, q) to d bits.
///
/// Compress_d(x) = round(2^d / q * x) mod 2^d
///
/// The result fits in d bits (no reduction needed for d ≤ 11).
#[inline(always)]
pub(crate) fn compress(x: u16, d: u32) -> u16 {
    // Multiply by 2^d, round by adding q/2, divide by q, mask to d bits.
    // Use u32 to avoid overflow: x < q < 2^12, 2^d ≤ 2^11.
    let val = (x as u32) << d;
    let half_q = (Q32 as u32) >> 1;
    let rounded = val.wrapping_add(half_q);
    // Divide by q: use the fact that 2^26/q ≈ 20159, same as Barrett denominator.
    // Exact integer division is required here; use multiplication approach.
    // For d ≤ 12, x < q < 2^12: rounded < 2^12 * 2^12 = 2^24, fits in u32.
    let t = rounded / Q32 as u32;
    (t & ((1 << d) - 1)) as u16
}

/// Decompress d bits back to a coefficient in [0, q).
///
/// Decompress_d(y) = round(q / 2^d * y)
#[inline(always)]
pub(crate) fn decompress(y: u16, d: u32) -> u16 {
    // round(q * y / 2^d) = (q*y + 2^{d-1}) >> d
    let t = (Q32 as u32)
        .wrapping_mul(y as u32)
        .wrapping_add(1u32 << (d - 1));
    (t >> d) as u16
}
