/// Z_q arithmetic for q = 8380417 = 2^23 − 2^13 + 1.
///
/// Coefficients are i32 (not i16 as in ML-KEM). The larger modulus requires
/// 64-bit intermediates for multiplication.
///
/// Montgomery domain: R = 2^32.
/// Barrett domain:    round(a / q) ≈ (a + 2^22) >> 23, exploiting q ≈ 2^23.
use crate::mlsigcrypt::specs::mldsa87::params::{GAMMA2, Q32, Q64};

// ── Montgomery constants ──────────────────────────────────────────────────────

/// q^{−1} mod 2^32.
/// Verification: q × QINV ≡ 1 (mod 2^32).
/// Must be verified against FIPS 204 KAT vectors.
pub(crate) const QINV: i32 = 58_728_449;

// ── Montgomery reduction ──────────────────────────────────────────────────────

/// Compute a × R^{−1} (mod q) for a 64-bit signed product.
///
/// Standard Montgomery trick for R = 2^32:
///   m = (a mod 2^32) × QINV mod 2^32   (lower 32 bits of a × QINV)
///   t = (a − m × q) / 2^32
/// Result t ∈ (−q, q).
///
/// Callers must ensure |a| < q × 2^32 to keep t in range.
#[inline(always)]
pub(crate) fn montgomery_reduce(a: i64) -> i32 {
    let m = (a as i32).wrapping_mul(QINV); // lower 32 bits of a × QINV
    ((a - m as i64 * Q64) >> 32) as i32
}

/// Multiply two i32 values and Montgomery-reduce.
/// Inputs must be in (−q, q); output is in (−q, q).
#[inline(always)]
pub(crate) fn fqmul(a: i32, b: i32) -> i32 {
    montgomery_reduce(a as i64 * b as i64)
}

// ── Reduction ─────────────────────────────────────────────────────────────────

/// Reduce a to canonical form in (−2^22, 2^22] by exploiting q ≈ 2^23.
///
/// Barrett approximation: round(a/q) ≈ (a + 2^22) >> 23.
/// Valid for |a| ≤ 2^31.
#[inline(always)]
pub(crate) fn reduce32(a: i32) -> i32 {
    let t = (a.wrapping_add(1 << 22)) >> 23;
    a.wrapping_sub(t.wrapping_mul(Q32))
}

/// Reduce a to [0, q). Adds q if negative.
#[inline(always)]
pub(crate) fn caddq(a: i32) -> i32 {
    let mask = a >> 31; // 0xFFFFFFFF if negative, 0 otherwise
    a.wrapping_add(mask & Q32)
}

// ── Power2Round ───────────────────────────────────────────────────────────────

/// Split r ∈ [0, q) into (r1, r0) where r = r1 × 2^d + r0, r0 ∈ (−2^{d−1}, 2^{d−1}].
///
/// Used to split t into (t1, t0) during key generation (FIPS 204 §3.1).
#[inline(always)]
pub(crate) fn power2round(r: i32) -> (i32, i32) {
    // FIPS / Dilithium reference form:
    //   r1 = floor((r + 2^{d-1} - 1) / 2^d)
    //   r0 = r - r1*2^d
    let d = crate::mlsigcrypt::specs::mldsa87::params::D;
    let r1 = (r + (1 << (d - 1)) - 1) >> d;
    let r0 = r - (r1 << d);
    (r1, r0)
}

// ── Decompose ─────────────────────────────────────────────────────────────────

/// Decompose r into (r1, r0) where r = r1 × α + r0, r0 ∈ (−α/2, α/2].
///
/// Special case: if r + r0 == q − 1, then r1 = 0, r0 = r0 − (q − 1).
/// (This handles the top of the range specially to keep r1 small.)
///
/// α = 2γ₂ = (q − 1) / 16. Used for HighBits and LowBits in sign/verify.
#[inline(always)]
pub(crate) fn decompose(r: i32) -> (i32, i32) {
    use crate::mlsigcrypt::specs::mldsa87::params::ALPHA;

    let mut r1 = (r + 127) >> 7;
    // Round r1 to nearest multiple of α/2^7; then keep in [0, 15].
    r1 = (r1 * 1025 + (1 << 21)) >> 22;
    r1 &= 15;
    let mut r0 = r - r1 * ALPHA;
    // Bring low bits into the centered representative interval.
    // Equivalent to: if r0 > (q-1)/2 then r0 -= q.
    r0 -= (((Q32 - 1) / 2 - r0) >> 31) & Q32;
    (r1, r0)
}

/// HighBits(r, α) = r1 from Decompose(r).
#[inline(always)]
pub(crate) fn high_bits(r: i32) -> i32 {
    decompose(r).0
}

/// LowBits(r, α) = r0 from Decompose(r).
#[inline(always)]
pub(crate) fn low_bits(r: i32) -> i32 {
    decompose(r).1
}

// ── Hint arithmetic ───────────────────────────────────────────────────────────

/// MakeHint(a0, a1): returns 1 if `a0` overflows the low-bit window.
///
/// Follows the Dilithium/ML-DSA reference rule:
/// - set hint if `a0 > GAMMA2` or `a0 < -GAMMA2`
/// - boundary case: set hint when `a0 == -GAMMA2` and `a1 != 0`
///
/// Here, `a0` is the adjusted low part and `a1` is the corresponding high part.
#[inline(always)]
pub(crate) fn make_hint(a0: i32, a1: i32) -> i32 {
    ((a0 > GAMMA2) || (a0 < -GAMMA2) || (a0 == -GAMMA2 && a1 != 0)) as i32
}

/// UseHint(h, r): corrects the high bits of r using hint h.
///
/// If h == 0: return HighBits(r) unchanged.
/// If h == 1: return a corrected r1 such that the hint is satisfied.
#[inline(always)]
pub(crate) fn use_hint(h: i32, r: i32) -> i32 {
    let (r1, r0) = decompose(r);
    if h == 0 {
        return r1;
    }
    // Hint is set: adjust r1 by ±1 depending on sign of r0.
    if r0 > 0 { (r1 + 1) & 15 } else { (r1 - 1) & 15 }
    // The &15 ensures r1 stays in [0, 15] (wraps at the boundaries).
    // For the special case where r1 == 0 and r0 < 0: (0-1)&15 = 15.
    // But in that case r ≈ q-1 and Decompose would have set r1=0 via the
    // special-case correction; UseHint must match Decompose's convention.
    // KAT verification required.
}

// ── Infinity-norm check ───────────────────────────────────────────────────────

/// True if |a| < bound (strictly). Used in sign rejection tests.
#[inline(always)]
pub(crate) fn chknorm(a: i32, bound: i32) -> bool {
    // Center a in (-q/2, q/2].
    let a_centered = if a > Q32 / 2 { a - Q32 } else { a };
    let a_pos = if a_centered < 0 {
        -a_centered
    } else {
        a_centered
    };
    a_pos < bound
}

#[cfg(test)]
mod tests {
    use super::{decompose, power2round};
    use crate::mlsigcrypt::specs::mldsa87::params::{D, GAMMA2, Q32};

    #[test]
    fn power2round_boundary_at_half_interval() {
        // FIPS/Dilithium boundary: 2^(d-1) maps to r0 = +2^(d-1), not -2^(d-1).
        let x = 1 << (D - 1);
        let (r1, r0) = power2round(x);
        assert_eq!(r1, 0);
        assert_eq!(r0, x as i32);
    }

    #[test]
    fn decompose_top_range_is_centered() {
        // Top representative window must be centered as negatives.
        let x = Q32 - (GAMMA2 - 1);
        let (r1, r0) = decompose(x);
        assert_eq!(r1, 0);
        assert_eq!(r0, -(GAMMA2 - 1));
    }
}
