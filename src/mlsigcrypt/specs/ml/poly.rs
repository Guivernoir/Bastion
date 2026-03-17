/// Polynomial in Z_q[X]/(X^256+1) with i32 coefficients, q = 8380417.
///
/// No Copy/Clone. Sensitive polynomials (s1, s2, t0, y, z) must be explicitly
/// zeroized via `zeroize_poly` before drop. Public polynomials (A rows, t1)
/// carry no zeroize obligation.
///
/// Key invariants:
///   Standard domain: coefficients ∈ [0, q) or (−q, q) depending on operation.
///   NTT domain:      coefficients may be in (−7q, 7q) until `reduce()` is called.
///   After `caddq`:   coefficients ∈ [0, q).
use core::ptr;
use core::sync::atomic::{Ordering, compiler_fence};

use crate::mlsigcrypt::specs::ml::field::{
    chknorm, high_bits, low_bits, make_hint, power2round, use_hint,
};
use crate::mlsigcrypt::specs::ml::ntt::{
    inv_ntt, ntt, poly_caddq, poly_pointwise_acc, poly_pointwise_montgomery, poly_reduce,
};
use crate::mlsigcrypt::specs::ml::params::{D, N, Q32};

// ── Type ──────────────────────────────────────────────────────────────────────

pub(crate) struct Poly {
    pub(crate) coeffs: [i32; N],
}

impl Poly {
    #[inline]
    pub(crate) const fn zero() -> Self {
        Self { coeffs: [0i32; N] }
    }

    // ── Reduction ─────────────────────────────────────────────────────────────

    /// Reduce all coefficients to (−2^22, 2^22].
    #[inline]
    pub(crate) fn reduce(&mut self) {
        poly_reduce(&mut self.coeffs);
    }

    /// Shift all coefficients to [0, q).
    #[inline]
    pub(crate) fn caddq(&mut self) {
        poly_caddq(&mut self.coeffs);
    }

    // ── Arithmetic ────────────────────────────────────────────────────────────

    #[inline]
    pub(crate) fn add_assign(&mut self, other: &Poly) {
        for i in 0..N {
            self.coeffs[i] = self.coeffs[i].wrapping_add(other.coeffs[i]);
        }
    }

    #[inline]
    pub(crate) fn sub_assign(&mut self, other: &Poly) {
        for i in 0..N {
            self.coeffs[i] = self.coeffs[i].wrapping_sub(other.coeffs[i]);
        }
    }

    /// Negate all coefficients: out = −self mod q.
    #[inline]
    pub(crate) fn neg_assign(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = Q32.wrapping_sub(*c);
        }
    }

    // ── NTT ───────────────────────────────────────────────────────────────────

    #[inline]
    pub(crate) fn ntt(&mut self) {
        ntt(&mut self.coeffs);
    }

    #[inline]
    pub(crate) fn inv_ntt(&mut self) {
        inv_ntt(&mut self.coeffs);
    }

    /// Pointwise Montgomery multiply: self[i] = a[i] × b[i] / R mod q.
    #[inline]
    pub(crate) fn pointwise_montgomery(&mut self, a: &Poly, b: &Poly) {
        poly_pointwise_montgomery(&a.coeffs, &b.coeffs, &mut self.coeffs);
    }

    /// Accumulate pointwise product: self[i] += a[i] × b[i] / R.
    #[inline]
    pub(crate) fn pointwise_acc(&mut self, a: &Poly, b: &Poly) {
        poly_pointwise_acc(&a.coeffs, &b.coeffs, &mut self.coeffs);
    }

    // ── Shift for t = t1 × 2^d + t0 ─────────────────────────────────────────

    /// Multiply all coefficients by 2^d in place (for t1 → t reconstruction in Verify).
    #[inline]
    pub(crate) fn shiftl(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c <<= D;
        }
    }

    // ── Power2Round ───────────────────────────────────────────────────────────

    /// Split self into (t1, t0) via Power2Round(coeff, d).
    /// Returns them as separate polynomials. Self must be in [0, q).
    pub(crate) fn power2round_split(&self, t1: &mut Poly, t0: &mut Poly) {
        for i in 0..N {
            let (r1, r0) = power2round(self.coeffs[i]);
            t1.coeffs[i] = r1;
            t0.coeffs[i] = r0;
        }
    }

    // ── Decompose / HighBits / LowBits ────────────────────────────────────────

    /// Compute HighBits of all coefficients into `self`.
    pub(crate) fn highbits_into(&self, out: &mut Poly) {
        for i in 0..N {
            out.coeffs[i] = high_bits(self.coeffs[i]);
        }
    }

    /// Compute LowBits of all coefficients into `self`.
    pub(crate) fn lowbits_into(&self, out: &mut Poly) {
        for i in 0..N {
            out.coeffs[i] = low_bits(self.coeffs[i]);
        }
    }

    // ── Hint operations ───────────────────────────────────────────────────────

    /// Compute MakeHint(z, r) coefficient-wise. Returns total weight (# of 1s).
    pub(crate) fn make_hint_into(z: &Poly, r: &Poly, h: &mut Poly) -> usize {
        let mut count = 0usize;
        for i in 0..N {
            h.coeffs[i] = make_hint(z.coeffs[i], r.coeffs[i]);
            count += h.coeffs[i] as usize;
        }
        count
    }

    /// Apply UseHint: self = UseHint(h, w) coefficient-wise.
    pub(crate) fn use_hint_into(h: &Poly, w: &Poly, out: &mut Poly) {
        for i in 0..N {
            out.coeffs[i] = use_hint(h.coeffs[i], w.coeffs[i]);
        }
    }

    // ── Norm check ────────────────────────────────────────────────────────────

    /// True if ALL coefficients satisfy |c| < bound.
    pub(crate) fn check_norm_lt(&self, bound: i32) -> bool {
        for &c in self.coeffs.iter() {
            if !chknorm(c, bound) {
                return false;
            }
        }
        true
    }

    /// Infinity norm: max |coeff| after centering mod q.
    pub(crate) fn infinity_norm(&self) -> i32 {
        let mut max = 0i32;
        for &c in self.coeffs.iter() {
            let centered = if c > Q32 / 2 { c - Q32 } else { c };
            let abs = if centered < 0 { -centered } else { centered };
            if abs > max {
                max = abs;
            }
        }
        max
    }

    // ── Message encoding ──────────────────────────────────────────────────────

    // Encode a 32-byte random mask as a polynomial for SampleInBall.
    // (Not the same as message encoding — used internally by sampling.)
    // Returns the polynomial with exactly TAU ±1 entries.
    // This is implemented in sampling.rs; declared here for coherence.
}

// ── Zeroization ───────────────────────────────────────────────────────────────

/// Volatile-write zeroize an ML-DSA polynomial. Call on any Poly holding secret data.
#[inline(never)]
pub(crate) fn zeroize_poly(p: &mut Poly) {
    for c in p.coeffs.iter_mut() {
        // SAFETY: c is a valid aligned i32 reference.
        unsafe { ptr::write_volatile(c, 0i32) };
    }
    compiler_fence(Ordering::SeqCst);
}
