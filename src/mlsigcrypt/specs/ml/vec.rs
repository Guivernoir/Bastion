/// Generic polynomial vector PolyVec<M> and derived operations.
///
/// ML-DSA-87 uses two distinct vector lengths:
///   L = 7: s1, y, z, and columns of A
///   K = 8: s2, t0, t1, w, rows of A
///
/// `PolyVec<M>` is generic over M via const generics, avoiding code duplication.
/// All const-sized arrays are initialized via `core::mem::zeroed()` — safe for i32.
///
/// Sensitive vectors (s1, s2, t0, y, z) must be zeroized before drop.
use crate::mlsigcrypt::specs::ml::params::K;
use crate::mlsigcrypt::specs::ml::poly::{Poly, zeroize_poly};

// ── Type ──────────────────────────────────────────────────────────────────────

pub(crate) struct PolyVec<const M: usize> {
    pub(crate) polys: [Poly; M],
}

impl<const M: usize> PolyVec<M> {
    #[inline]
    pub(crate) fn zero() -> Self {
        // SAFETY: [i32; N] is valid when all bytes are zero. Poly is repr(Rust) of [i32; 256].
        unsafe { core::mem::zeroed() }
    }

    // ── Reduction ─────────────────────────────────────────────────────────────

    pub(crate) fn reduce(&mut self) {
        for p in self.polys.iter_mut() {
            p.reduce();
        }
    }

    pub(crate) fn caddq(&mut self) {
        for p in self.polys.iter_mut() {
            p.caddq();
        }
    }

    // ── NTT ───────────────────────────────────────────────────────────────────

    pub(crate) fn ntt(&mut self) {
        for p in self.polys.iter_mut() {
            p.ntt();
        }
    }

    pub(crate) fn inv_ntt(&mut self) {
        for p in self.polys.iter_mut() {
            p.inv_ntt();
        }
    }

    // ── Arithmetic ────────────────────────────────────────────────────────────

    pub(crate) fn add_assign(&mut self, other: &PolyVec<M>) {
        for i in 0..M {
            self.polys[i].add_assign(&other.polys[i]);
        }
    }

    pub(crate) fn sub_assign(&mut self, other: &PolyVec<M>) {
        for i in 0..M {
            self.polys[i].sub_assign(&other.polys[i]);
        }
    }

    pub(crate) fn neg_assign(&mut self) {
        for p in self.polys.iter_mut() {
            p.neg_assign();
        }
    }

    // ── Shift ─────────────────────────────────────────────────────────────────

    pub(crate) fn shiftl(&mut self) {
        for p in self.polys.iter_mut() {
            p.shiftl();
        }
    }

    // ── Norm check ────────────────────────────────────────────────────────────

    /// True if every coefficient in every polynomial satisfies |c| < bound.
    pub(crate) fn check_norm_lt(&self, bound: i32) -> bool {
        for p in self.polys.iter() {
            if !p.check_norm_lt(bound) {
                return false;
            }
        }
        true
    }
}

// ── K-vector-specific operations ─────────────────────────────────────────────

impl PolyVec<K> {
    /// Compute w1 = HighBits(w, α) coefficient-wise.
    pub(crate) fn highbits_into(&self, out: &mut PolyVec<K>) {
        for i in 0..K {
            self.polys[i].highbits_into(&mut out.polys[i]);
        }
    }

    /// Compute w0 = LowBits(w, α) coefficient-wise.
    pub(crate) fn lowbits_into(&self, out: &mut PolyVec<K>) {
        for i in 0..K {
            self.polys[i].lowbits_into(&mut out.polys[i]);
        }
    }

    /// Compute MakeHint(z, r) coefficient-wise; return total hint weight.
    pub(crate) fn make_hint_into(z: &PolyVec<K>, r: &PolyVec<K>, h: &mut PolyVec<K>) -> usize {
        let mut total = 0usize;
        for i in 0..K {
            total += Poly::make_hint_into(&z.polys[i], &r.polys[i], &mut h.polys[i]);
        }
        total
    }

    /// Apply UseHint: out[i] = UseHint(h[i], w[i]).
    pub(crate) fn use_hint_into(h: &PolyVec<K>, w: &PolyVec<K>, out: &mut PolyVec<K>) {
        for i in 0..K {
            Poly::use_hint_into(&h.polys[i], &w.polys[i], &mut out.polys[i]);
        }
    }
}

// ── Zeroization ──────────────────────────────────────────────────────────────

pub(crate) fn zeroize_polyvec<const M: usize>(v: &mut PolyVec<M>) {
    for p in v.polys.iter_mut() {
        zeroize_poly(p);
    }
}
