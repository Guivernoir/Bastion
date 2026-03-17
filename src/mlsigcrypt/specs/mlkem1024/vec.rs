use crate::mlsigcrypt::specs::mlkem1024::ntt::poly_basemul;
/// PolyVec: a K-dimensional vector of polynomials over Z_q[X]/(X^256+1).
///
/// Core operations: NTT, inner product (dot), 12-bit encode/decode.
///
/// No Copy/Clone — vectors holding secret key material (s, e, r) must be
/// explicitly managed. Use `zeroize_polyvec()` before drop on sensitive instances.
use crate::mlsigcrypt::specs::mlkem1024::params::{
    DU, K, N, POLY_BYTES, POLYVEC_BYTES, POLYVEC_COMPRESSED_U,
};
use crate::mlsigcrypt::specs::mlkem1024::poly::{Poly, poly_decode12, poly_encode12, zeroize_poly};

// ── Type ──────────────────────────────────────────────────────────────────────

/// A K-vector of polynomials. Stack size: 4 × 512 B = 2048 B.
pub(crate) struct PolyVec {
    pub(crate) polys: [Poly; K],
}

impl PolyVec {
    /// Zero vector.
    #[inline]
    pub(crate) fn zero() -> Self {
        // Cannot use array::from_fn in no_std easily; construct manually.
        Self {
            polys: [Poly::zero(), Poly::zero(), Poly::zero(), Poly::zero()],
        }
    }

    // ── Reduction ─────────────────────────────────────────────────────────────

    /// Barrett-reduce all polynomial coefficients.
    #[inline]
    pub(crate) fn reduce(&mut self) {
        for p in self.polys.iter_mut() {
            p.reduce();
        }
    }

    // ── NTT ───────────────────────────────────────────────────────────────────

    /// Apply forward NTT to each polynomial.
    #[inline]
    pub(crate) fn ntt(&mut self) {
        for p in self.polys.iter_mut() {
            p.ntt();
        }
    }

    /// Apply inverse NTT to each polynomial.
    #[inline]
    pub(crate) fn inv_ntt(&mut self) {
        for p in self.polys.iter_mut() {
            p.inv_ntt();
        }
    }

    // ── Arithmetic ────────────────────────────────────────────────────────────

    /// Component-wise addition.
    #[inline]
    pub(crate) fn add_assign(&mut self, other: &PolyVec) {
        for i in 0..K {
            self.polys[i].add_assign(&other.polys[i]);
        }
    }

    /// Component-wise addition with reduction.
    #[inline]
    pub(crate) fn add_reduce(&mut self, other: &PolyVec) {
        for i in 0..K {
            self.polys[i].add_reduce(&other.polys[i]);
        }
    }

    // ── Inner product ─────────────────────────────────────────────────────────

    /// NTT-domain inner product: out = Σ self[i] * b[i] (pointwise).
    ///
    /// Accumulates into `out` via basemul; `out` must be zeroed before the call
    /// or the caller accepts that existing contents are added to.
    /// After K accumulations coefficients are in (-K*q, K*q); Barrett-reduce before use.
    pub(crate) fn dot_ntt(&self, b: &PolyVec, out: &mut Poly) {
        // Accumulate K basemul products into out.
        for i in 0..K {
            let mut tmp = Poly::zero();
            poly_basemul(&self.polys[i].coeffs, &b.polys[i].coeffs, &mut tmp.coeffs);
            out.add_assign(&tmp);
            zeroize_poly(&mut tmp);
        }
        out.reduce();
    }

    // ── Serialisation ─────────────────────────────────────────────────────────

    /// Encode all K polynomials as 12 bits/coefficient into `out` (POLYVEC_BYTES = 1536 bytes).
    /// All coefficients reduced to [0, q) before encoding.
    pub(crate) fn encode12(&self, out: &mut [u8; POLYVEC_BYTES]) {
        for i in 0..K {
            let chunk: &mut [u8; POLY_BYTES] =
                // SAFETY: out is exactly K*POLY_BYTES; each slice is non-overlapping POLY_BYTES.
                unsafe {
                    &mut *(out.as_mut_ptr().add(i * POLY_BYTES) as *mut [u8; POLY_BYTES])
                };
            poly_encode12(&self.polys[i], chunk);
        }
    }

    /// Decode K polynomials from 12-bit packed bytes (POLYVEC_BYTES = 1536 bytes).
    pub(crate) fn decode12(&mut self, bytes: &[u8; POLYVEC_BYTES]) {
        for i in 0..K {
            let chunk: &[u8; POLY_BYTES] =
                // SAFETY: bytes is exactly K*POLY_BYTES; offset arithmetic is in bounds.
                unsafe {
                    &*(bytes.as_ptr().add(i * POLY_BYTES) as *const [u8; POLY_BYTES])
                };
            poly_decode12(chunk, &mut self.polys[i]);
        }
    }

    // ── Compression ───────────────────────────────────────────────────────────

    /// Compress-and-encode u component: K polys × DU bits/coeff → 1408 bytes.
    pub(crate) fn compress_du(&self, out: &mut [u8; POLYVEC_COMPRESSED_U]) {
        let bytes_per = N * DU / 8; // 352
        for i in 0..K {
            self.polys[i].compress_du(&mut out[i * bytes_per..(i + 1) * bytes_per]);
        }
    }

    /// Decode-and-decompress u component: 1408 bytes → K polys.
    pub(crate) fn decompress_du(&mut self, bytes: &[u8; POLYVEC_COMPRESSED_U]) {
        let bytes_per = N * DU / 8;
        for i in 0..K {
            self.polys[i].decompress_du(&bytes[i * bytes_per..(i + 1) * bytes_per]);
        }
    }
}

// ── Zeroization ──────────────────────────────────────────────────────────────

/// Zeroize all polynomials in a PolyVec. Call before dropping secret vectors.
#[inline]
pub(crate) fn zeroize_polyvec(v: &mut PolyVec) {
    for p in v.polys.iter_mut() {
        zeroize_poly(p);
    }
}
