use crate::mlsigcrypt::specs::mlkem1024::ntt::poly_basemul;
/// PolyMatrix: a K×K matrix of polynomials in NTT domain.
///
/// Used to hold the public matrix A (or Aᵀ) generated from ρ via SHAKE-128.
/// A is not secret — no zeroization required.
///
/// Indexing: `rows[i].polys[j]` = A[i][j].
///
/// Stack cost: K × PolyVec = 4 × 2048 B = 8 KB.
use crate::mlsigcrypt::specs::mlkem1024::params::K;
use crate::mlsigcrypt::specs::mlkem1024::poly::{Poly, zeroize_poly};
use crate::mlsigcrypt::specs::mlkem1024::vec::PolyVec;

// ── Type ──────────────────────────────────────────────────────────────────────

/// K×K matrix of polynomials (NTT domain).
pub(crate) struct PolyMatrix {
    pub(crate) rows: [PolyVec; K],
}

impl PolyMatrix {
    /// Zero matrix.
    #[inline]
    pub(crate) fn zero() -> Self {
        Self {
            rows: [
                PolyVec::zero(),
                PolyVec::zero(),
                PolyVec::zero(),
                PolyVec::zero(),
            ],
        }
    }

    // ── Matrix-vector products ────────────────────────────────────────────────

    /// Compute out = A · s where all inputs are in NTT domain.
    ///
    /// out[i] = Σ_j A[i][j] * s[j]     (NTT-domain inner products)
    ///
    /// Result is in NTT domain with coefficients Barrett-reduced.
    /// `out` must be zeroed before calling.
    pub(crate) fn matvec_ntt(&self, s: &PolyVec, out: &mut PolyVec) {
        for i in 0..K {
            self.rows[i].dot_ntt(s, &mut out.polys[i]);
        }
    }

    /// Compute out = Aᵀ · r where all inputs are in NTT domain.
    ///
    /// out[j] = Σ_i A[i][j] * r[i]     (column-wise dot products)
    ///
    /// Aᵀ is never materialised; we iterate over columns by indexing rows.
    /// `out` must be zeroed before calling.
    pub(crate) fn matvec_transpose_ntt(&self, r: &PolyVec, out: &mut PolyVec) {
        for j in 0..K {
            // out[j] = Σ_i A[i][j] * r[i]
            let p = &mut out.polys[j];
            p.coeffs.fill(0);
            for i in 0..K {
                let mut tmp = Poly::zero();
                poly_basemul(
                    &self.rows[i].polys[j].coeffs,
                    &r.polys[i].coeffs,
                    &mut tmp.coeffs,
                );
                p.add_assign(&tmp);
                // `tmp` depends on secret `r` and must be wiped before reuse.
                zeroize_poly(&mut tmp);
            }
            p.reduce();
        }
    }
}

// ── Note on zeroization ───────────────────────────────────────────────────────
// A is public; no sensitive data. No explicit zeroize needed.
// If a matrix is used in a context where it might hold intermediate secret
// computation results, the caller may call `zeroize_polyvec` on each row.
