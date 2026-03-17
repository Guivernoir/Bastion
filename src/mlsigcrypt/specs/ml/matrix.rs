use crate::mlsigcrypt::specs::ml::ntt::poly_pointwise_acc;
/// K×L polynomial matrix for ML-DSA-87.
///
/// The public matrix A is generated in NTT domain from seed ρ and never leaves it.
/// Two products are needed:
///   • A  × s̃ (NTT-domain, KeyGen: w = INTT(A × NTT(s1)))
///   • Aᵀ × r̃ (NTT-domain, Verify: A × NTT(z) − c × 2^d × t1)
///
/// Indexing: rows[i].polys[j] = A[i][j], i ∈ [0,K), j ∈ [0,L).
///
/// A is public — no zeroization required.
use crate::mlsigcrypt::specs::ml::params::{K, L, N};
use crate::mlsigcrypt::specs::ml::vec::PolyVec;

// ── Type ──────────────────────────────────────────────────────────────────────

/// K×L matrix of NTT-domain polynomials. Stack size: 8 × 7 × 1024 B = 57344 B ≈ 56 KB.
///
/// This is the largest stack allocation in the module. On embedded targets, consider
/// splitting KeyGen/Sign into phases with explicit stack frames or using a static.
pub(crate) struct PolyMatrix {
    pub(crate) rows: [PolyVec<L>; K],
}

impl PolyMatrix {
    #[inline]
    pub(crate) fn zero() -> Self {
        // SAFETY: all-zero bytes are valid for [i32; N] at every position.
        unsafe { core::mem::zeroed() }
    }

    // ── A × s (used in KeyGen and Sign) ──────────────────────────────────────

    /// out = A × s̃ in NTT domain.
    ///
    /// out[i] = Σ_{j=0}^{L-1} A[i][j] ⊙ s̃[j]   (pointwise Montgomery multiply)
    ///
    /// Inputs and output are all in NTT domain.
    /// out must be zeroed before calling; K accumulations without inter-reduce
    /// can accumulate to at most K × q × q = 8 × q^2 < 2^50, safe for i32 sums.
    /// Call `reduce()` on out after the call.
    pub(crate) fn matvec_ntt(&self, s: &PolyVec<L>, out: &mut PolyVec<K>) {
        for i in 0..K {
            out.polys[i].coeffs.fill(0);
            for j in 0..L {
                poly_pointwise_acc(
                    &self.rows[i].polys[j].coeffs,
                    &s.polys[j].coeffs,
                    &mut out.polys[i].coeffs,
                );
            }
            out.polys[i].reduce();
        }
    }

    /// out = A × z − c × 2^d × t1, all in NTT domain. Used in Verify.
    ///
    /// Computes: out[i] = Σ_j A[i][j] ⊙ ẑ[j] − ĉ ⊙ (2^d × t̂1[i])
    /// where ẑ = NTT(z) and t̂1[i] = NTT(shiftl(t1[i])) are both pre-computed
    /// by the caller.
    ///
    /// `az`: A×z product (K-vector, NTT domain, already computed via matvec_ntt)
    /// `ct1`: c×2^d×t1 (K-vector, NTT domain)
    /// `out`: az − ct1 (K-vector, NTT domain)
    pub(crate) fn verify_product(az: &PolyVec<K>, ct1: &PolyVec<K>, out: &mut PolyVec<K>) {
        for i in 0..K {
            for j in 0..N {
                out.polys[i].coeffs[j] = az.polys[i].coeffs[j] - ct1.polys[i].coeffs[j];
            }
            out.polys[i].reduce();
        }
    }
}
