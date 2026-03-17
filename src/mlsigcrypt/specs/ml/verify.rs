use crate::mlsigcrypt::specs::ml::field::{fqmul, use_hint};
use crate::mlsigcrypt::specs::ml::matrix::PolyMatrix;
use crate::mlsigcrypt::specs::ml::packing::{polyw1_pack, unpack_pk, unpack_sig};
/// ML-DSA-87 signature verification — FIPS 204 Algorithm 3.
///
/// # Algorithm
///
///   Input:  pk (2592 bytes), msg (arbitrary), sig (4627 bytes)
///   Output: bool (true iff valid)
///
///   1.  Unpack pk → (ρ, t1)
///   2.  Unpack sig → (c̃, z, h);  REJECT if hint encoding is malformed
///   3.  REJECT if ‖z‖∞ ≥ γ₁ − β
///   4.  REJECT if weight(h) > ω    (implicit in unpack_hint)
///   5.  A ← ExpandA(ρ)
///   6.  tr ← H(pk, 64);  μ ← H(tr ‖ msg, 64)
///   7.  c ← SampleInBall(c̃);  ĉ ← NTT(c)
///   8.  w' ← INTT(A·NTT(z) − ĉ·NTT(2^d·t1))
///   9.  w1' ← UseHint(h, w')
///   10. c̃' ← H(μ ‖ BitPack(w1'))
///   11. return c̃' == c̃
///
/// # Constant-time properties
/// Steps 1–9 run in data-independent time w.r.t. the acceptance decision.
/// The final comparison (step 11) uses a constant-time equality check.
/// Steps 5–9 do NOT branch on secret data; all branches depend only on
/// public inputs or iteration variables.
use crate::mlsigcrypt::specs::ml::params::{
    BETA, GAMMA1, K, L, LAMBDA2_BYTES, N, PK_BYTES, POLYW1_BYTES, SIG_BYTES,
};
use crate::mlsigcrypt::specs::ml::poly::Poly;
use crate::mlsigcrypt::specs::ml::sampling::{expand_a, sample_in_ball, shake256_absorb_squeeze};
use crate::mlsigcrypt::specs::ml::vec::PolyVec;

// ── Public API ────────────────────────────────────────────────────────────────

/// Verify an ML-DSA-87 signature.
///
/// Returns `true` if and only if `sig` is a valid signature on `msg` under `pk`.
///
/// All structural checks (hint weight, z norm, encoding validity) return `false`
/// rather than panicking, so this function is safe to call on untrusted inputs.
pub(crate) fn verify(sig: &[u8; SIG_BYTES], msg: &[u8], pk: &[u8; PK_BYTES]) -> bool {
    // ── Step 1: Unpack public key ─────────────────────────────────────────────
    let mut rho = [0u8; 32];
    let mut t1: PolyVec<K> = PolyVec::zero();
    unpack_pk(&mut rho, &mut t1, pk);

    // ── Step 2: Unpack signature, validate hint encoding ─────────────────────
    let mut c_tilde = [0u8; LAMBDA2_BYTES];
    let mut z: PolyVec<L> = PolyVec::zero();
    let mut h: PolyVec<K> = PolyVec::zero();
    if !unpack_sig(&mut c_tilde, &mut z, &mut h, sig) {
        return false; // malformed hint bytes
    }

    // ── Step 3: Norm check on z ───────────────────────────────────────────────
    // z coefficients from polyz_unpack are in (-γ₁, γ₁); check ‖z‖∞ < γ₁−β.
    if !z.check_norm_lt(GAMMA1 - BETA) {
        return false;
    }

    // ── Steps 5–6: Expand A; derive μ ────────────────────────────────────────
    let mut mat_a = PolyMatrix::zero();
    expand_a(&mut mat_a, &rho);

    // tr = H(pk, 64);  μ = H(tr ‖ msg, 64).
    let mut tr = [0u8; 64];
    shake256_absorb_squeeze(&[pk.as_slice()], &mut tr);
    let mut mu = [0u8; 64];
    shake256_absorb_squeeze(&[&tr, msg], &mut mu);

    // ── Step 7: c ← SampleInBall(c̃);  ĉ ← NTT(c) ──────────────────────────
    let mut c_hat: Poly = Poly::zero();
    sample_in_ball(&mut c_hat, &c_tilde);
    c_hat.ntt();

    // ── Step 8a: A·NTT(z) in NTT domain ──────────────────────────────────────
    z.ntt(); // z is now NTT(z); we no longer need standard-domain z
    let mut az: PolyVec<K> = PolyVec::zero();
    mat_a.matvec_ntt(&z, &mut az); // az = A·NTT(z) in NTT domain

    // ── Step 8b: ĉ·NTT(2^d·t1) in NTT domain ────────────────────────────────
    //
    // For each row i: t1_shifted = t1[i] << D (shiftl), then NTT.
    // ct1[i] = ĉ ⊙ NTT(t1_shifted[i]).
    let mut ct1: PolyVec<K> = PolyVec::zero();
    for i in 0..K {
        // Copy t1[i] into ct1[i], shift left by D bits, then NTT.
        ct1.polys[i].coeffs.copy_from_slice(&t1.polys[i].coeffs);
        ct1.polys[i].shiftl(); // × 2^d
        ct1.polys[i].ntt(); // NTT(2^d·t1[i])
        // Overwrite with pointwise product with ĉ.
        for j in 0..N {
            ct1.polys[i].coeffs[j] = fqmul(c_hat.coeffs[j], ct1.polys[i].coeffs[j]);
        }
    }

    // ── Step 8c: w' = INTT(az − ct1) ─────────────────────────────────────────
    let mut w: PolyVec<K> = PolyVec::zero();
    PolyMatrix::verify_product(&az, &ct1, &mut w); // NTT domain subtraction + reduce
    w.inv_ntt(); // to standard domain

    // Centre into [0, q) for UseHint (which internally calls Decompose).
    w.reduce();
    w.caddq();

    // ── Step 9: w1' = UseHint(h, w') coefficient-wise ────────────────────────
    let mut w1_prime: PolyVec<K> = PolyVec::zero();
    for i in 0..K {
        for j in 0..N {
            w1_prime.polys[i].coeffs[j] = use_hint(h.polys[i].coeffs[j], w.polys[i].coeffs[j]);
        }
    }

    // ── Step 10: c̃' = H(μ ‖ BitPack(w1')) ───────────────────────────────────
    let mut w1_packed = [0u8; K * POLYW1_BYTES]; // 1024 bytes
    for i in 0..K {
        let start = i * POLYW1_BYTES;
        let end = start + POLYW1_BYTES;
        let packed: &mut [u8; POLYW1_BYTES] = (&mut w1_packed[start..end]).try_into().unwrap();
        polyw1_pack(packed, &w1_prime.polys[i]);
    }
    let mut c_tilde_prime = [0u8; LAMBDA2_BYTES];
    shake256_absorb_squeeze(&[&mu, &w1_packed], &mut c_tilde_prime);

    // ── Step 11: Constant-time comparison c̃' == c̃ ───────────────────────────
    //
    // XOR all bytes and OR into an accumulator. Result is 0 iff equal.
    // This prevents the compiler from short-circuiting the comparison.
    let mut diff = 0u8;
    for i in 0..LAMBDA2_BYTES {
        diff |= c_tilde_prime[i] ^ c_tilde[i];
    }
    diff == 0
}
