use crate::mlsigcrypt::specs::ml::field::{decompose, fqmul, make_hint, reduce32};
use crate::mlsigcrypt::specs::ml::matrix::PolyMatrix;
use crate::mlsigcrypt::specs::ml::packing::{pack_sig, polyw1_pack, unpack_sk};
/// ML-DSA-87 signing — FIPS 204 Algorithm 2.
///
/// # Algorithm
///
///   Input:  sk (4896 bytes), msg (arbitrary), rnd (32 bytes)
///   Output: sig (4627 bytes)
///
///   1.  Unpack sk → (ρ, K_seed, tr, s1, s2, t0)
///   2.  μ   ← H(tr ‖ msg, 64 bytes)
///   3.  ρ'  ← H(K_seed ‖ rnd ‖ μ, 64 bytes)
///   4.  Precompute: A ← ExpandA(ρ);  NTT(s1), NTT(s2), NTT(t0)
///   5.  κ ← 0
///   6.  LOOP:
///         y ← ExpandMask(ρ', κ);   κ += L
///         Compute w = INTT(A·NTT(y)),  w1 = HighBits(w),  w0 = LowBits(w)
///         c̃ ← H(μ ‖ BitPack(w1), λ/4 bytes)
///         c ← SampleInBall(c̃);  ĉ ← NTT(c)
///         cs1 ← INTT(ĉ ⊙ ŝ1);  cs2 ← INTT(ĉ ⊙ ŝ2);  ct0 ← INTT(ĉ ⊙ t̂0)
///         z ← y + cs1
///         r0 ← LowBits(w − cs2)
///         REJECT if ‖z‖∞ ≥ γ₁−β  or  ‖r0‖∞ ≥ γ₂−β
///         h ← MakeHint(−ct0, w − cs2 + ct0)
///         REJECT if ‖ct0‖∞ ≥ γ₂  or  weight(h) > ω
///         BREAK
///   7.  σ ← sigEncode(c̃, z mod± q, h)
///
/// # Randomized vs deterministic signing
/// Pass `rnd = [0u8; 32]` for fully deterministic signing (useful for KAT).
/// Pass 32 random bytes for hedged signing (protects against faulty RNG).
///
/// # Timing
/// The rejection loop is NOT constant-time w.r.t. the number of iterations.
/// This is by design: iteration count reveals no information beyond a geometric
/// distribution with a fixed parameter. Side-channel analysis of WHICH iteration
/// succeeded may still be possible on some microarchitectures.
use crate::mlsigcrypt::specs::ml::params::{
    BETA, GAMMA1, GAMMA2, K, L, LAMBDA2_BYTES, N, OMEGA, POLYW1_BYTES, SIG_BYTES, SK_BYTES,
};
use crate::mlsigcrypt::specs::ml::poly::Poly;
use crate::mlsigcrypt::specs::ml::sampling::{
    expand_a, expand_mask, sample_in_ball, shake256_absorb_squeeze,
};
use crate::mlsigcrypt::specs::ml::vec::{PolyVec, zeroize_polyvec};
use crate::zeroize::zeroize_array;

// ── Public API ────────────────────────────────────────────────────────────────

/// Sign a message using ML-DSA-87.
///
/// # Arguments
/// * `sig` — output buffer for the signature (4627 bytes)
/// * `msg` — message bytes to sign
/// * `sk`  — secret key (4896 bytes, output of `keypair`)
/// * `rnd` — 32 bytes of fresh randomness, or `[0u8;32]` for deterministic mode
pub(crate) fn sign(sig: &mut [u8; SIG_BYTES], msg: &[u8], sk: &[u8; SK_BYTES], rnd: &[u8; 32]) {
    // ── Step 1: Unpack secret key ─────────────────────────────────────────────
    let mut rho = [0u8; 32];
    let mut k_seed = [0u8; 32];
    let mut tr = [0u8; 64];
    let mut s1: PolyVec<L> = PolyVec::zero();
    let mut s2: PolyVec<K> = PolyVec::zero();
    let mut t0: PolyVec<K> = PolyVec::zero();
    unpack_sk(
        &mut rho,
        &mut k_seed,
        &mut tr,
        &mut s1,
        &mut s2,
        &mut t0,
        sk,
    );

    // ── Step 2: μ = H(tr ‖ msg, 64 bytes) ────────────────────────────────────
    let mut mu = [0u8; 64];
    shake256_absorb_squeeze(&[&tr, msg], &mut mu);

    // ── Step 3: ρ' = H(K_seed ‖ rnd ‖ μ, 64 bytes) ──────────────────────────
    let mut rho_prime = [0u8; 64];
    shake256_absorb_squeeze(&[&k_seed, rnd, &mu], &mut rho_prime);

    // ── Step 4: Precompute public matrix and NTT of secret material ───────────
    let mut mat_a = PolyMatrix::zero();
    expand_a(&mut mat_a, &rho);

    // s1, s2, t0 are converted to NTT domain in-place — they are never used
    // again in standard form (only in pointwise multiplication with ĉ).
    s1.ntt();
    s2.ntt();
    t0.ntt();

    // ── Step 5/6: Rejection-sampling loop ────────────────────────────────────
    let mut kappa: u16 = 0;

    // Stack temporaries reused across loop iterations.
    let mut y: PolyVec<L> = PolyVec::zero();
    let mut y_hat: PolyVec<L> = PolyVec::zero();
    let mut w_hat: PolyVec<K> = PolyVec::zero();
    let mut w: PolyVec<K> = PolyVec::zero();
    let mut w1: PolyVec<K> = PolyVec::zero();
    let mut w0: PolyVec<K> = PolyVec::zero();
    let mut c_hat: Poly = Poly::zero();
    let mut cs1: PolyVec<L> = PolyVec::zero();
    let mut cs2: PolyVec<K> = PolyVec::zero();
    let mut ct0: PolyVec<K> = PolyVec::zero();
    let mut z: PolyVec<L> = PolyVec::zero();
    let mut h: PolyVec<K> = PolyVec::zero();

    let mut c_tilde = [0u8; LAMBDA2_BYTES];
    let mut w1_packed_buf = [0u8; K * POLYW1_BYTES]; // 1024 bytes on stack

    'outer: loop {
        // ── Sample mask y ─────────────────────────────────────────────────────
        expand_mask(&mut y, &rho_prime, kappa);
        kappa = kappa.wrapping_add(L as u16);

        // ── w = INTT(A × NTT(y)) ─────────────────────────────────────────────
        // Keep y in standard form; compute y_hat as a separate NTT copy.
        for i in 0..L {
            y_hat.polys[i].coeffs.copy_from_slice(&y.polys[i].coeffs);
            y_hat.polys[i].ntt();
        }
        mat_a.matvec_ntt(&y_hat, &mut w_hat);

        for i in 0..K {
            w.polys[i].coeffs.copy_from_slice(&w_hat.polys[i].coeffs);
            w.polys[i].inv_ntt();
            w.polys[i].reduce();
            w.polys[i].caddq(); // ensure coefficients in [0, q) for Decompose
        }

        // ── w1 = HighBits(w),  w0 = LowBits(w) ──────────────────────────────
        for i in 0..K {
            for j in 0..N {
                let (r1, r0) = decompose(w.polys[i].coeffs[j]);
                w1.polys[i].coeffs[j] = r1;
                w0.polys[i].coeffs[j] = r0;
            }
        }

        // ── c̃ = H(μ ‖ BitPack(w1), λ/4 bytes) ───────────────────────────────
        for i in 0..K {
            let start = i * POLYW1_BYTES;
            let end = start + POLYW1_BYTES;
            let packed: &mut [u8; POLYW1_BYTES] =
                (&mut w1_packed_buf[start..end]).try_into().unwrap();
            polyw1_pack(packed, &w1.polys[i]);
        }
        shake256_absorb_squeeze(&[&mu, &w1_packed_buf], &mut c_tilde);

        // ── c ← SampleInBall(c̃);  ĉ ← NTT(c) ──────────────────────────────
        sample_in_ball(&mut c_hat, &c_tilde);
        c_hat.ntt();

        // ── cs1 = INTT(ĉ ⊙ ŝ1),  cs2 = INTT(ĉ ⊙ ŝ2),  ct0 = INTT(ĉ ⊙ t̂0) ─
        for i in 0..L {
            for j in 0..N {
                cs1.polys[i].coeffs[j] = fqmul(c_hat.coeffs[j], s1.polys[i].coeffs[j]);
            }
            cs1.polys[i].inv_ntt();
            cs1.polys[i].reduce();
        }
        for i in 0..K {
            for j in 0..N {
                cs2.polys[i].coeffs[j] = fqmul(c_hat.coeffs[j], s2.polys[i].coeffs[j]);
            }
            cs2.polys[i].inv_ntt();
            cs2.polys[i].reduce();

            for j in 0..N {
                ct0.polys[i].coeffs[j] = fqmul(c_hat.coeffs[j], t0.polys[i].coeffs[j]);
            }
            ct0.polys[i].inv_ntt();
            ct0.polys[i].reduce();
        }

        // ── z = y + cs1 ───────────────────────────────────────────────────────
        for i in 0..L {
            for j in 0..N {
                z.polys[i].coeffs[j] = y.polys[i].coeffs[j].wrapping_add(cs1.polys[i].coeffs[j]);
            }
        }

        // ── Rejection: ‖z‖∞ ≥ γ₁−β ──────────────────────────────────────────
        if !z.check_norm_lt(GAMMA1 - BETA) {
            continue 'outer;
        }

        // ── r0 rejection: w0 = w0 − cs2; reject if ‖w0‖∞ ≥ γ₂−β ─────────────
        let mut reject_r0 = false;
        for i in 0..K {
            for j in 0..N {
                let v = w0.polys[i].coeffs[j].wrapping_sub(cs2.polys[i].coeffs[j]);
                let r0 = reduce32(v);
                w0.polys[i].coeffs[j] = r0;
                if r0.abs() >= GAMMA2 - BETA {
                    reject_r0 = true;
                }
            }
        }
        if reject_r0 {
            continue 'outer;
        }

        // ── ‖ct0‖∞ ≥ γ₂ rejection ────────────────────────────────────────────
        if !ct0.check_norm_lt(GAMMA2) {
            continue 'outer;
        }

        // ── h = MakeHint(w0 + ct0, w1) ───────────────────────────────────────
        let mut hint_weight = 0usize;
        for i in 0..K {
            for j in 0..N {
                let a0 = reduce32(w0.polys[i].coeffs[j].wrapping_add(ct0.polys[i].coeffs[j]));
                w0.polys[i].coeffs[j] = a0;
                let h_bit = make_hint(a0, w1.polys[i].coeffs[j]);
                h.polys[i].coeffs[j] = h_bit;
                hint_weight += h_bit as usize;
            }
        }

        // ── weight(h) > ω rejection ───────────────────────────────────────────
        if hint_weight > OMEGA {
            continue 'outer;
        }

        // ── Accept: encode signature ──────────────────────────────────────────
        break 'outer;
    }

    // z mod± q: coefficients are already in (-γ₁, γ₁) after norm check passes.
    pack_sig(sig, &c_tilde, &z, &h);

    // ── Zeroize sensitive material ────────────────────────────────────────────
    zeroize_polyvec(&mut s1);
    zeroize_polyvec(&mut s2);
    zeroize_polyvec(&mut t0);
    zeroize_polyvec(&mut y);
    zeroize_polyvec(&mut w);
    zeroize_polyvec(&mut w0);
    zeroize_polyvec(&mut w1);
    zeroize_polyvec(&mut cs1);
    zeroize_polyvec(&mut cs2);
    zeroize_polyvec(&mut ct0);
    zeroize_polyvec(&mut z);
    zeroize_polyvec(&mut h);
    zeroize_polyvec(&mut y_hat);
    zeroize_polyvec(&mut w_hat);
    zeroize_array(&mut rho);
    zeroize_array(&mut k_seed);
    zeroize_array(&mut tr);
    zeroize_array(&mut mu);
    zeroize_array(&mut rho_prime);
    zeroize_array(&mut c_tilde);
    zeroize_array(&mut w1_packed_buf);
    crate::mlsigcrypt::specs::ml::poly::zeroize_poly(&mut c_hat);
}
