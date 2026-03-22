/// Sampling algorithms for ML-DSA-87 (FIPS 204 §4.2).
///
/// ExpandA(ρ)      → A (public matrix, SHAKE-128 rejection sampling)
/// ExpandS(ρ, η)   → (s1, s2) (secret polynomials, bounded-coefficient rejection)
/// ExpandMask(ρ',κ)→ y (signing mask vector, γ₁-bounded)
/// SampleInBall(c̃) → c (challenge polynomial, τ ±1 entries)
///
/// All XOF state is zeroized after use. Sensitive inputs (σ, K, ρ') are zeroized
/// in the caller (sign.rs); this module only sees them transiently.
use crate::mlsigcrypt::specs::ml::matrix::PolyMatrix;
use crate::mlsigcrypt::specs::ml::params::{ETA, GAMMA1, K, L, LAMBDA2_BYTES, N, Q, TAU};
use crate::mlsigcrypt::specs::ml::poly::Poly;
use crate::mlsigcrypt::specs::ml::vec::PolyVec;

// ── Rate constants ────────────────────────────────────────────────────────────

const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;

// ── Local KeccakSponge access ─────────────────────────────────────────────────
// MLSigcrypt shares a single internal Keccak sponge implementation across the
// hash, XOF, and signing modules.

use crate::mlsigcrypt::specs::keccak::{KeccakSponge, zeroize_sponge};

const SHAKE_SUFFIX: u8 = 0x1F;

/// Absorb two slices then finalize a SHAKE-128 sponge for ExpandA.
#[inline]
fn shake128_init_2(a: &[u8], b: &[u8]) -> KeccakSponge<SHAKE128_RATE> {
    let mut s: KeccakSponge<SHAKE128_RATE> = KeccakSponge::new();
    s.absorb(a);
    s.absorb(b);
    s.finalize(SHAKE_SUFFIX);
    s
}

/// One-shot SHAKE-256 into a fixed-size output buffer.
/// Used for commitment hash, PRF, and mu derivation.
#[inline]
pub(crate) fn shake256_absorb_squeeze(inputs: &[&[u8]], out: &mut [u8]) {
    let mut s: KeccakSponge<SHAKE256_RATE> = KeccakSponge::new();
    for input in inputs {
        s.absorb(input);
    }
    s.finalize(SHAKE_SUFFIX);
    s.squeeze(out);
    zeroize_sponge(&mut s);
}

// ── ExpandA: matrix generation ────────────────────────────────────────────────

/// Rejection-sample a uniform NTT-domain polynomial from SHAKE-128.
///
/// Algorithm (FIPS 204 §4.2.1 / RejNTTPoly):
///   Squeeze three bytes at a time; extract one 23-bit value t:
///      t = (b0 | b1<<8 | b2<<16) & 0x7FFFFF
///   Accept t if t < q.
fn rej_ntt_poly(p: &mut Poly, rho: &[u8; 32], j: u8, i: u8) {
    // XOF(ρ ‖ j ‖ i): j = column index, i = row index (FIPS 204 order).
    let ji = [j, i];
    let mut xof = shake128_init_2(rho, &ji);

    let mut ctr = 0usize;
    let mut buf = [0u8; SHAKE128_RATE * 2];

    'outer: loop {
        xof.squeeze(&mut buf);
        let mut pos = 0usize;
        while pos + 3 <= buf.len() {
            let b0 = buf[pos] as u32;
            let b1 = buf[pos + 1] as u32;
            let b2 = buf[pos + 2] as u32;
            pos += 3;
            let t = (b0 | (b1 << 8) | (b2 << 16)) & 0x7FFFFF;
            if t < Q as u32 {
                p.coeffs[ctr] = t as i32;
                ctr += 1;
                if ctr == N {
                    break 'outer;
                }
            }
        }
    }
    zeroize_sponge(&mut xof);
}

/// ExpandA(ρ): generate the public K×L matrix A in NTT domain.
///
/// A[i][j] = RejNTTPoly(SHAKE-128(ρ ‖ j ‖ i))   (j = col, i = row).
pub(crate) fn expand_a(m: &mut PolyMatrix, rho: &[u8; 32]) {
    for i in 0..K {
        for j in 0..L {
            rej_ntt_poly(&mut m.rows[i].polys[j], rho, j as u8, i as u8);
        }
    }
}

// ── ExpandS: secret vector generation ────────────────────────────────────────

/// Rejection-sample a bounded polynomial (η=2) from SHAKE-256.
///
/// Algorithm (FIPS 204 §4.2.3 / CoefFromHalfByte for η=2):
///   Each byte yields two half-bytes b0 = byte & 0x0F, b1 = byte >> 4.
///   Accept b_i if b_i < 15; coefficient = b_i mod 5 − 2.
///   Rejection rate: 1/16 per nibble.
fn rej_bounded_poly(p: &mut Poly, rho: &[u8; 64], nonce: u16) {
    let nonce_bytes = nonce.to_le_bytes();
    let mut xof = {
        let mut s: KeccakSponge<SHAKE256_RATE> = KeccakSponge::new();
        s.absorb(rho);
        s.absorb(&nonce_bytes);
        s.finalize(SHAKE_SUFFIX);
        s
    };

    let mut ctr = 0usize;
    let mut buf = [0u8; SHAKE256_RATE * 2];

    'outer: loop {
        xof.squeeze(&mut buf);
        for &byte in buf.iter() {
            let b0 = (byte & 0x0F) as i32;
            let b1 = (byte >> 4) as i32;
            // Accept b if b < 15: coeff = η − (b mod 5) = 2 − (b mod 5).
            if b0 < 15 {
                p.coeffs[ctr] = ETA - (b0 % 5); // η = 2 → b%5 ∈ {0..4} → coeff ∈ {-2..2}
                ctr += 1;
                if ctr == N {
                    break 'outer;
                }
            }
            if b1 < 15 {
                p.coeffs[ctr] = ETA - (b1 % 5);
                ctr += 1;
                if ctr == N {
                    break 'outer;
                }
            }
        }
    }
    zeroize_sponge(&mut xof);
}

/// ExpandS(ρ, η): sample secret vectors s1 (L-vector) and s2 (K-vector).
///
/// s1[i] = RejBoundedPoly(SHAKE-256(ρ ‖ i))       for i = 0..L-1
/// s2[i] = RejBoundedPoly(SHAKE-256(ρ ‖ L+i))     for i = 0..K-1
pub(crate) fn expand_s(s1: &mut PolyVec<L>, s2: &mut PolyVec<K>, rho: &[u8; 64]) {
    for i in 0..L {
        rej_bounded_poly(&mut s1.polys[i], rho, i as u16);
    }
    for i in 0..K {
        rej_bounded_poly(&mut s2.polys[i], rho, (L + i) as u16);
    }
}

// ── ExpandMask ────────────────────────────────────────────────────────────────

/// ExpandMask(ρ', κ): sample the L-dimensional signing mask vector y.
///
/// FIPS 204 §4.2.4 / SampleMaskPoly.
///
/// For each i ∈ [0, L):
///   y[i] ← SampleMaskPoly(SHAKE-256(ρ' ‖ (κ+i) as LE16))
///
/// Coefficients: v = (γ₁ − sample) where sample is a 20-bit value.
/// Since 2γ₁ = 2^20, all 20-bit samples are within range — no rejection loop needed.
/// Result: y[i] coefficients ∈ [−γ₁+1, γ₁] (outer norm check in sign.rs ensures ‖y‖ < γ₁).
///
/// # Packing: 2 coefficients per 5 bytes (little-endian bits)
///   v0 = b0 | b1<<8 | (b2 & 0x0F)<<16        (bits 0–19)
///   v1 = (b2 >> 4) | b3<<4 | b4<<12          (bits 20–39)
pub(crate) fn expand_mask(y: &mut PolyVec<L>, rho_prime: &[u8; 64], kappa: u16) {
    // Buffer large enough for 256 coefficients × 5/2 bytes = 640 bytes in one go.
    let mut buf = [0u8; SHAKE256_RATE * 5]; // 680 bytes ≥ 640

    for i in 0..L {
        let nonce = kappa.wrapping_add(i as u16).to_le_bytes();

        let mut xof: KeccakSponge<SHAKE256_RATE> = KeccakSponge::new();
        xof.absorb(rho_prime);
        xof.absorb(&nonce);
        xof.finalize(SHAKE_SUFFIX);

        let mut ctr = 0usize;

        'outer: loop {
            xof.squeeze(&mut buf);
            let mut pos = 0usize;
            while pos + 5 <= buf.len() {
                let b0 = buf[pos] as u32;
                let b1 = buf[pos + 1] as u32;
                let b2 = buf[pos + 2] as u32;
                let b3 = buf[pos + 3] as u32;
                let b4 = buf[pos + 4] as u32;
                pos += 5;

                // Two 20-bit samples, little-endian.
                let v0 = b0 | (b1 << 8) | ((b2 & 0x0F) << 16);
                let v1 = (b2 >> 4) | (b3 << 4) | (b4 << 12);

                y.polys[i].coeffs[ctr] = GAMMA1 - v0 as i32;
                ctr += 1;
                if ctr == N {
                    break 'outer;
                }

                y.polys[i].coeffs[ctr] = GAMMA1 - v1 as i32;
                ctr += 1;
                if ctr == N {
                    break 'outer;
                }
            }
        }

        zeroize_sponge(&mut xof);
    }
}

// ── SampleInBall ──────────────────────────────────────────────────────────────

/// SampleInBall(c̃): generate the challenge polynomial with exactly τ = TAU entries in {±1}.
///
/// FIPS 204 §4.2.5.
///
/// Algorithm:
///   1. ctx = SHAKE-256(c̃)
///   2. Squeeze 8 bytes → u64 sign register (τ=60 bits needed; 64 available).
///   3. For i from (N−τ) to (N−1):
///        Rejection-sample j ∈ [0, i] from the XOF byte stream.
///        c[i] ← c[j]                       (Knuth-shuffle step)
///        c[j] ← 1 − 2·(signs & 1)          (assign ±1)
///        signs >>= 1
///
/// The shuffle produces a polynomial with exactly τ nonzero coefficients,
/// each ∈ {±1}, uniformly distributed over all such polynomials.
///
/// # Buffering
/// Bytes are squeezed in SHAKE256_RATE = 136 chunks, not one at a time,
/// to avoid per-byte Keccak permutation calls.
pub(crate) fn sample_in_ball(c: &mut Poly, c_tilde: &[u8; LAMBDA2_BYTES]) {
    let mut xof: KeccakSponge<SHAKE256_RATE> = KeccakSponge::new();
    xof.absorb(c_tilde);
    xof.finalize(SHAKE_SUFFIX);

    let mut buf = [0u8; SHAKE256_RATE];
    xof.squeeze(&mut buf);

    // First 8 bytes: sign register (60 sign bits for τ=60 nonzero entries).
    let mut signs = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let mut buf_pos = 8usize; // continue from byte 8 for position sampling

    c.coeffs.fill(0);

    for i in (N - TAU)..N {
        // Rejection-sample j ∈ [0, i].
        let j = loop {
            if buf_pos >= SHAKE256_RATE {
                xof.squeeze(&mut buf);
                buf_pos = 0;
            }
            let b = buf[buf_pos] as usize;
            buf_pos += 1;
            if b <= i {
                break b;
            }
        };

        c.coeffs[i] = c.coeffs[j];
        c.coeffs[j] = 1 - 2 * ((signs & 1) as i32); // ±1 from sign bit
        signs >>= 1;
    }

    zeroize_sponge(&mut xof);
}
