use crate::mlsigcrypt::specs::mlkem1024::hash::{shake128_xof_init, shake256_prf};
use crate::mlsigcrypt::specs::mlkem1024::keccak::zeroize_sponge;
use crate::mlsigcrypt::specs::mlkem1024::matrix::PolyMatrix;
/// Sampling for ML-KEM: CBD-η (centered binomial) and matrix rejection sampling.
///
/// CBD-η2(σ, b): SHAKE-256(σ ‖ b) → 128 bytes → polynomial with small coefficients.
/// XOF(ρ, i, j): SHAKE-128(ρ ‖ i ‖ j) → rejection-sample a uniform Z_q polynomial.
///
/// No allocation; PRF output lives on the stack.
/// All secret-input sponges are zeroized via `zeroize_sponge`.
use crate::mlsigcrypt::specs::mlkem1024::params::{
    ETA1, ETA1_PRF_BYTES, ETA2, ETA2_PRF_BYTES, K, N,
};
use crate::mlsigcrypt::specs::mlkem1024::poly::Poly;
use crate::mlsigcrypt::specs::mlkem1024::vec::PolyVec;

// ── Centered binomial distribution ────────────────────────────────────────────

/// Sample a polynomial from the centered binomial distribution CBD_η.
///
/// `buf` must be exactly `64 * eta` bytes (= PRF output).
/// Coefficients will be in {-η, ..., η} ⊂ [-2, 2] for η=2.
///
/// Algorithm: for each of the N positions, read 2η bits; let a = popcount of
/// first η bits, b = popcount of second η bits; coefficient = a - b.
///
/// Specialised for η ∈ {1, 2} (no other values used in ML-KEM-1024).
fn cbd(p: &mut Poly, buf: &[u8], eta: usize) {
    debug_assert_eq!(buf.len(), 64 * eta);
    match eta {
        2 => cbd2(p, buf),
        _ => unreachable!("ML-KEM-1024 only uses η ∈ {{1, 2}}"),
    }
}

/// CBD-2 specialisation: 4 bits → (2-bit a, 2-bit b) → coefficient = a - b.
///
/// Process 8 coefficients per 32-bit word, matching the Kyber reference flow.
#[inline]
fn cbd2(p: &mut Poly, buf: &[u8]) {
    debug_assert_eq!(buf.len(), 128);
    for i in 0..N / 8 {
        let t = u32::from_le_bytes([buf[4 * i], buf[4 * i + 1], buf[4 * i + 2], buf[4 * i + 3]]);
        let mut d = t & 0x5555_5555;
        d = d.wrapping_add((t >> 1) & 0x5555_5555);

        for j in 0..8usize {
            let a = ((d >> (4 * j)) & 0x3) as i16;
            let b = ((d >> (4 * j + 2)) & 0x3) as i16;
            p.coeffs[8 * i + j] = a - b;
        }
    }
}

// ── PRF wrappers ──────────────────────────────────────────────────────────────

/// Sample the l-th secret polynomial: p ← CBD_η1(PRF(σ, l)).
pub(crate) fn sample_noise_eta1(p: &mut Poly, sigma: &[u8; 32], nonce: u8) {
    let mut buf = [0u8; ETA1_PRF_BYTES];
    shake256_prf(sigma, nonce, &mut buf);
    cbd(p, &buf, ETA1);
    // Zeroize PRF output — it's derived from the secret σ.
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0u8) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Sample the l-th error polynomial: p ← CBD_η2(PRF(σ, l)).
pub(crate) fn sample_noise_eta2(p: &mut Poly, sigma: &[u8; 32], nonce: u8) {
    let mut buf = [0u8; ETA2_PRF_BYTES];
    shake256_prf(sigma, nonce, &mut buf);
    cbd(p, &buf, ETA2);
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0u8) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// ── Vector sampling ───────────────────────────────────────────────────────────

/// Sample a K-vector of noise polynomials starting at `nonce_offset`.
///
/// s or e in KeyGen: nonce 0..K-1 and K..2K-1 respectively.
/// r in Encaps: nonce 0..K-1.
pub(crate) fn sample_noise_vec_eta1(v: &mut PolyVec, sigma: &[u8; 32], nonce_offset: u8) {
    for i in 0..K {
        sample_noise_eta1(&mut v.polys[i], sigma, nonce_offset + i as u8);
    }
}

/// Sample K error polynomials with CBD_η2 starting at `nonce_offset`.
pub(crate) fn sample_noise_vec_eta2(v: &mut PolyVec, sigma: &[u8; 32], nonce_offset: u8) {
    for i in 0..K {
        sample_noise_eta2(&mut v.polys[i], sigma, nonce_offset + i as u8);
    }
}

// ── Rejection sampling for matrix A ──────────────────────────────────────────

/// Parse (rejection sample) a uniform polynomial from a SHAKE-128 XOF stream.
///
/// Algorithm (FIPS 203 §4.2.2 SampleNTT):
///   Squeeze bytes three at a time; extract two 12-bit values d1, d2.
///   Accept d1 if d1 < q; accept d2 if d2 < q.
///   Stop when 256 coefficients have been accepted.
///
/// Average bytes needed: 256 × (3/2) / (q/4096) ≈ 530 — fits in two SHAKE-128 blocks (336 bytes).
fn parse_poly_from_xof(p: &mut Poly, rho: &[u8; 32], i: u8, j: u8) {
    let mut xof = shake128_xof_init(rho, i, j);

    let mut ctr = 0usize;
    let mut buf = [0u8; 168 * 2]; // two rate-blocks; more than enough in practice

    'outer: loop {
        xof.squeeze(&mut buf);
        let mut pos = 0usize;

        while pos + 3 <= buf.len() {
            let b0 = buf[pos] as u16;
            let b1 = buf[pos + 1] as u16;
            let b2 = buf[pos + 2] as u16;
            pos += 3;

            let d1 = b0 | ((b1 & 0x0F) << 8); // 12-bit value
            let d2 = (b1 >> 4) | (b2 << 4); // 12-bit value

            if d1 < crate::mlsigcrypt::specs::mlkem1024::params::Q as u16 {
                p.coeffs[ctr] = d1 as i16;
                ctr += 1;
                if ctr == N {
                    break 'outer;
                }
            }
            if d2 < crate::mlsigcrypt::specs::mlkem1024::params::Q as u16 {
                p.coeffs[ctr] = d2 as i16;
                ctr += 1;
                if ctr == N {
                    break 'outer;
                }
            }
        }
    }

    zeroize_sponge(&mut xof);
    // xof is NOT secret (ρ is public), but zeroize defensively.
}

// ── Matrix generation ─────────────────────────────────────────────────────────

/// Generate the public matrix A (or Aᵀ) from seed ρ.
///
/// A[i][j] = SampleNTT(XOF(ρ, j, i))  — standard orientation
/// Aᵀ[i][j] = A[j][i] = SampleNTT(XOF(ρ, i, j))  — transposed
///
/// `transposed = false` → A  (used in KeyGen for t̂ = Â·ŝ + ê)
/// `transposed = true`  → Aᵀ (used in Enc for u = NTTᵻ(Âᵀ·r̂) + e₁)
pub(crate) fn gen_matrix(m: &mut PolyMatrix, rho: &[u8; 32], transposed: bool) {
    for i in 0..K {
        for j in 0..K {
            // FIPS 203 / Kyber convention:
            //   A[i][j]   = XOF(rho, j, i)
            //   A^T[i][j] = XOF(rho, i, j)
            let (xof_i, xof_j) = if transposed {
                (i as u8, j as u8)
            } else {
                (j as u8, i as u8)
            };
            parse_poly_from_xof(&mut m.rows[i].polys[j], rho, xof_i, xof_j);
        }
    }
}
