/// Polynomial type for Z_q[X]/(X^256+1).
///
/// Coefficients stored as i16. In standard form: values in [0, q).
/// In NTT domain: values may range up to ≈7q; reduce before arithmetic.
///
/// `Poly` intentionally has no Copy or Clone — secret polynomials (s, e, r)
/// must be explicitly zeroized and passed by reference. Public polynomials
/// (t̂, A rows) are stack-allocated and their lifetime is controlled structurally.
///
/// `Zeroize` is implemented via Drop only when wrapped in sensitive key types.
use core::ptr;

use crate::mlsigcrypt::specs::mlkem1024::field::{barrett_reduce, fqmul, reduce_to_pos};
use crate::mlsigcrypt::specs::mlkem1024::ntt::{inv_ntt, ntt, poly_basemul};
use crate::mlsigcrypt::specs::mlkem1024::params::{DU, DV, N, Q16};

// ── Type ──────────────────────────────────────────────────────────────────────

/// A polynomial in Z_q[X]/(X^256+1) with i16 coefficients.
pub(crate) struct Poly {
    pub(crate) coeffs: [i16; N],
}

impl Poly {
    /// Zero polynomial.
    #[inline]
    pub(crate) const fn zero() -> Self {
        Self { coeffs: [0i16; N] }
    }

    // ── Reduction ─────────────────────────────────────────────────────────────

    /// Barrett-reduce all coefficients to (-q, q).
    #[inline]
    pub(crate) fn reduce(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = barrett_reduce(*c);
        }
    }

    /// Reduce all coefficients to [0, q).
    #[inline]
    pub(crate) fn reduce_pos(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = reduce_to_pos(*c) as i16;
        }
    }

    // ── Arithmetic ────────────────────────────────────────────────────────────

    /// Coefficient-wise addition. No reduction; caller must reduce after use.
    #[inline]
    pub(crate) fn add_assign(&mut self, other: &Poly) {
        for i in 0..N {
            self.coeffs[i] = self.coeffs[i].wrapping_add(other.coeffs[i]);
        }
    }

    /// Coefficient-wise subtraction.
    #[inline]
    pub(crate) fn sub_assign(&mut self, other: &Poly) {
        for i in 0..N {
            self.coeffs[i] = self.coeffs[i].wrapping_sub(other.coeffs[i]);
        }
    }

    /// Add `other` into `self` and Barrett-reduce.
    #[inline]
    pub(crate) fn add_reduce(&mut self, other: &Poly) {
        for i in 0..N {
            self.coeffs[i] = barrett_reduce(self.coeffs[i].wrapping_add(other.coeffs[i]));
        }
    }

    // ── NTT ───────────────────────────────────────────────────────────────────

    /// Apply forward NTT in place.
    #[inline]
    pub(crate) fn ntt(&mut self) {
        ntt(&mut self.coeffs);
        self.reduce();
    }

    /// Apply inverse NTT in place. Scales by 128^{-1} mod q.
    #[inline]
    pub(crate) fn inv_ntt(&mut self) {
        inv_ntt(&mut self.coeffs);
    }

    /// Multiply two NTT-domain polynomials, result into `self`.
    #[inline]
    pub(crate) fn basemul(&mut self, a: &Poly, b: &Poly) {
        poly_basemul(&a.coeffs, &b.coeffs, &mut self.coeffs);
    }

    /// Accumulate NTT-domain product: self += a * b.
    #[inline]
    pub(crate) fn basemul_acc(&mut self, a: &Poly, b: &Poly) {
        // Reuse poly_basemul into temp then add — avoids allocating a full Poly.
        let mut tmp = Poly::zero();
        poly_basemul(&a.coeffs, &b.coeffs, &mut tmp.coeffs);
        self.add_assign(&tmp);
        zeroize_poly(&mut tmp);
    }

    // ── Compress / Decompress ─────────────────────────────────────────────────

    /// Compress to d_u bits per coefficient and write to `out` (POLY_COMPRESSED_U bytes).
    /// `out.len()` must equal N * DU / 8 = 352.
    pub(crate) fn compress_du(&self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), N * DU / 8);
        for i in 0..N / 8 {
            let mut t = [0u16; 8];
            for (k, tk) in t.iter_mut().enumerate() {
                let mut u = self.coeffs[8 * i + k];
                u += (u >> 15) & Q16;
                let mut d0 = (u as u64) << 11;
                d0 = d0.wrapping_add(1664);
                d0 = d0.wrapping_mul(645_084);
                d0 >>= 31;
                *tk = (d0 as u16) & 0x07FF;
            }

            let base = 11 * i;
            out[base] = (t[0] >> 0) as u8;
            out[base + 1] = ((t[0] >> 8) | (t[1] << 3)) as u8;
            out[base + 2] = ((t[1] >> 5) | (t[2] << 6)) as u8;
            out[base + 3] = (t[2] >> 2) as u8;
            out[base + 4] = ((t[2] >> 10) | (t[3] << 1)) as u8;
            out[base + 5] = ((t[3] >> 7) | (t[4] << 4)) as u8;
            out[base + 6] = ((t[4] >> 4) | (t[5] << 7)) as u8;
            out[base + 7] = (t[5] >> 1) as u8;
            out[base + 8] = ((t[5] >> 9) | (t[6] << 2)) as u8;
            out[base + 9] = ((t[6] >> 6) | (t[7] << 5)) as u8;
            out[base + 10] = (t[7] >> 3) as u8;
        }
    }

    /// Decompress d_u bits per coefficient from `bytes` (352 bytes).
    pub(crate) fn decompress_du(&mut self, bytes: &[u8]) {
        debug_assert_eq!(bytes.len(), N * DU / 8);
        for i in 0..N / 8 {
            let base = 11 * i;
            let t0 = (bytes[base] as u16) | ((bytes[base + 1] as u16) << 8);
            let t1 = ((bytes[base + 1] as u16) >> 3) | ((bytes[base + 2] as u16) << 5);
            let t2 = ((bytes[base + 2] as u16) >> 6)
                | ((bytes[base + 3] as u16) << 2)
                | ((bytes[base + 4] as u16) << 10);
            let t3 = ((bytes[base + 4] as u16) >> 1) | ((bytes[base + 5] as u16) << 7);
            let t4 = ((bytes[base + 5] as u16) >> 4) | ((bytes[base + 6] as u16) << 4);
            let t5 = ((bytes[base + 6] as u16) >> 7)
                | ((bytes[base + 7] as u16) << 1)
                | ((bytes[base + 8] as u16) << 9);
            let t6 = ((bytes[base + 8] as u16) >> 2) | ((bytes[base + 9] as u16) << 6);
            let t7 = ((bytes[base + 9] as u16) >> 5) | ((bytes[base + 10] as u16) << 3);
            let t = [t0, t1, t2, t3, t4, t5, t6, t7];
            for (k, tk) in t.iter().enumerate() {
                self.coeffs[8 * i + k] = (((tk & 0x07FF) as u32 * Q16 as u32 + 1024) >> 11) as i16;
            }
        }
    }

    /// Compress to d_v bits per coefficient (POLY_COMPRESSED_V = 160 bytes).
    pub(crate) fn compress_dv(&self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), N * DV / 8);
        for i in 0..N / 8 {
            let mut t = [0u8; 8];
            for (j, tj) in t.iter_mut().enumerate() {
                let mut u = self.coeffs[8 * i + j];
                u += (u >> 15) & Q16;
                let mut d0 = (u as u32) << 5;
                d0 = d0.wrapping_add(1664);
                d0 = d0.wrapping_mul(40_318);
                d0 >>= 27;
                *tj = (d0 as u8) & 0x1F;
            }

            let base = 5 * i;
            out[base] = (t[0] >> 0) | (t[1] << 5);
            out[base + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
            out[base + 2] = (t[3] >> 1) | (t[4] << 4);
            out[base + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
            out[base + 4] = (t[6] >> 2) | (t[7] << 3);
        }
    }

    /// Decompress d_v bits per coefficient (160 bytes).
    pub(crate) fn decompress_dv(&mut self, bytes: &[u8]) {
        debug_assert_eq!(bytes.len(), N * DV / 8);
        for i in 0..N / 8 {
            let base = 5 * i;
            let t0 = bytes[base] >> 0;
            let t1 = (bytes[base] >> 5) | (bytes[base + 1] << 3);
            let t2 = bytes[base + 1] >> 2;
            let t3 = (bytes[base + 1] >> 7) | (bytes[base + 2] << 1);
            let t4 = (bytes[base + 2] >> 4) | (bytes[base + 3] << 4);
            let t5 = bytes[base + 3] >> 1;
            let t6 = (bytes[base + 3] >> 6) | (bytes[base + 4] << 2);
            let t7 = bytes[base + 4] >> 3;
            let t = [t0, t1, t2, t3, t4, t5, t6, t7];
            for (j, tj) in t.iter().enumerate() {
                self.coeffs[8 * i + j] = (((tj & 0x1F) as u32 * Q16 as u32 + 16) >> 5) as i16;
            }
        }
    }

    // ── Message encoding ──────────────────────────────────────────────────────

    /// Encode a 32-byte message into a polynomial.
    ///
    /// Each message bit b encodes as coefficient round(b * q/2).
    /// Decompress_1(y) = round(q/2 * y).
    pub(crate) fn from_msg(msg: &[u8; 32]) -> Self {
        let mut p = Poly::zero();
        for i in 0..N {
            let bit = ((msg[i / 8] >> (i % 8)) & 1) as i16;
            // bit * (q+1)/2 rounded — equivalent to Decompress_1
            p.coeffs[i] = (bit * ((Q16 + 1) / 2)) as i16;
        }
        p
    }

    /// Decode a polynomial to a 32-byte message via Compress_1.
    ///
    /// Each coefficient x rounds to nearest of {0, q/2}.
    /// compress(x, 1) = round(2/q * x) mod 2 = MSB of 2x/q.
    pub(crate) fn to_msg(&self, msg: &mut [u8; 32]) {
        for i in 0..N / 8 {
            msg[i] = 0;
            for j in 0..8 {
                let mut t = self.coeffs[8 * i + j] as i32 as u32;
                t <<= 1;
                t = t.wrapping_add(1665);
                t = t.wrapping_mul(80635);
                t >>= 28;
                t &= 1;
                msg[i] |= (t as u8) << j;
            }
        }
    }
}

// ── Zeroization ───────────────────────────────────────────────────────────────

/// Volatile-write zeroize a polynomial's coefficient array.
/// Must be called on any Poly that held secret data before it is dropped.
#[inline]
pub(crate) fn zeroize_poly(p: &mut Poly) {
    for c in p.coeffs.iter_mut() {
        // SAFETY: c is a valid aligned i16 reference.
        unsafe { ptr::write_volatile(c, 0i16) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// ── 12-bit encode/decode (key material) ──────────────────────────────────────

/// Encode a polynomial as 12 bits per coefficient (384 bytes).
/// Used for serialising ŝ and t̂ into key material.
/// Coefficients must be in [0, q) before calling.
pub(crate) fn poly_encode12(p: &Poly, out: &mut [u8; 384]) {
    // Two coefficients per 3-byte group: c0 in bits 0..11, c1 in bits 12..23.
    for i in 0..128 {
        let c0 = reduce_to_pos(p.coeffs[2 * i]) as u16;
        let c1 = reduce_to_pos(p.coeffs[2 * i + 1]) as u16;
        out[3 * i] = c0 as u8;
        out[3 * i + 1] = ((c0 >> 8) | (c1 << 4)) as u8;
        out[3 * i + 2] = (c1 >> 4) as u8;
    }
}

/// Decode a 384-byte buffer into a polynomial (12 bits per coefficient).
pub(crate) fn poly_decode12(bytes: &[u8; 384], p: &mut Poly) {
    for i in 0..128 {
        let b0 = bytes[3 * i] as u16;
        let b1 = bytes[3 * i + 1] as u16;
        let b2 = bytes[3 * i + 2] as u16;
        p.coeffs[2 * i] = (b0 | ((b1 & 0x0F) << 8)) as i16;
        p.coeffs[2 * i + 1] = ((b1 >> 4) | (b2 << 4)) as i16;
    }
}

/// Montgomery-domain conversion: multiply all coefficients by R mod q via `R^2 mod q`.
/// Call after `poly_decode12` on t̂ / ŝ if operations will use `fqmul`.
#[inline]
pub(crate) fn poly_to_mont(p: &mut Poly) {
    use crate::mlsigcrypt::specs::mlkem1024::field::MONT2;
    for c in p.coeffs.iter_mut() {
        *c = fqmul(*c, MONT2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntt_roundtrip_recovers_polynomial_mod_q() {
        let mut p = Poly::zero();
        let mut expected = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = ((i * 17) as i16).wrapping_sub(2000);
            expected.coeffs[i] = barrett_reduce(p.coeffs[i]);
        }
        poly_to_mont(&mut expected);

        p.ntt();
        p.inv_ntt();
        p.reduce();

        for i in 0..N {
            assert_eq!(
                reduce_to_pos(p.coeffs[i]),
                reduce_to_pos(expected.coeffs[i])
            );
        }
    }
}
