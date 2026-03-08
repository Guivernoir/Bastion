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

use crate::algos::mlkem1024::field::{
    barrett_reduce, compress as field_compress, decompress as field_decompress, fqmul,
    reduce_to_pos,
};
use crate::algos::mlkem1024::ntt::{inv_ntt, ntt, poly_basemul};
use crate::algos::mlkem1024::params::{DU, DV, N, Q16};

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
        pack_bits(&self.coeffs, out, DU, |c| {
            field_compress(reduce_to_pos(c) as u16, DU as u32)
        });
    }

    /// Decompress d_u bits per coefficient from `bytes` (352 bytes).
    pub(crate) fn decompress_du(&mut self, bytes: &[u8]) {
        debug_assert_eq!(bytes.len(), N * DU / 8);
        unpack_bits(bytes, &mut self.coeffs, DU, |y| {
            field_decompress(y, DU as u32) as i16
        });
    }

    /// Compress to d_v bits per coefficient (POLY_COMPRESSED_V = 160 bytes).
    pub(crate) fn compress_dv(&self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), N * DV / 8);
        pack_bits(&self.coeffs, out, DV, |c| {
            field_compress(reduce_to_pos(c) as u16, DV as u32)
        });
    }

    /// Decompress d_v bits per coefficient (160 bytes).
    pub(crate) fn decompress_dv(&mut self, bytes: &[u8]) {
        debug_assert_eq!(bytes.len(), N * DV / 8);
        unpack_bits(bytes, &mut self.coeffs, DV, |y| {
            field_decompress(y, DV as u32) as i16
        });
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
        msg.fill(0);
        for i in 0..N {
            let bit = field_compress(reduce_to_pos(self.coeffs[i]) as u16, 1) as u8;
            msg[i / 8] |= bit << (i % 8);
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

// ── Bit-packing helpers ───────────────────────────────────────────────────────

/// Generic d-bit packer for compress output.
///
/// Packs 256 values of `d` bits each into `out`.
/// `out.len()` == 256 * d / 8.
/// `extract(coeff)` must return a value in [0, 2^d).
fn pack_bits(coeffs: &[i16; N], out: &mut [u8], d: usize, extract: impl Fn(i16) -> u16) {
    let mask = ((1u16 << d) - 1) as u32;
    let mut acc: u32 = 0;
    let mut bits: usize = 0;
    let mut out_idx: usize = 0;

    for &c in coeffs.iter() {
        let val = (extract(c) as u32) & mask;
        acc |= val << bits;
        bits += d;
        while bits >= 8 {
            out[out_idx] = acc as u8;
            out_idx += 1;
            acc >>= 8;
            bits -= 8;
        }
    }
    // Flush any remaining bits (d*256 is always divisible by 8 for valid d).
    if bits > 0 {
        out[out_idx] = acc as u8;
    }
}

/// Generic d-bit unpacker for decompress input.
///
/// Reads 256 values of `d` bits each from `bytes`.
/// `inject(raw)` converts from [0, 2^d) to a coefficient.
fn unpack_bits(bytes: &[u8], coeffs: &mut [i16; N], d: usize, inject: impl Fn(u16) -> i16) {
    let mask = (1u32 << d) - 1;
    let mut acc: u32 = 0;
    let mut bits: usize = 0;
    let mut src_idx: usize = 0;

    for c in coeffs.iter_mut() {
        while bits < d {
            acc |= (bytes[src_idx] as u32) << bits;
            src_idx += 1;
            bits += 8;
        }
        *c = inject((acc & mask) as u16);
        acc >>= d;
        bits -= d;
    }
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

/// Montgomery-domain conversion: multiply all coefficients by MONT = 2^16 mod q.
/// Call after `poly_decode12` on t̂ / ŝ if operations will use `fqmul`.
#[inline]
pub(crate) fn poly_to_mont(p: &mut Poly) {
    use crate::algos::mlkem1024::field::MONT;
    for c in p.coeffs.iter_mut() {
        *c = fqmul(*c, MONT);
    }
}
