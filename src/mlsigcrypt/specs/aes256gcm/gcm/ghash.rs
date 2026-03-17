/// GHASH — authenticator for GCM mode.
///
/// Computes GHASH(H, A, C) as defined in NIST SP 800-38D §6.4:
///   S_0 = 0^128
///   S_i = (S_{i-1} ⊕ B_i) × H   for each block B_i
///
/// Where the block sequence is:
///   pad(A) || pad(C) || [len(A) || len(C)]
///
/// The multiplication × is in GF(2^128) with the GCM irreducible polynomial:
///   p(x) = x^128 + x^7 + x^2 + x + 1
///
/// Bit ordering (NIST SP 800-38D §6.1): the leftmost bit of the first byte
/// is the coefficient of x^0 (the *lowest* degree term). This means:
///   "multiply by x" = right-shift with conditional reduction on the bit
///   that falls off the right (was at position x^127).
///
/// Reduction constant: R = 0xE1 || 0^120 (from p(x) without x^128).
///
/// Software path: classical 128-step binary multiplication.
/// This is correct, auditable, and ~500ns/KB. For high-throughput paths,
/// replace `gf_mul` with the 4-bit Shoup table method or PCLMULQDQ.
use crate::zeroize::{Zeroize, zeroize_array};

// ─────────────────────────────────────────────────────────────────────────────
// GhashState
// ─────────────────────────────────────────────────────────────────────────────

/// GHASH accumulator state.
///
/// Holds H (the subkey) and the running accumulator.
/// Both are secret — zeroized on `Drop`.
pub(crate) struct GhashState {
    h: [u8; 16],     // H = AES_K(0^128): the GHASH subkey
    accum: [u8; 16], // running accumulator, starts at 0^128
}

impl GhashState {
    /// Initialise GHASH with the subkey `h`.
    /// Accumulator starts at 0^128.
    pub(crate) fn new(h: [u8; 16]) -> Self {
        GhashState {
            h,
            accum: [0u8; 16],
        }
    }

    /// Process one exact 16-byte block:  accum = (accum ⊕ block) × H
    pub(crate) fn update(&mut self, block: &[u8; 16]) {
        xor_inplace(&mut self.accum, block);
        self.accum = gf_mul(&self.accum, &self.h);
    }

    /// Process an arbitrary-length byte slice.
    ///
    /// Complete 16-byte blocks are processed directly.
    /// A partial final block is zero-padded to 16 bytes before processing.
    /// An empty slice is a no-op (contributes no blocks to the accumulator).
    pub(crate) fn update_padded(&mut self, data: &[u8]) {
        let mut i = 0;
        // Full blocks
        while i + 16 <= data.len() {
            let block: [u8; 16] = data[i..i + 16].try_into().unwrap();
            self.update(&block);
            i += 16;
        }
        // Partial final block — zero-pad to 16 bytes
        if i < data.len() {
            let mut block = [0u8; 16];
            block[..data.len() - i].copy_from_slice(&data[i..]);
            self.update(&block);
        }
    }

    /// Write the 128-bit GHASH output into `out` and consume `self`.
    ///
    /// The accumulator is explicitly zeroized *before* `Drop` runs so that
    /// the value is never simultaneously live in `out` and still present in
    /// the now-unreachable `self.accum` on the stack. `Drop` will zeroize
    /// `self.h` (and redundantly re-zeroize `self.accum`), which is correct.
    ///
    /// Callers are responsible for zeroizing `out` after its final use.
    pub(crate) fn finalize_into(mut self, out: &mut [u8; 16]) {
        // 1. Copy accumulator to caller-owned output.
        *out = self.accum;
        // 2. Explicit wipe: the accumulator is secret material (it's the raw
        //    GHASH output S, from which the tag is derived). Clear it now,
        //    before this stack frame is reclaimed, rather than relying solely
        //    on Drop — which would run *after* the value has been moved out
        //    and the frame is about to be unwound.
        zeroize_array(&mut self.accum);
        // 3. Drop runs here, calling self.zeroize() which re-clears accum
        //    (already zero, harmless) and clears self.h.
    }
}

impl Zeroize for GhashState {
    fn zeroize(&mut self) {
        zeroize_array(&mut self.h);
        zeroize_array(&mut self.accum);
    }
}

impl Drop for GhashState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GF(2^128) multiplication
// ─────────────────────────────────────────────────────────────────────────────

/// Multiply two 128-bit GCM field elements.
///
/// Algorithm: classical bit-by-bit (NIST SP 800-38D Algorithm 1).
///   Z = 0, V = y
///   For each bit i of x (from MSbit of x[0] to LSbit of x[15]):
///     if x_i = 1: Z ⊕= V
///     V = gf_mul_x(V)   (right-shift with conditional reduction)
///
/// 128 iterations. Correct and auditable baseline.
///
/// # Performance note
/// For high-throughput use, replace with a 4-bit window table (32 iterations)
/// or PCLMULQDQ (3 carryless multiplications + reduction). The architecture
/// dispatch pattern in `arch/mod.rs` is already wired for a hardware path.
fn gf_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;

    for byte_idx in 0..16 {
        for bit_shift in (0..8).rev() {
            // Process bit (byte_idx*8 + (7-bit_shift)) of x, MSbit first.
            // bit_shift=7 → MSbit of the byte (x_i for i=byte_idx*8)
            if (x[byte_idx] >> bit_shift) & 1 == 1 {
                xor_inplace(&mut z, &v);
            }
            // Multiply V by x: right-shift by 1, reduce if the bit that
            // fell off the right (old LSbit of v[15], = x^127 coefficient) was 1.
            let lsb = v[15] & 1;
            for k in (1..16).rev() {
                v[k] = (v[k] >> 1) | ((v[k - 1] & 1) << 7);
            }
            v[0] >>= 1;
            if lsb == 1 {
                // R = 0xE1 followed by 15 zero bytes.
                // Derived from: x^128 ≡ x^7 + x^2 + x + 1 mod p(x)
                // In GCM bit ordering: MSbit of byte 0 = x^0, so
                //   x^0 = 0x80, x^1 = 0x40, x^2 = 0x20, x^7 = 0x01 → sum = 0xE1
                v[0] ^= 0xE1;
            }
        }
    }
    z
}

/// In-place XOR of two 16-byte arrays.
#[inline(always)]
fn xor_inplace(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── gf_mul field axioms ───────────────────────────────────────────────────

    #[test]
    fn gf_mul_by_zero_is_zero() {
        let h = [
            0xDCu8, 0x95, 0xC0, 0x78, 0xA2, 0x40, 0x89, 0xAD, 0x48, 0xA2, 0x14, 0x92, 0x84, 0x20,
            0x87, 0x08,
        ];
        assert_eq!(gf_mul(&[0u8; 16], &h), [0u8; 16]);
    }

    #[test]
    fn gf_mul_zero_by_h_is_zero() {
        let h = [
            0xDCu8, 0x95, 0xC0, 0x78, 0xA2, 0x40, 0x89, 0xAD, 0x48, 0xA2, 0x14, 0x92, 0x84, 0x20,
            0x87, 0x08,
        ];
        assert_eq!(gf_mul(&h, &[0u8; 16]), [0u8; 16]);
    }

    #[test]
    fn gf_mul_commutativity() {
        let a = [
            0x01u8, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let b = [
            0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77,
        ];
        assert_eq!(gf_mul(&a, &b), gf_mul(&b, &a));
    }

    #[test]
    fn gf_mul_distributivity() {
        let a = [0x12u8; 16];
        let b = [0x34u8; 16];
        let c = [0x56u8; 16];
        let mut bc = b;
        xor_inplace(&mut bc, &c);
        let lhs = gf_mul(&a, &bc);
        let mut rhs = gf_mul(&a, &b);
        xor_inplace(&mut rhs, &gf_mul(&a, &c));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn gf_mul_associativity() {
        let a = [0x11u8; 16];
        let b = [0x22u8; 16];
        let c = [0x33u8; 16];
        let lhs = gf_mul(&gf_mul(&a, &b), &c);
        let rhs = gf_mul(&a, &gf_mul(&b, &c));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn gf_mul_identity() {
        // The multiplicative identity in GCM's GF(2^128) is [0x80, 0, 0, ..., 0]
        let one = {
            let mut v = [0u8; 16];
            v[0] = 0x80;
            v
        };
        let a = [0xABu8; 16];
        assert_eq!(gf_mul(&a, &one), a, "a * 1 ≠ a");
        assert_eq!(gf_mul(&one, &a), a, "1 * a ≠ a");
    }

    #[test]
    fn gf_mul_self_xor_is_zero() {
        let a = [0x42u8; 16];
        assert_eq!(gf_mul(&a, &[0u8; 16]), [0u8; 16]);
    }

    // ── GHASH accumulation ───────────────────────────────────────────────────

    #[test]
    fn ghash_empty_data_zero_h_is_zero() {
        let mut out = [0u8; 16];
        GhashState::new([0u8; 16]).finalize_into(&mut out);
        assert_eq!(out, [0u8; 16]);
    }

    #[test]
    fn ghash_single_block_zero_h() {
        let mut gs = GhashState::new([0u8; 16]);
        gs.update(&[0xFFu8; 16]);
        let mut out = [0u8; 16];
        gs.finalize_into(&mut out);
        assert_eq!(out, [0u8; 16]);
    }

    #[test]
    fn ghash_update_single_block_with_real_h() {
        let h = [
            0xdcu8, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20,
            0x87, 0x08,
        ];
        let mut gs = GhashState::new(h);
        gs.update(&[0u8; 16]);
        let mut out = [0u8; 16];
        gs.finalize_into(&mut out);
        assert_eq!(out, [0u8; 16]);
    }

    #[test]
    fn ghash_update_non_zero_block() {
        // With H = identity element, (0 ^ block) * 1 = block
        let one = {
            let mut v = [0u8; 16];
            v[0] = 0x80;
            v
        };
        let block = [
            0x12u8, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let mut gs = GhashState::new(one);
        gs.update(&block);
        let mut out = [0u8; 16];
        gs.finalize_into(&mut out);
        assert_eq!(out, block);
    }

    #[test]
    fn ghash_update_padded_empty_is_noop() {
        let h = [
            0xdcu8, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20,
            0x87, 0x08,
        ];
        let gs = GhashState::new(h);
        let mut out = [0u8; 16];
        gs.finalize_into(&mut out);
        assert_eq!(out, [0u8; 16]);
    }

    #[test]
    fn ghash_update_padded_exact_block_boundary() {
        let h = [0x80u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let data = [0xAAu8; 32];

        let mut gs_padded = GhashState::new(h);
        gs_padded.update_padded(&data);
        let mut out_p = [0u8; 16];
        gs_padded.finalize_into(&mut out_p);

        let mut gs_manual = GhashState::new(h);
        gs_manual.update(&data[0..16].try_into().unwrap());
        gs_manual.update(&data[16..32].try_into().unwrap());
        let mut out_m = [0u8; 16];
        gs_manual.finalize_into(&mut out_m);

        assert_eq!(out_p, out_m);
    }

    #[test]
    fn ghash_update_padded_partial_last_block() {
        let h = [0x80u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let data = [0xBBu8; 20];

        let mut gs_padded = GhashState::new(h);
        gs_padded.update_padded(&data);
        let mut out_p = [0u8; 16];
        gs_padded.finalize_into(&mut out_p);

        let mut gs_manual = GhashState::new(h);
        let b1: [u8; 16] = data[0..16].try_into().unwrap();
        let mut b2 = [0u8; 16];
        b2[..4].copy_from_slice(&data[16..]);
        gs_manual.update(&b1);
        gs_manual.update(&b2);
        let mut out_m = [0u8; 16];
        gs_manual.finalize_into(&mut out_m);

        assert_eq!(out_p, out_m);
    }

    #[test]
    fn ghash_zeroize_clears_state() {
        let h = [
            0xdcu8, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20,
            0x87, 0x08,
        ];
        let mut gs = GhashState::new(h);
        gs.update(&[0xFFu8; 16]);
        gs.zeroize();
        assert_eq!(gs.h, [0u8; 16]);
        assert_eq!(gs.accum, [0u8; 16]);
    }

    // ── finalize_into leaves no residue in the GhashState ────────────────────

    #[test]
    fn finalize_into_writes_correct_output() {
        // H = identity → GHASH(block) = block
        let one = {
            let mut v = [0u8; 16];
            v[0] = 0x80;
            v
        };
        let block = [0xDEu8; 16];
        let mut gs = GhashState::new(one);
        gs.update(&block);
        let mut out = [0u8; 16];
        gs.finalize_into(&mut out);
        assert_eq!(out, block);
    }

    // ── Determinism & sensitivity ─────────────────────────────────────────────

    #[test]
    fn ghash_deterministic_for_same_h_and_data() {
        let h = [
            0xdcu8, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20,
            0x87, 0x08,
        ];
        let data = [0x42u8; 48];

        let mut out_a = [0u8; 16];
        let mut out_b = [0u8; 16];
        let mut gs_a = GhashState::new(h);
        gs_a.update_padded(&data);
        gs_a.finalize_into(&mut out_a);
        let mut gs_b = GhashState::new(h);
        gs_b.update_padded(&data);
        gs_b.finalize_into(&mut out_b);

        assert_eq!(out_a, out_b);
    }

    #[test]
    fn ghash_different_h_different_output() {
        let h1 = [0x01u8; 16];
        let h2 = [0x02u8; 16];
        let data = [0xAAu8; 16];

        let mut out1 = [0u8; 16];
        let mut gs1 = GhashState::new(h1);
        gs1.update_padded(&data);
        gs1.finalize_into(&mut out1);

        let mut out2 = [0u8; 16];
        let mut gs2 = GhashState::new(h2);
        gs2.update_padded(&data);
        gs2.finalize_into(&mut out2);

        assert_ne!(out1, out2);
    }
}
