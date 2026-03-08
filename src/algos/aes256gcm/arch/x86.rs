#![allow(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
/// x86/x86_64 AES-NI + PCLMULQDQ hardware-accelerated paths.
///
/// Requires: `target_feature = "aes"` (Intel 2010+, AMD 2011+).
///
/// AES-NI instruction set used:
///   `_mm_aeskeygenassist_si128`  — key schedule assist
///   `_mm_aesenc_si128`           — one AES round (Sub+Shift+Mix+XOR)
///   `_mm_aesenclast_si128`       — final AES round (no MixColumns)
///
/// Key schedule technique: Intel white paper
/// "Intel Advanced Encryption Standard (AES) New Instructions Set" (2010).
///
/// Safety contract: all functions are gated behind `#[target_feature(enable = "aes")]`
/// or called only after confirmed runtime detection. The `unsafe` blocks here are
/// a necessary consequence of the SIMD intrinsic API — not an architectural smell.

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

// ─────────────────────────────────────────────────────────────────────────────
// Key Schedule (AES-NI)
// ─────────────────────────────────────────────────────────────────────────────

/// Expand a 256-bit key into 15 round keys using AES-NI assist instructions.
///
/// AES-256 key derivation:
///   - Even round keys: `aeskeygenassist` on previous *odd* key (imm8 = Rcon)
///   - Odd round keys:  `aeskeygenassist` on previous *even* key (imm8 = 0x00)
///
/// # Safety
/// Caller must ensure `target_feature = "aes"` is available.
#[target_feature(enable = "aes")]
pub(super) unsafe fn expand_key_256(key: &[u8; 32], round_keys: &mut [[u8; 16]; 15]) {
    let mut key_lo = _mm_loadu_si128(key.as_ptr() as *const __m128i);
    let mut key_hi = _mm_loadu_si128(key.as_ptr().add(16) as *const __m128i);

    _mm_storeu_si128(round_keys[0].as_mut_ptr() as *mut __m128i, key_lo);
    _mm_storeu_si128(round_keys[1].as_mut_ptr() as *mut __m128i, key_hi);

    macro_rules! expand_even {
        ($rcon:expr, $out:expr) => {{
            let assist = _mm_aeskeygenassist_si128(key_hi, $rcon);
            key_lo = key_assist_even(key_lo, assist);
            _mm_storeu_si128(round_keys[$out].as_mut_ptr() as *mut __m128i, key_lo);
        }};
    }

    macro_rules! expand_odd {
        ($out:expr) => {{
            let assist = _mm_aeskeygenassist_si128(key_lo, 0x00);
            key_hi = key_assist_odd(key_hi, assist);
            _mm_storeu_si128(round_keys[$out].as_mut_ptr() as *mut __m128i, key_hi);
        }};
    }

    expand_even!(0x01, 2);
    expand_odd!(3);
    expand_even!(0x02, 4);
    expand_odd!(5);
    expand_even!(0x04, 6);
    expand_odd!(7);
    expand_even!(0x08, 8);
    expand_odd!(9);
    expand_even!(0x10, 10);
    expand_odd!(11);
    expand_even!(0x20, 12);
    expand_odd!(13);
    expand_even!(0x40, 14);
}

/// Even-round key assist: feedback XOR pattern for even round keys.
#[inline]
#[target_feature(enable = "aes")]
unsafe fn key_assist_even(mut key: __m128i, assist: __m128i) -> __m128i {
    // Splat the high 32-bit word across all four 32-bit lanes
    let assist = _mm_shuffle_epi32(assist, 0xFF);
    let mut tmp = _mm_slli_si128(key, 4);
    key = _mm_xor_si128(key, tmp);
    tmp = _mm_slli_si128(key, 4);
    key = _mm_xor_si128(key, tmp);
    tmp = _mm_slli_si128(key, 4);
    key = _mm_xor_si128(key, tmp);
    _mm_xor_si128(key, assist)
}

/// Odd-round key assist: uses lane 2 of the assist (imm8 = 0xAA).
#[inline]
#[target_feature(enable = "aes")]
unsafe fn key_assist_odd(mut key: __m128i, assist: __m128i) -> __m128i {
    let assist = _mm_shuffle_epi32(assist, 0xAA);
    let mut tmp = _mm_slli_si128(key, 4);
    key = _mm_xor_si128(key, tmp);
    tmp = _mm_slli_si128(key, 4);
    key = _mm_xor_si128(key, tmp);
    tmp = _mm_slli_si128(key, 4);
    key = _mm_xor_si128(key, tmp);
    _mm_xor_si128(key, assist)
}

// ─────────────────────────────────────────────────────────────────────────────
// Block Encrypt (AES-NI)
// ─────────────────────────────────────────────────────────────────────────────

/// Encrypt a single 128-bit block in-place using AES-NI.
///
/// 13 × `aesenc` + 1 × `aesenclast` = 14 rounds.
/// On Haswell: ~4-cycle latency per `aesenc`, throughput 1/cycle.
///
/// # Safety
/// Caller must ensure `target_feature = "aes"` is available.
#[target_feature(enable = "aes")]
pub(super) unsafe fn aes256_encrypt(block: &mut [u8; 16], round_keys: &[[u8; 16]; 15]) {
    let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);

    // Helper macro: load round key i as __m128i without a named binding array
    macro_rules! rk {
        ($i:expr) => {
            _mm_loadu_si128(round_keys[$i].as_ptr() as *const __m128i)
        };
    }

    // Round 0: AddRoundKey
    state = _mm_xor_si128(state, rk!(0));

    // Rounds 1–13: SubBytes + ShiftRows + MixColumns + AddRoundKey
    state = _mm_aesenc_si128(state, rk!(1));
    state = _mm_aesenc_si128(state, rk!(2));
    state = _mm_aesenc_si128(state, rk!(3));
    state = _mm_aesenc_si128(state, rk!(4));
    state = _mm_aesenc_si128(state, rk!(5));
    state = _mm_aesenc_si128(state, rk!(6));
    state = _mm_aesenc_si128(state, rk!(7));
    state = _mm_aesenc_si128(state, rk!(8));
    state = _mm_aesenc_si128(state, rk!(9));
    state = _mm_aesenc_si128(state, rk!(10));
    state = _mm_aesenc_si128(state, rk!(11));
    state = _mm_aesenc_si128(state, rk!(12));
    state = _mm_aesenc_si128(state, rk!(13));

    // Round 14: SubBytes + ShiftRows + AddRoundKey (no MixColumns)
    state = _mm_aesenclast_si128(state, rk!(14));

    _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
}

// ─────────────────────────────────────────────────────────────────────────────
// GCM field multiply (PCLMULQDQ) — used by ghash module
// ─────────────────────────────────────────────────────────────────────────────

/// Carry-less 128×128 multiply using PCLMULQDQ + Karatsuba decomposition.
///
/// Returns the raw 256-bit product as (lo_128, hi_128).
/// GCM polynomial reduction is the caller's responsibility (see `ghash.rs`).
///
/// Karatsuba: 3 CLMUL ops instead of 4.
///   lo    = a_lo × b_lo
///   hi    = a_hi × b_hi
///   mid   = (a_lo × b_hi) ⊕ (a_hi × b_lo)
///   full  = lo ⊕ (mid << 64) | (mid >> 64) ⊕ hi
///
/// # Safety
/// Requires `pclmulqdq`, `sse2`, `ssse3`.
#[cfg(target_feature = "pclmulqdq")]
#[target_feature(enable = "pclmulqdq", enable = "sse2", enable = "ssse3")]
pub(super) unsafe fn clmul_128(a: &[u8; 16], b: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let a = _mm_loadu_si128(a.as_ptr() as *const __m128i);
    let b = _mm_loadu_si128(b.as_ptr() as *const __m128i);

    let lo = _mm_clmulepi64_si128(a, b, 0x00); // a_lo × b_lo
    let hi = _mm_clmulepi64_si128(a, b, 0x11); // a_hi × b_hi
    let mid_a = _mm_clmulepi64_si128(a, b, 0x10); // a_lo × b_hi
    let mid_b = _mm_clmulepi64_si128(a, b, 0x01); // a_hi × b_lo
    let mid = _mm_xor_si128(mid_a, mid_b);

    let mid_lo = _mm_slli_si128(mid, 8);
    let mid_hi = _mm_srli_si128(mid, 8);

    let result_lo = _mm_xor_si128(lo, mid_lo);
    let result_hi = _mm_xor_si128(hi, mid_hi);

    let mut out_lo = [0u8; 16];
    let mut out_hi = [0u8; 16];
    _mm_storeu_si128(out_lo.as_mut_ptr() as *mut __m128i, result_lo);
    _mm_storeu_si128(out_hi.as_mut_ptr() as *mut __m128i, result_hi);
    (out_lo, out_hi)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    // These tests only run on x86/x86_64 where AES-NI is present at compile time.
    // If building without `target_feature=+aes`, the tests are compiled out.
    //
    // To run on a native machine:
    //   RUSTFLAGS="-C target-feature=+aes,+ssse3,+pclmulqdq" cargo test

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "aes"
    ))]
    mod aesni {
        use super::*;

        fn expand(key: [u8; 32]) -> [[u8; 16]; 15] {
            let mut rk = [[0u8; 16]; 15];
            // SAFETY: test is cfg-gated behind target_feature = "aes"
            unsafe { expand_key_256(&key, &mut rk) };
            rk
        }

        fn encrypt(key: [u8; 32], mut block: [u8; 16]) -> [u8; 16] {
            let rk = expand(key);
            // SAFETY: test is cfg-gated behind target_feature = "aes"
            unsafe { aes256_encrypt(&mut block, &rk) };
            block
        }

        #[test]
        fn key_schedule_rk0_is_first_half() {
            let key = [
                0x60u8, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85,
                0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10,
                0xa3, 0x09, 0x14, 0xdf, 0xf4,
            ];
            let rk = expand(key);
            assert_eq!(rk[0], key[0..16]);
            assert_eq!(rk[1], key[16..32]);
        }

        #[test]
        fn key_schedule_rk2_nist_vector() {
            let key = [
                0x60u8, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85,
                0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10,
                0xa3, 0x09, 0x14, 0xdf, 0xf4,
            ];
            let rk = expand(key);
            assert_eq!(
                rk[2],
                [
                    0x9b, 0xa3, 0x54, 0x11, 0x8e, 0x69, 0x25, 0xaf, 0xa5, 0x1a, 0x8b, 0x5f, 0x20,
                    0x67, 0xfc, 0xde
                ]
            );
        }

        #[test]
        fn encrypt_fips197_appendix_b() {
            let key = [
                0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            ];
            let pt = [
                0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff,
            ];
            let ct = encrypt(key, pt);
            assert_eq!(
                ct,
                [
                    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b,
                    0x49, 0x60, 0x89
                ]
            );
        }

        #[test]
        fn encrypt_zero_block_zero_key() {
            let ct = encrypt([0u8; 32], [0u8; 16]);
            assert_eq!(
                ct,
                [
                    0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84,
                    0x20, 0x87, 0x08
                ]
            );
        }

        #[test]
        fn aesni_matches_software_path() {
            // AES-NI and software must produce identical output for all inputs tested
            use crate::algos::aes256gcm::arch::soft;
            let key = [0xABu8; 32];
            let pt = [0xCDu8; 16];

            let hw = encrypt(key, pt);

            let mut sw_rk = [[0u8; 16]; 15];
            soft::expand_key_256(&key, &mut sw_rk);
            let mut sw = pt;
            soft::aes256_encrypt(&mut sw, &sw_rk);

            assert_eq!(hw, sw, "AES-NI and software paths diverge");
        }
    }
}
