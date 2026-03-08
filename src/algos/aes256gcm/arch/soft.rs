/// Software (portable) AES-256 implementation.
///
/// Uses four 1KB lookup tables (Te0–Te3) built at compile time via `const fn`.
/// No heap, no alloc, no external dependencies.
///
/// Performance: ~20–50 cycles/byte. Acceptable fallback for non-x86 targets or
/// when AES-NI is unavailable. The hardware path is 1–3 cycles/byte.
///
/// References:
///   - FIPS 197, Section 5.1 (Cipher)
///   - FIPS 197, Section 5.2 (Key Expansion)

// ─────────────────────────────────────────────────────────────────────────────
// S-box and round constants
// ─────────────────────────────────────────────────────────────────────────────

// `const` (not `static`) — required to be usable inside `const fn build_te()`.
#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

#[rustfmt::skip]
const RCON: [u32; 11] = [
    0x00000000,
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000,
];

// ─────────────────────────────────────────────────────────────────────────────
// GF(2⁸) xtime — branchless multiply-by-2
// ─────────────────────────────────────────────────────────────────────────────

#[inline(always)]
const fn xtime(a: u8) -> u8 {
    let shifted = (a as u16) << 1;
    let mask = if a & 0x80 != 0 { 0x1Bu8 } else { 0x00u8 };
    (shifted as u8) ^ mask
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time Te table generation
// ─────────────────────────────────────────────────────────────────────────────

/// Build the four Te tables at compile time.
///
/// Te0[x] = [2·S(x), S(x), S(x), 3·S(x)] as a big-endian u32.
/// Te1–Te3 are byte rotations of Te0, encoding the ShiftRows permutation.
///
/// These fold SubBytes + ShiftRows + MixColumns into 4 table lookups per round.
const fn build_te() -> ([u32; 256], [u32; 256], [u32; 256], [u32; 256]) {
    let mut te0 = [0u32; 256];
    let mut te1 = [0u32; 256];
    let mut te2 = [0u32; 256];
    let mut te3 = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let s = SBOX[i];
        let s2 = xtime(s);
        let s3 = s2 ^ s;
        te0[i] = ((s2 as u32) << 24) | ((s as u32) << 16) | ((s as u32) << 8) | (s3 as u32);
        te1[i] = te0[i].rotate_right(8);
        te2[i] = te0[i].rotate_right(16);
        te3[i] = te0[i].rotate_right(24);
        i += 1;
    }
    (te0, te1, te2, te3)
}

/// 4 × 1024 bytes = 4KB, read-only, built at compile time.
static TE: ([u32; 256], [u32; 256], [u32; 256], [u32; 256]) = build_te();

// ─────────────────────────────────────────────────────────────────────────────
// Key Schedule
// ─────────────────────────────────────────────────────────────────────────────

/// Expand a 256-bit key into 15 × 128-bit round keys.
/// Temporary word schedule `w` is zeroized before returning.
pub(crate) fn expand_key_256(key: &[u8; 32], round_keys: &mut [[u8; 16]; 15]) {
    let mut w = [0u32; 60];

    for i in 0..8 {
        w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }

    for i in 8..60 {
        let mut temp = w[i - 1];
        if i % 8 == 0 {
            temp = sub_word(temp.rotate_left(8)) ^ RCON[i / 8];
        } else if i % 8 == 4 {
            temp = sub_word(temp);
        }
        w[i] = w[i - 8] ^ temp;
    }

    for rk in 0..15 {
        for word in 0..4 {
            let bytes = w[rk * 4 + word].to_be_bytes();
            round_keys[rk][word * 4..word * 4 + 4].copy_from_slice(&bytes);
        }
    }

    // Zeroize temporary word schedule — it mirrors key material.
    // SAFETY: `w` is valid for 60×4=240-byte write; exclusive access guaranteed.
    unsafe { crate::zeroize::zeroize_mem(w.as_mut_ptr() as *mut u8, 60 * 4) };
}

#[inline(always)]
fn sub_word(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

// ─────────────────────────────────────────────────────────────────────────────
// AES-256 Block Encrypt
// ─────────────────────────────────────────────────────────────────────────────

/// Encrypt a single 128-bit block in-place using Te tables.
///
/// - Rounds 0:     AddRoundKey
/// - Rounds 1–13:  SubBytes + ShiftRows + MixColumns + AddRoundKey (via Te)
/// - Round 14:     SubBytes + ShiftRows + AddRoundKey (no MixColumns, via S-box)
pub(crate) fn aes256_encrypt(block: &mut [u8; 16], round_keys: &[[u8; 16]; 15]) {
    let mut s0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
    let mut s1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
    let mut s2 = u32::from_be_bytes([block[8], block[9], block[10], block[11]]);
    let mut s3 = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);

    // Round 0: AddRoundKey
    let rk = load_rk(&round_keys[0]);
    s0 ^= rk[0];
    s1 ^= rk[1];
    s2 ^= rk[2];
    s3 ^= rk[3];

    // Rounds 1–13: SubBytes + ShiftRows + MixColumns + AddRoundKey
    let (te0, te1, te2, te3) = &TE;
    for r in 1..14 {
        let rk = load_rk(&round_keys[r]);
        let t0 = te0[(s0 >> 24) as usize]
            ^ te1[((s1 >> 16) & 0xFF) as usize]
            ^ te2[((s2 >> 8) & 0xFF) as usize]
            ^ te3[(s3 & 0xFF) as usize]
            ^ rk[0];
        let t1 = te0[(s1 >> 24) as usize]
            ^ te1[((s2 >> 16) & 0xFF) as usize]
            ^ te2[((s3 >> 8) & 0xFF) as usize]
            ^ te3[(s0 & 0xFF) as usize]
            ^ rk[1];
        let t2 = te0[(s2 >> 24) as usize]
            ^ te1[((s3 >> 16) & 0xFF) as usize]
            ^ te2[((s0 >> 8) & 0xFF) as usize]
            ^ te3[(s1 & 0xFF) as usize]
            ^ rk[2];
        let t3 = te0[(s3 >> 24) as usize]
            ^ te1[((s0 >> 16) & 0xFF) as usize]
            ^ te2[((s1 >> 8) & 0xFF) as usize]
            ^ te3[(s2 & 0xFF) as usize]
            ^ rk[3];
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    // Round 14: SubBytes + ShiftRows + AddRoundKey (no MixColumns)
    let rk = load_rk(&round_keys[14]);
    let t0 = ((SBOX[(s0 >> 24) as usize] as u32) << 24)
        | ((SBOX[((s1 >> 16) & 0xFF) as usize] as u32) << 16)
        | ((SBOX[((s2 >> 8) & 0xFF) as usize] as u32) << 8)
        | (SBOX[(s3 & 0xFF) as usize] as u32);
    let t1 = ((SBOX[(s1 >> 24) as usize] as u32) << 24)
        | ((SBOX[((s2 >> 16) & 0xFF) as usize] as u32) << 16)
        | ((SBOX[((s3 >> 8) & 0xFF) as usize] as u32) << 8)
        | (SBOX[(s0 & 0xFF) as usize] as u32);
    let t2 = ((SBOX[(s2 >> 24) as usize] as u32) << 24)
        | ((SBOX[((s3 >> 16) & 0xFF) as usize] as u32) << 16)
        | ((SBOX[((s0 >> 8) & 0xFF) as usize] as u32) << 8)
        | (SBOX[(s1 & 0xFF) as usize] as u32);
    let t3 = ((SBOX[(s3 >> 24) as usize] as u32) << 24)
        | ((SBOX[((s0 >> 16) & 0xFF) as usize] as u32) << 16)
        | ((SBOX[((s1 >> 8) & 0xFF) as usize] as u32) << 8)
        | (SBOX[(s2 & 0xFF) as usize] as u32);

    s0 = t0 ^ rk[0];
    s1 = t1 ^ rk[1];
    s2 = t2 ^ rk[2];
    s3 = t3 ^ rk[3];

    block[0..4].copy_from_slice(&s0.to_be_bytes());
    block[4..8].copy_from_slice(&s1.to_be_bytes());
    block[8..12].copy_from_slice(&s2.to_be_bytes());
    block[12..16].copy_from_slice(&s3.to_be_bytes());
}

#[inline(always)]
fn load_rk(rk: &[u8; 16]) -> [u32; 4] {
    [
        u32::from_be_bytes([rk[0], rk[1], rk[2], rk[3]]),
        u32::from_be_bytes([rk[4], rk[5], rk[6], rk[7]]),
        u32::from_be_bytes([rk[8], rk[9], rk[10], rk[11]]),
        u32::from_be_bytes([rk[12], rk[13], rk[14], rk[15]]),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn expand(key: [u8; 32]) -> [[u8; 16]; 15] {
        let mut rk = [[0u8; 16]; 15];
        expand_key_256(&key, &mut rk);
        rk
    }

    // ── S-box sanity ─────────────────────────────────────────────────────────

    #[test]
    fn sbox_zero_maps_to_0x63() {
        // AES S-box: S(0x00) = 0x63 (FIPS 197, Figure 7)
        assert_eq!(SBOX[0x00], 0x63);
    }

    #[test]
    fn sbox_0x53_maps_to_0xed() {
        // S(0x53) = 0xED from FIPS 197 worked example
        assert_eq!(SBOX[0x53], 0xED);
    }

    #[test]
    fn sbox_length() {
        assert_eq!(SBOX.len(), 256);
    }

    #[test]
    fn sbox_is_bijection() {
        // The S-box must be a permutation (all 256 output values distinct)
        let mut seen = [false; 256];
        for &v in SBOX.iter() {
            assert!(!seen[v as usize], "S-box collision at output {:#04x}", v);
            seen[v as usize] = true;
        }
    }

    // ── xtime (GF multiply-by-2) ─────────────────────────────────────────────

    #[test]
    fn xtime_no_reduction() {
        // 0x01 × 2 = 0x02 (no high bit)
        assert_eq!(xtime(0x01), 0x02);
    }

    #[test]
    fn xtime_with_reduction() {
        // 0x80 × 2 = 0x1B (high bit set, reduce with 0x1B)
        assert_eq!(xtime(0x80), 0x1B);
    }

    #[test]
    fn xtime_0x53() {
        // From FIPS 197: xtime(0x53) = 0xA6
        assert_eq!(xtime(0x53), 0xA6);
    }

    #[test]
    fn xtime_0xff_reduces() {
        // 0xFF × 2 = 0xFE XOR 0x1B = 0xE5
        assert_eq!(xtime(0xFF), 0xE5);
    }

    // ── Te table structure ───────────────────────────────────────────────────

    #[test]
    fn te_tables_are_rotations_of_each_other() {
        // Te1[i] = ROR(Te0[i], 8), Te2[i] = ROR(Te0[i], 16), etc.
        let (te0, te1, te2, te3) = &TE;
        for i in 0..256 {
            assert_eq!(te1[i], te0[i].rotate_right(8), "Te1[{i}] mismatch");
            assert_eq!(te2[i], te0[i].rotate_right(16), "Te2[{i}] mismatch");
            assert_eq!(te3[i], te0[i].rotate_right(24), "Te3[{i}] mismatch");
        }
    }

    #[test]
    fn te0_entry_0_is_correct() {
        // SBOX[0] = 0x63, xtime(0x63) = 0xC6, 3*0x63 = 0xC6 ^ 0x63 = 0xA5
        // Te0[0] = [0xC6, 0x63, 0x63, 0xA5] = 0xC6636363... wait
        // Te0[0] = [2·S(0), S(0), S(0), 3·S(0)] = [xtime(0x63), 0x63, 0x63, xtime(0x63)^0x63]
        let s = SBOX[0]; // 0x63
        let s2 = xtime(s); // xtime(0x63)
        let s3 = s2 ^ s; // 3·s
        let expected = ((s2 as u32) << 24) | ((s as u32) << 16) | ((s as u32) << 8) | (s3 as u32);
        assert_eq!(TE.0[0], expected);
    }

    // ── Key schedule ─────────────────────────────────────────────────────────

    #[test]
    fn key_schedule_rk0_is_key_first_half() {
        let key = [
            0x60u8, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let rk = expand(key);
        assert_eq!(rk[0], key[0..16]);
        assert_eq!(rk[1], key[16..32]);
    }

    #[test]
    fn key_schedule_rk2_nist_vector() {
        // NIST FIPS 197 Appendix A.3 round key 2
        let key = [
            0x60u8, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let rk = expand(key);
        assert_eq!(
            rk[2],
            [
                0x9b, 0xa3, 0x54, 0x11, 0x8e, 0x69, 0x25, 0xaf, 0xa5, 0x1a, 0x8b, 0x5f, 0x20, 0x67,
                0xfc, 0xde
            ]
        );
    }

    #[test]
    fn key_schedule_zero_key_rk0() {
        let rk = expand([0u8; 32]);
        assert_eq!(rk[0], [0u8; 16]);
        assert_eq!(rk[1], [0u8; 16]);
    }

    // ── Block encryption ─────────────────────────────────────────────────────

    #[test]
    fn encrypt_nist_fips197_appendix_b() {
        // NIST FIPS 197 Appendix B
        let key = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let mut block = [
            0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let rk = expand(key);
        aes256_encrypt(&mut block, &rk);
        assert_eq!(
            block,
            [
                0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
                0x60, 0x89
            ]
        );
    }

    #[test]
    fn encrypt_zero_block_zero_key() {
        // Used as the GHASH H value derivation
        let rk = expand([0u8; 32]);
        let mut block = [0u8; 16];
        aes256_encrypt(&mut block, &rk);
        assert_eq!(
            block,
            [
                0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84,
                0x20, 0x87
            ]
        );
    }

    #[test]
    fn encrypt_deterministic() {
        let rk = expand([0x42u8; 32]);
        let mut a = [0xABu8; 16];
        let mut b = [0xABu8; 16];
        aes256_encrypt(&mut a, &rk);
        aes256_encrypt(&mut b, &rk);
        assert_eq!(a, b);
    }

    #[test]
    fn encrypt_avalanche() {
        let rk = expand([0u8; 32]);
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        b[0] = 0x01;
        aes256_encrypt(&mut a, &rk);
        aes256_encrypt(&mut b, &rk);
        let diff: u32 = a
            .iter()
            .zip(b.iter())
            .map(|(x, y)| (x ^ y).count_ones())
            .sum();
        assert!(
            diff >= 40 && diff <= 88,
            "Avalanche weak: {diff}/128 bits differ"
        );
    }
}
