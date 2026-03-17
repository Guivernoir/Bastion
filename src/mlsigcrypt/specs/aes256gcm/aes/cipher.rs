/// AES-256 block encryption.
///
/// GCM requires block *encryption* only — never decryption.
/// CTR mode is symmetric, GHASH derives H from `AES_K(0^128)`.
/// No block decrypt = no inverse S-box, no InvMixColumns, no ~300 dead lines.
use crate::mlsigcrypt::specs::aes256gcm::aes::key_schedule::KeySchedule;
use crate::mlsigcrypt::specs::aes256gcm::arch;

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Encrypt a single 128-bit block in-place.
/// Dispatches to AES-NI or software via `arch`.
#[inline(always)]
pub(crate) fn aes256_encrypt_block(ks: &KeySchedule, block: &mut [u8; 16]) {
    arch::aes256_encrypt(block, ks.round_keys());
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlsigcrypt::specs::aes256gcm::aes::key_schedule::{Key256, KeySchedule};

    fn encrypt(key: [u8; 32], mut block: [u8; 16]) -> [u8; 16] {
        let ks = KeySchedule::new(&Key256::from_bytes(key));
        aes256_encrypt_block(&ks, &mut block);
        block
    }

    // ── NIST vectors ─────────────────────────────────────────────────────────

    /// NIST FIPS 197 Appendix B
    #[test]
    fn fips197_appendix_b() {
        let key = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let ct = encrypt(
            key,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
        );
        assert_eq!(
            ct,
            [
                0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
                0x60, 0x89
            ]
        );
    }

    /// NIST SP 800-38A AES-256-ECB vector 1
    #[test]
    fn sp800_38a_vector_1() {
        let key = [
            0x60u8, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let ct = encrypt(
            key,
            [
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                0x17, 0x2a,
            ],
        );
        assert_eq!(
            ct,
            [
                0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1,
                0x81, 0xf8
            ]
        );
    }

    /// AES-256(0^32, 0^128) — GHASH subkey H when K = 0.
    /// Verified against OpenSSL and NIST AES ECB Known Answer Tests.
    #[test]
    fn zero_key_zero_block_is_h_for_gcm() {
        let ct = encrypt([0u8; 32], [0u8; 16]);
        assert_eq!(
            ct,
            [
                0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84,
                0x20, 0x87
            ]
        );
    }

    // ── Correctness properties ────────────────────────────────────────────────

    #[test]
    fn encryption_is_deterministic() {
        let key = [0x42u8; 32];
        let pt = [0xABu8; 16];
        assert_eq!(encrypt(key, pt), encrypt(key, pt));
    }

    #[test]
    fn different_keys_produce_different_ciphertext() {
        let pt = [0x00u8; 16];
        assert_ne!(encrypt([0x00u8; 32], pt), encrypt([0xFFu8; 32], pt));
    }

    #[test]
    fn different_plaintexts_produce_different_ciphertext() {
        let key = [0x00u8; 32];
        assert_ne!(encrypt(key, [0x00u8; 16]), encrypt(key, [0x01u8; 16]));
    }

    #[test]
    fn full_block_range_of_values() {
        // Encrypting the block [0x00..0xFF] (each byte = its own index)
        let key = [0u8; 32];
        let pt: [u8; 16] = core::array::from_fn(|i| i as u8);
        let ct = encrypt(key, pt);
        // Must not be the identity function
        assert_ne!(ct, pt);
        // Must be deterministic
        assert_eq!(ct, encrypt(key, pt));
    }

    #[test]
    fn avalanche_one_bit_change() {
        let key = [0u8; 32];
        let pt_a = [0u8; 16];
        let mut pt_b = [0u8; 16];
        pt_b[0] ^= 0x01; // flip exactly one bit
        let ct_a = encrypt(key, pt_a);
        let ct_b = encrypt(key, pt_b);
        let diff: u32 = ct_a
            .iter()
            .zip(ct_b.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();
        // ~64/128 bits expected; accept anything in [40, 88]
        assert!(
            diff >= 40 && diff <= 88,
            "Avalanche: {diff}/128 bits differ"
        );
    }

    #[test]
    fn avalanche_key_change() {
        let pt = [0u8; 16];
        let key_a = [0u8; 32];
        let mut key_b = [0u8; 32];
        key_b[16] ^= 0x01;
        let ct_a = encrypt(key_a, pt);
        let ct_b = encrypt(key_b, pt);
        let diff: u32 = ct_a
            .iter()
            .zip(ct_b.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();
        assert!(
            diff >= 40 && diff <= 88,
            "Key avalanche: {diff}/128 bits differ"
        );
    }
}
