/// AES-256 Key Schedule.
///
/// `Key256`      — holds the 32-byte master key.
/// `KeySchedule` — holds 15 × 128-bit round keys derived from `Key256`.
///
/// Both types:
///   - Have no `Copy`, no `Clone`, no `Debug`
///   - Zeroize all bytes on `Drop`
///   - Expose secret bytes only through the minimum necessary API surface
use crate::algos::aes256gcm::arch;
use crate::zeroize::{Zeroize, zeroize_array, zeroize_array2d};

// ─────────────────────────────────────────────────────────────────────────────
// Key256
// ─────────────────────────────────────────────────────────────────────────────

/// A 256-bit (32-byte) AES master key.
///
/// Construction copies from caller-owned bytes and immediately zeroizes the
/// caller buffer to minimize key duplication lifetime.
pub(crate) struct Key256 {
    pub(crate) bytes: [u8; 32],
}

impl Key256 {
    /// Construct from a mutable 32-byte key buffer.
    ///
    /// The source buffer is wiped before returning.
    pub(crate) fn from_mut_bytes(bytes: &mut [u8; 32]) -> Self {
        let mut owned = [0u8; 32];
        owned.copy_from_slice(bytes);
        zeroize_array(bytes);
        Key256 { bytes: owned }
    }

    #[inline(always)]
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Test-only convenience constructor. In production code, use
    /// `from_mut_bytes` so the source buffer is wiped immediately.
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Key256 { bytes }
    }
}

impl Zeroize for Key256 {
    fn zeroize(&mut self) {
        zeroize_array(&mut self.bytes);
    }
}

impl Drop for Key256 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KeySchedule
// ─────────────────────────────────────────────────────────────────────────────

/// AES-256 expanded key schedule: 15 × 128-bit round keys (240 bytes, stack-only).
pub(crate) struct KeySchedule {
    pub(crate) round_keys: [[u8; 16]; 15],
}

impl KeySchedule {
    /// Derive a key schedule from a 256-bit key.
    /// Dispatches to AES-NI or software key expansion via `arch`.
    pub(crate) fn new(key: &Key256) -> Self {
        let mut ks = KeySchedule {
            round_keys: [[0u8; 16]; 15],
        };
        arch::expand_key_256(&key.bytes, &mut ks.round_keys);
        ks
    }

    #[inline(always)]
    pub(crate) fn round_keys(&self) -> &[[u8; 16]; 15] {
        &self.round_keys
    }
}

impl Zeroize for KeySchedule {
    fn zeroize(&mut self) {
        zeroize_array2d(&mut self.round_keys);
    }
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zeroize::Zeroize;

    // ── Key256 ───────────────────────────────────────────────────────────────

    #[test]
    fn key256_from_bytes_stores_correctly() {
        let raw = core::array::from_fn::<u8, 32, _>(|i| i as u8);
        let key = Key256::from_bytes(raw);
        assert_eq!(key.as_bytes(), &raw);
    }

    #[test]
    fn key256_from_mut_bytes_wipes_source() {
        let mut raw = core::array::from_fn::<u8, 32, _>(|i| (255 - i) as u8);
        let expected = raw;
        let key = Key256::from_mut_bytes(&mut raw);
        assert_eq!(key.as_bytes(), &expected);
        assert_eq!(raw, [0u8; 32]);
    }

    #[test]
    fn key256_zeroize_clears_all_bytes() {
        let mut key = Key256::from_bytes([0xFFu8; 32]);
        key.zeroize();
        assert_eq!(key.bytes, [0u8; 32]);
    }

    #[test]
    fn key256_as_bytes_returns_reference() {
        let raw = [0xABu8; 32];
        let key = Key256::from_bytes(raw);
        assert_eq!(key.as_bytes().len(), 32);
        assert_eq!(key.as_bytes()[0], 0xAB);
        assert_eq!(key.as_bytes()[31], 0xAB);
    }

    // ── KeySchedule (NIST FIPS 197 Appendix A.3) ─────────────────────────────

    #[test]
    fn key_schedule_rk0_and_rk1_are_raw_key_halves() {
        let key = Key256::from_bytes([
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ]);
        let ks = KeySchedule::new(&key);
        assert_eq!(
            ks.round_keys[0],
            [
                0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
                0x77, 0x81
            ]
        );
        assert_eq!(
            ks.round_keys[1],
            [
                0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
                0xdf, 0xf4
            ]
        );
    }

    #[test]
    fn key_schedule_rk2_nist_fips197_a3() {
        let key = Key256::from_bytes([
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ]);
        let ks = KeySchedule::new(&key);
        assert_eq!(
            ks.round_keys[2],
            [
                0x9b, 0xa3, 0x54, 0x11, 0x8e, 0x69, 0x25, 0xaf, 0xa5, 0x1a, 0x8b, 0x5f, 0x20, 0x67,
                0xfc, 0xde
            ]
        );
    }

    #[test]
    fn key_schedule_zero_key() {
        let key = Key256::from_bytes([0u8; 32]);
        let ks = KeySchedule::new(&key);
        // Round keys 0 and 1 are the raw key halves (both zero)
        assert_eq!(ks.round_keys[0], [0u8; 16]);
        assert_eq!(ks.round_keys[1], [0u8; 16]);
        // Round key 2 must be non-zero (SubBytes of zero is 0x63)
        assert_ne!(ks.round_keys[2], [0u8; 16]);
    }

    #[test]
    fn key_schedule_zeroize_clears_all_round_keys() {
        let key = Key256::from_bytes([0xAAu8; 32]);
        let mut ks = KeySchedule::new(&key);
        ks.zeroize();
        assert_eq!(ks.round_keys, [[0u8; 16]; 15]);
    }

    #[test]
    fn key_schedule_round_keys_accessor() {
        let key = Key256::from_bytes([0x42u8; 32]);
        let ks = KeySchedule::new(&key);
        let rk = ks.round_keys();
        assert_eq!(rk.len(), 15);
    }

    #[test]
    fn two_keys_same_bytes_same_schedule() {
        let raw = [0x55u8; 32];
        let ks_a = KeySchedule::new(&Key256::from_bytes(raw));
        let ks_b = KeySchedule::new(&Key256::from_bytes(raw));
        assert_eq!(ks_a.round_keys, ks_b.round_keys);
    }

    #[test]
    fn two_different_keys_different_schedules() {
        let ks_a = KeySchedule::new(&Key256::from_bytes([0x00u8; 32]));
        let ks_b = KeySchedule::new(&Key256::from_bytes([0xFFu8; 32]));
        assert_ne!(ks_a.round_keys, ks_b.round_keys);
    }
}
