/// AES-256-CTR keystream generator for GCM.
///
/// Counter layout (96-bit nonce || 32-bit big-endian counter):
///
///   ┌────────────────────────────────┬───────────────────┐
///   │       nonce (12 bytes)         │  counter (4 bytes)│
///   └────────────────────────────────┴───────────────────┘
///
/// J0 = nonce || 0x00000001  — encrypted to produce the authentication tag mask.
/// J1 = nonce || 0x00000002  — first keystream block (first plaintext block).
/// Jn = nonce || (n + 1)     — n-th keystream block.
///
/// This module manages keystream from J1 onwards. J0 is handled by `gcm::seal/open`
/// directly (encrypted once for the tag mask, never used for keystream).
///
/// NIST SP 800-38D §5.2.1.1 limits GCM to (2^32 − 2) × 128-bit blocks per
/// (key, nonce) pair — approximately 68 GiB. Counter overflow is enforced:
/// `process` returns `Err(CtrOverflow)` if the caller attempts to exceed this
/// limit, preventing silent keystream reuse.
use crate::mlsigcrypt::specs::aes256gcm::aes::key_schedule::KeySchedule;
use crate::mlsigcrypt::specs::aes256gcm::arch;
use crate::mlsigcrypt::specs::aes256gcm::gcm::Nonce;
use crate::zeroize::{Zeroize, zeroize_array};

// ─────────────────────────────────────────────────────────────────────────────
// CtrOverflow
// ─────────────────────────────────────────────────────────────────────────────

/// Returned by `CtrState::process` when the message exceeds the GCM maximum
/// of (2^32 − 2) × 16 bytes per (key, nonce) pair.
///
/// This is an opaque error — callers must treat it as a hard encryption failure
/// and must not retry with the same nonce.
pub(crate) struct CtrOverflow;

// ─────────────────────────────────────────────────────────────────────────────
// CtrState
// ─────────────────────────────────────────────────────────────────────────────

/// CTR mode state.
///
/// Holds the current counter block and one buffered keystream block.
/// Zeroized on `Drop`.
pub(crate) struct CtrState {
    counter: [u8; 16],   // current counter block (nonce || be32 counter)
    keystream: [u8; 16], // AES(counter) — buffered keystream
    pos: usize,          // next byte to consume in keystream; 16 = buffer exhausted
    exhausted: bool,     // true once counter value 0xFFFFFFFF was consumed
}

impl CtrState {
    /// Initialise CTR state at J1 = nonce || 0x00000002.
    ///
    /// J0 (counter = 1) is reserved for tag generation and never used for
    /// keystream — that's the caller's contract, enforced by starting here.
    pub(crate) fn new(nonce: &Nonce) -> Self {
        let mut counter = [0u8; 16];
        counter[..12].copy_from_slice(&nonce.0);
        // Counter field starts at 2 (J1): big-endian 0x00000002
        counter[15] = 2;
        CtrState {
            counter,
            keystream: [0u8; 16],
            pos: 16, // force refill on first byte consumed
            exhausted: false,
        }
    }

    /// XOR `data` with the keystream in-place (encrypt or decrypt — identical).
    ///
    /// Returns `Err(CtrOverflow)` if the message would exceed (2^32 − 2) × 16
    /// bytes, the maximum permitted by NIST SP 800-38D §5.2.1.1. The buffer
    /// contents are undefined on error; callers must discard the entire message.
    pub(crate) fn process(&mut self, ks: &KeySchedule, data: &mut [u8]) -> Result<(), CtrOverflow> {
        for byte in data.iter_mut() {
            if self.pos == 16 {
                self.refill(ks)?;
            }
            *byte ^= self.keystream[self.pos];
            self.pos += 1;
        }
        Ok(())
    }

    /// Encrypt the current counter block into `keystream`, then advance counter.
    ///
    /// 0xFFFFFFFF is a legal final block value per SP 800-38D. After that block
    /// is consumed, any further refill attempt returns `Err(CtrOverflow)`.
    #[inline]
    fn refill(&mut self, ks: &KeySchedule) -> Result<(), CtrOverflow> {
        if self.exhausted {
            return Err(CtrOverflow);
        }

        // Copy counter into keystream buffer, then encrypt in-place.
        // This preserves the counter value for the increment step.
        self.keystream = self.counter;
        arch::aes256_encrypt(&mut self.keystream, ks.round_keys());

        let c = u32::from_be_bytes([
            self.counter[12],
            self.counter[13],
            self.counter[14],
            self.counter[15],
        ]);
        if c == u32::MAX {
            // Last legal block reached. Mark exhausted so a next refill fails.
            self.exhausted = true;
        } else {
            self.increment_counter()?;
        }

        self.pos = 0;
        Ok(())
    }

    /// Increment the 32-bit big-endian counter (bytes 12–15).
    ///
    /// Returns `Err(CtrOverflow)` if the counter is already at 0xFFFFFFFF.
    /// Incrementing further would wrap to 0x00000000, and eventually to
    /// 0x00000001 (= J0), re-using the tag-generation keystream for plaintext.
    /// Per NIST SP 800-38D §5.2.1.1, the maximum counter value is 2^32 − 2,
    /// meaning counter values 2 through 0xFFFFFFFF (inclusive) are valid.
    /// Counter = 0xFFFFFFFF represents the 2^32 − 2'nd block — the last legal
    /// block. Any attempt to produce a further block is a hard error.
    #[inline]
    fn increment_counter(&mut self) -> Result<(), CtrOverflow> {
        let c = u32::from_be_bytes([
            self.counter[12],
            self.counter[13],
            self.counter[14],
            self.counter[15],
        ]);
        if c == u32::MAX {
            // Counter has reached 0xFFFFFFFF — incrementing would wrap to 0.
            // This violates the GCM length constraint; refuse unconditionally.
            return Err(CtrOverflow);
        }
        let next = c + 1; // no wrapping needed: guarded above
        self.counter[12..16].copy_from_slice(&next.to_be_bytes());
        Ok(())
    }
}

impl Zeroize for CtrState {
    fn zeroize(&mut self) {
        zeroize_array(&mut self.counter);
        zeroize_array(&mut self.keystream);
        self.pos = 0;
        self.exhausted = false;
    }
}

impl Drop for CtrState {
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
    use crate::mlsigcrypt::specs::aes256gcm::aes::key_schedule::{Key256, KeySchedule};

    fn make_ks(key: [u8; 32]) -> KeySchedule {
        KeySchedule::new(&Key256::from_bytes(key))
    }

    fn make_nonce(bytes: [u8; 12]) -> Nonce {
        Nonce(bytes)
    }

    // ── Counter initialisation ────────────────────────────────────────────────

    #[test]
    fn counter_starts_at_j1() {
        let nonce = make_nonce([0xAAu8; 12]);
        let ctr = CtrState::new(&nonce);
        let expected = {
            let mut b = [0u8; 16];
            b[..12].copy_from_slice(&[0xAAu8; 12]);
            b[15] = 2;
            b
        };
        assert_eq!(ctr.counter, expected);
    }

    #[test]
    fn counter_pos_starts_at_16_forces_refill() {
        let ctr = CtrState::new(&make_nonce([0u8; 12]));
        assert_eq!(ctr.pos, 16);
    }

    // ── Counter increment ─────────────────────────────────────────────────────

    #[test]
    fn counter_increment_basic() {
        let nonce = make_nonce([0u8; 12]);
        let mut ctr = CtrState::new(&nonce);
        let ks = make_ks([0u8; 32]);
        ctr.refill(&ks)
            .unwrap_or_else(|_| panic!("refill must not overflow at J1"));
        assert_eq!(ctr.counter[15], 3);
    }

    #[test]
    fn counter_increment_multi_byte_carry() {
        // 0x000000FF + 1 = 0x00000100
        let nonce = make_nonce([0u8; 12]);
        let mut ctr = CtrState::new(&nonce);
        ctr.counter[12] = 0x00;
        ctr.counter[13] = 0x00;
        ctr.counter[14] = 0x00;
        ctr.counter[15] = 0xFF;
        ctr.increment_counter()
            .unwrap_or_else(|_| panic!("0xFF + 1 must not overflow"));
        assert_eq!(&ctr.counter[12..16], &[0x00, 0x00, 0x01, 0x00]);
    }

    // ── Counter overflow enforcement (NIST SP 800-38D §5.2.1.1) ──────────────

    #[test]
    fn counter_overflow_at_max_returns_error() {
        let nonce = make_nonce([0u8; 12]);
        let mut ctr = CtrState::new(&nonce);
        // Force counter to 0xFFFFFFFF — the last legal value
        ctr.counter[12] = 0xFF;
        ctr.counter[13] = 0xFF;
        ctr.counter[14] = 0xFF;
        ctr.counter[15] = 0xFF;
        // Incrementing further must be refused
        assert!(
            ctr.increment_counter().is_err(),
            "must return CtrOverflow at u32::MAX"
        );
    }

    #[test]
    fn process_overflow_propagates_as_error() {
        let ks = make_ks([0u8; 32]);
        let nonce = make_nonce([0u8; 12]);
        let mut ctr = CtrState::new(&nonce);
        // Set counter to 0xFFFFFFFF (last legal block value).
        ctr.counter[12] = 0xFF;
        ctr.counter[13] = 0xFF;
        ctr.counter[14] = 0xFF;
        ctr.counter[15] = 0xFF;
        // pos = 16 forces an immediate refill on process().
        // 17 bytes requires two keystream blocks; the second must overflow.
        ctr.pos = 16;
        let mut buf = [0u8; 17];
        assert!(
            ctr.process(&ks, &mut buf).is_err(),
            "process must propagate CtrOverflow"
        );
    }

    #[test]
    fn counter_penultimate_value_succeeds() {
        // 0xFFFFFFFE + 1 = 0xFFFFFFFF — still within the legal range
        let nonce = make_nonce([0u8; 12]);
        let mut ctr = CtrState::new(&nonce);
        ctr.counter[12] = 0xFF;
        ctr.counter[13] = 0xFF;
        ctr.counter[14] = 0xFF;
        ctr.counter[15] = 0xFE;
        assert!(
            ctr.increment_counter().is_ok(),
            "0xFFFFFFFE must be incrementable"
        );
        assert_eq!(&ctr.counter[12..16], &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn process_at_counter_max_allows_one_final_block() {
        let ks = make_ks([0u8; 32]);
        let nonce = make_nonce([0u8; 12]);
        let mut ctr = CtrState::new(&nonce);

        ctr.counter[12] = 0xFF;
        ctr.counter[13] = 0xFF;
        ctr.counter[14] = 0xFF;
        ctr.counter[15] = 0xFF;
        ctr.pos = 16;

        let mut one_block = [0u8; 16];
        assert!(
            ctr.process(&ks, &mut one_block).is_ok(),
            "last legal block must be accepted"
        );

        let mut next_byte = [0u8; 1];
        assert!(
            ctr.process(&ks, &mut next_byte).is_err(),
            "one byte past limit must fail"
        );
    }

    // ── XOR idempotency (encrypt then decrypt = identity) ────────────────────

    #[test]
    fn encrypt_then_decrypt_is_identity() {
        let ks = make_ks([0u8; 32]);
        let nonce = make_nonce([0u8; 12]);
        let plaintext = b"Hello, AES-CTR!."; // 16 bytes

        let mut buf = *plaintext;
        CtrState::new(&nonce)
            .process(&ks, &mut buf)
            .unwrap_or_else(|_| panic!("encrypt"));
        assert_ne!(&buf, plaintext, "XOR did nothing");

        CtrState::new(&nonce)
            .process(&ks, &mut buf)
            .unwrap_or_else(|_| panic!("decrypt"));
        assert_eq!(&buf, plaintext, "Decryption failed");
    }

    #[test]
    fn encrypt_arbitrary_length() {
        let ks = make_ks([0x42u8; 32]);
        let nonce = make_nonce([0x11u8; 12]);
        let mut data = [0u8; 100]; // not a multiple of 16
        let original = data;

        CtrState::new(&nonce)
            .process(&ks, &mut data)
            .unwrap_or_else(|_| panic!("encrypt"));
        assert_ne!(data, original);

        CtrState::new(&nonce)
            .process(&ks, &mut data)
            .unwrap_or_else(|_| panic!("decrypt"));
        assert_eq!(data, original);
    }

    #[test]
    fn encrypt_empty_slice_is_noop() {
        let ks = make_ks([0u8; 32]);
        let nonce = make_nonce([0u8; 12]);
        let mut ctr = CtrState::new(&nonce);
        let mut empty: [u8; 0] = [];
        ctr.process(&ks, &mut empty)
            .unwrap_or_else(|_| panic!("empty slice must not error"));
    }

    #[test]
    fn different_nonces_produce_different_keystreams() {
        let ks = make_ks([0u8; 32]);
        let n1 = make_nonce([0u8; 12]);
        let n2 = make_nonce([1u8; 12]);

        let mut buf1 = [0u8; 16];
        let mut buf2 = [0u8; 16];
        CtrState::new(&n1)
            .process(&ks, &mut buf1)
            .unwrap_or_else(|_| panic!("n1"));
        CtrState::new(&n2)
            .process(&ks, &mut buf2)
            .unwrap_or_else(|_| panic!("n2"));
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn different_keys_produce_different_keystreams() {
        let n = make_nonce([0u8; 12]);
        let ks1 = make_ks([0u8; 32]);
        let ks2 = make_ks([1u8; 32]);

        let mut buf1 = [0u8; 16];
        let mut buf2 = [0u8; 16];
        CtrState::new(&n)
            .process(&ks1, &mut buf1)
            .unwrap_or_else(|_| panic!("ks1"));
        CtrState::new(&n)
            .process(&ks2, &mut buf2)
            .unwrap_or_else(|_| panic!("ks2"));
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn keystream_is_deterministic() {
        let ks = make_ks([0xDEu8; 32]);
        let n = make_nonce([0xADu8; 12]);

        let mut buf_a = [0u8; 48];
        let mut buf_b = [0u8; 48];
        CtrState::new(&n)
            .process(&ks, &mut buf_a)
            .unwrap_or_else(|_| panic!("a"));
        CtrState::new(&n)
            .process(&ks, &mut buf_b)
            .unwrap_or_else(|_| panic!("b"));
        assert_eq!(buf_a, buf_b);
    }

    // ── Keystream correctness vs manual computation ───────────────────────────

    #[test]
    fn first_block_matches_aes_of_j1() {
        let key = [0u8; 32];
        let nonce_bytes = [0u8; 12];
        let ks = make_ks(key);
        let nonce = make_nonce(nonce_bytes);

        // Manual: compute AES(K, J1) where J1 = nonce || 0x00000002
        let mut j1 = [0u8; 16];
        j1[..12].copy_from_slice(&nonce_bytes);
        j1[15] = 2;
        let mut expected_ks = j1;
        arch::aes256_encrypt(&mut expected_ks, ks.round_keys());

        // XOR all-zero plaintext with CTR keystream gives the raw keystream
        let mut buf = [0u8; 16];
        CtrState::new(&nonce)
            .process(&ks, &mut buf)
            .unwrap_or_else(|_| panic!("first block"));
        assert_eq!(buf, expected_ks);
    }

    // ── Zeroization ──────────────────────────────────────────────────────────

    #[test]
    fn ctr_zeroize_clears_counter_and_keystream() {
        let ks = make_ks([0u8; 32]);
        let nonce = make_nonce([0xFFu8; 12]);
        let mut ctr = CtrState::new(&nonce);
        let mut buf = [1u8; 16];
        ctr.process(&ks, &mut buf)
            .unwrap_or_else(|_| panic!("process"));
        ctr.exhausted = true;
        ctr.zeroize();
        assert_eq!(ctr.counter, [0u8; 16]);
        assert_eq!(ctr.keystream, [0u8; 16]);
        assert_eq!(ctr.pos, 0);
        assert!(!ctr.exhausted);
    }
}
