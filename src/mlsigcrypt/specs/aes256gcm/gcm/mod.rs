/// AES-256-GCM authenticated encryption.
///
/// Implements NIST SP 800-38D §7 over AES-256 (FIPS 197).
///
/// # Security contract
///
/// - **Nonce uniqueness**: (key, nonce) pairs must never be reused. Repeating
///   a nonce under the same key exposes the GHASH subkey H and enables universal
///   forgery. This module cannot enforce uniqueness across calls.
///
/// - **Verify-then-decrypt**: `open_in_place` runs GHASH over the ciphertext,
///   compares the computed tag with `ct_eq_16` (constant-time), and only decrypts
///   if the tags match. Plaintext is never exposed from an unauthenticated buffer.
///
/// - **Message length**: GCM is limited to (2^32 − 2) × 16 bytes ≈ 68 GiB per
///   (key, nonce) pair (NIST SP 800-38D §5.2.1.1). `seal_in_place` returns
///   `Err(MessageTooLarge)` if this limit is reached; callers must not retry
///   with the same nonce on error.
///
/// # Usage
///
/// ```rust,ignore
/// use crate::mlsigcrypt::specs::aes256gcm::{Aes256Gcm, AuthError, Nonce};
/// use crate::mlsigcrypt::specs::aes256gcm::aes::Key256;
///
/// let mut key_bytes = [0u8; 32];
/// let key  = Key256::from_mut_bytes(&mut key_bytes);
/// let gcm  = Aes256Gcm::new(key);   // key is zeroized inside new()
/// let nonce = Nonce([0u8; 12]);
///
/// let mut buf = *b"hello";
/// let tag = gcm.seal_in_place(&nonce, b"aad", &mut buf).unwrap();
/// gcm.open_in_place(&nonce, b"aad", &mut buf, &tag).unwrap();
/// ```
pub(crate) mod ctr;
pub(crate) mod ghash;

use crate::constant_time::ct_eq_16;
use crate::mlsigcrypt::specs::aes256gcm::aes::cipher::aes256_encrypt_block;
use crate::mlsigcrypt::specs::aes256gcm::aes::{Key256, KeySchedule};
use crate::mlsigcrypt::specs::aes256gcm::gcm::ctr::CtrState;
use crate::mlsigcrypt::specs::aes256gcm::gcm::ghash::GhashState;
use crate::zeroize::{Zeroize, zeroize_array};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// AES-256-GCM AEAD context.
///
/// Holds the expanded key schedule (240 bytes) and the GHASH subkey H.
/// Both are zeroized on `Drop`. Not `Clone` or `Copy` — key material is
/// single-owner. Not `Debug` — key material must not appear in logs.
pub(crate) struct Aes256Gcm {
    ks: KeySchedule,
    h: [u8; 16], // H = AES_K(0^128): GHASH subkey, derived once at construction
}

/// 96-bit GCM nonce.
///
/// Nonces carry no secret material and are transmitted in the clear alongside
/// ciphertext. Caller is responsible for ensuring (key, nonce) uniqueness
/// across all `seal_in_place` calls under the same key.
pub(crate) struct Nonce(pub(crate) [u8; 12]);

/// Authentication failure from `open_in_place`.
///
/// Opaque by design: distinguishing *why* verification failed — wrong key,
/// wrong nonce, tampered ciphertext, replayed message — would provide oracle
/// information usable in adaptive chosen-ciphertext attacks.
pub(crate) struct AuthError;

/// Returned by `seal_in_place` when the plaintext exceeds the GCM maximum
/// of (2^32 − 2) × 16 bytes ≈ 68 GiB per (key, nonce) pair.
///
/// Callers must discard the (key, nonce) pair on this error — the CTR state
/// is partially advanced and the nonce must not be reused.
pub(crate) struct MessageTooLarge;

// ─────────────────────────────────────────────────────────────────────────────
// Aes256Gcm implementation
// ─────────────────────────────────────────────────────────────────────────────

impl Aes256Gcm {
    /// Construct an AES-256-GCM context from a 256-bit key.
    ///
    /// Expands the key schedule once. The `Key256` is consumed and its destructor
    /// zeroizes the raw key bytes before this function returns.
    ///
    /// H = AES_K(0^128) is derived immediately and stored alongside the schedule.
    pub(crate) fn new(key: Key256) -> Self {
        let ks = KeySchedule::new(&key);
        // key drops here — zeroized by Key256::drop.
        let mut h = [0u8; 16]; // all-zero block → AES_K(0^128)
        aes256_encrypt_block(&ks, &mut h);
        Aes256Gcm { ks, h }
    }

    /// Encrypt `buffer` in-place and return the 16-byte authentication tag.
    ///
    /// `buffer` is replaced with ciphertext on `Ok`. On `Err(MessageTooLarge)`,
    /// the buffer content is unspecified and the nonce must be retired.
    ///
    /// Tag derivation (NIST SP 800-38D §7.1):
    ///   1. EJ0 = AES_K(J0),   J0 = nonce ∥ 0x00000001
    ///   2. CT  = AES_256_CTR starting at J1 applied to `buffer`
    ///   3. S   = GHASH_H(pad(AAD) ∥ pad(CT) ∥ [len(A)₆₄ ∥ len(C)₆₄])
    ///   4. Tag = S ⊕ EJ0
    pub(crate) fn seal_in_place(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; 16], MessageTooLarge> {
        // Step 1: EJ0 = AES_K(J0)
        let mut ej0 = j0_block(nonce);
        aes256_encrypt_block(&self.ks, &mut ej0);

        // Step 2: CTR encrypt plaintext → ciphertext (in-place, starting at J1)
        let mut ctr = CtrState::new(nonce);
        ctr.process(&self.ks, buffer).map_err(|_| {
            // Before returning the error, zero EJ0 — it must not persist.
            zeroize_array(&mut ej0);
            MessageTooLarge
        })?;

        // Step 3: GHASH over (pad(AAD) ∥ pad(CT) ∥ length block)
        let mut s = [0u8; 16];
        ghash_gcm(&self.h, aad, buffer, &mut s);

        // Step 4: Tag = S ⊕ EJ0
        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = s[i] ^ ej0[i];
        }

        // EJ0 is secret (derived from key + nonce) — wipe before returning.
        zeroize_array(&mut ej0);
        zeroize_array(&mut s);

        Ok(tag)
    }

    /// Verify the authentication tag and, on success, decrypt `buffer` in-place.
    ///
    /// Returns `Ok(())` if and only if `tag` authenticates `(nonce, aad, buffer)`.
    /// On `Err(AuthError)`, `buffer` is left unchanged and no plaintext is exposed.
    ///
    /// Verification runs entirely before decryption (verify-then-decrypt).
    /// The tag comparison uses `ct_eq_16` — constant-time, no early exit.
    pub(crate) fn open_in_place(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), AuthError> {
        // Step 1: EJ0 = AES_K(J0)
        let mut ej0 = j0_block(nonce);
        aes256_encrypt_block(&self.ks, &mut ej0);

        // Step 2: GHASH over (pad(AAD) ∥ pad(CT) ∥ length block)
        //         Note: buffer still holds *ciphertext* at this point.
        let mut s = [0u8; 16];
        ghash_gcm(&self.h, aad, buffer, &mut s);

        // Step 3: Compute expected tag = S ⊕ EJ0
        let mut expected = [0u8; 16];
        for i in 0..16 {
            expected[i] = s[i] ^ ej0[i];
        }
        zeroize_array(&mut ej0);
        zeroize_array(&mut s);

        // Step 4: Constant-time tag comparison — no early exit
        if !ct_eq_16(&expected, tag) {
            zeroize_array(&mut expected);
            // Buffer remains as ciphertext — caller cannot observe plaintext.
            return Err(AuthError);
        }
        zeroize_array(&mut expected);

        // Step 5: CTR decrypt — only reached after successful authentication
        let mut ctr = CtrState::new(nonce);
        ctr.process(&self.ks, buffer).map_err(|_| AuthError)?;

        Ok(())
    }
}

impl Zeroize for Aes256Gcm {
    fn zeroize(&mut self) {
        self.ks.zeroize();
        zeroize_array(&mut self.h);
    }
}

impl Drop for Aes256Gcm {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build J0 = nonce ∥ 0x00000001 (the counter block used for tag generation).
///
/// J0 is never used as a CTR keystream block — `CtrState` starts at J1.
#[inline]
fn j0_block(nonce: &Nonce) -> [u8; 16] {
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(&nonce.0);
    j0[15] = 0x01;
    j0
}

/// Compute GHASH_H(pad(aad) ∥ pad(ct) ∥ [len(A)₆₄_bits ∥ len(C)₆₄_bits]).
///
/// Writes the 128-bit GHASH output into `out` and zeroizes the `GhashState`
/// accumulator via `finalize_into`. The `out` buffer contains secret material
/// and must be zeroized by the caller after use.
#[inline]
fn ghash_gcm(h: &[u8; 16], aad: &[u8], ct: &[u8], out: &mut [u8; 16]) {
    let mut gs = GhashState::new(*h);

    // Process additional authenticated data (zero-padded to 128-bit boundary)
    gs.update_padded(aad);

    // Process ciphertext (zero-padded to 128-bit boundary)
    gs.update_padded(ct);

    // Length block: [len(A) in bits as u64 BE ∥ len(C) in bits as u64 BE]
    // Lengths are in bits per NIST SP 800-38D §6.4.
    // Overflow of the byte-to-bit conversion is impossible in practice
    // (the GCM size limit is ≈68 GiB, far below u64::MAX bits).
    let len_a_bits = (aad.len() as u64).wrapping_mul(8);
    let len_c_bits = (ct.len() as u64).wrapping_mul(8);
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&len_a_bits.to_be_bytes());
    len_block[8..16].copy_from_slice(&len_c_bits.to_be_bytes());
    gs.update(&len_block);
    zeroize_array(&mut len_block);

    // finalize_into explicitly zeroizes gs.accum before Drop runs on gs.h
    gs.finalize_into(out);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gcm(key_bytes: [u8; 32]) -> Aes256Gcm {
        Aes256Gcm::new(Key256::from_bytes(key_bytes))
    }

    // ── NIST SP 800-38D Appendix B — AES-256-GCM Test Vectors ────────────────
    //
    // Source: NIST SP 800-38D, Appendix B, Test Cases 13–14 (AES-256).
    // Also published in: NIST CAVP GCM Test Vectors, gcmEncryptExtIV256.rsp.

    /// TC13: K=0^256, IV=0^96, PT=empty, AAD=empty.
    /// Only the tag is produced; ciphertext is empty.
    #[test]
    fn nist_tc13_empty_pt_empty_aad_tag() {
        let gcm = make_gcm([0u8; 32]);
        let nonce = Nonce([0u8; 12]);
        let mut buf: [u8; 0] = [];
        let tag = gcm
            .seal_in_place(&nonce, b"", &mut buf)
            .unwrap_or_else(|_| panic!("TC13 seal must not overflow"));
        assert_eq!(
            tag,
            [
                0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
                0x73, 0x8b
            ],
            "TC13: tag mismatch"
        );
    }

    #[test]
    fn nist_tc13_open_succeeds() {
        let gcm = make_gcm([0u8; 32]);
        let nonce = Nonce([0u8; 12]);
        let tag = [
            0x53u8, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
            0x73, 0x8b,
        ];
        let mut buf: [u8; 0] = [];
        gcm.open_in_place(&nonce, b"", &mut buf, &tag)
            .unwrap_or_else(|_| panic!("TC13 open must verify"));
    }

    /// TC14: K=0^256, IV=0^96, PT=0^128 (16 zero bytes), AAD=empty.
    #[test]
    fn nist_tc14_zero_pt_ciphertext() {
        let gcm = make_gcm([0u8; 32]);
        let nonce = Nonce([0u8; 12]);
        let mut buf = [0u8; 16];
        gcm.seal_in_place(&nonce, b"", &mut buf)
            .unwrap_or_else(|_| panic!("TC14 seal"));
        assert_eq!(
            buf,
            [
                0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
                0x9d, 0x18
            ],
            "TC14: ciphertext mismatch"
        );
    }

    #[test]
    fn nist_tc14_zero_pt_tag() {
        let gcm = make_gcm([0u8; 32]);
        let nonce = Nonce([0u8; 12]);
        let mut buf = [0u8; 16];
        let tag = gcm
            .seal_in_place(&nonce, b"", &mut buf)
            .unwrap_or_else(|_| panic!("TC14 seal"));
        assert_eq!(
            tag,
            [
                0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a,
                0xb9, 0x19
            ],
            "TC14: tag mismatch"
        );
    }

    #[test]
    fn nist_tc14_open_roundtrip() {
        let gcm = make_gcm([0u8; 32]);
        let nonce = Nonce([0u8; 12]);
        let pt = [0u8; 16];
        let mut buf = pt;

        let tag = gcm
            .seal_in_place(&nonce, b"", &mut buf)
            .unwrap_or_else(|_| panic!("seal"));
        gcm.open_in_place(&nonce, b"", &mut buf, &tag)
            .unwrap_or_else(|_| panic!("open"));
        assert_eq!(buf, pt, "decrypted plaintext must match original");
    }

    // ── Seal / Open roundtrips ────────────────────────────────────────────────

    #[test]
    fn roundtrip_arbitrary_plaintext() {
        let gcm = make_gcm([0x42u8; 32]);
        let nonce = Nonce([0x11u8; 12]);
        let pt = b"the quick brown fox jumps over the lazy dog";
        let mut buf = *pt;

        let tag = gcm
            .seal_in_place(&nonce, b"header", &mut buf)
            .unwrap_or_else(|_| panic!("seal"));
        gcm.open_in_place(&nonce, b"header", &mut buf, &tag)
            .unwrap_or_else(|_| panic!("open"));
        assert_eq!(&buf, pt);
    }

    #[test]
    fn roundtrip_single_byte() {
        let gcm = make_gcm([0xAAu8; 32]);
        let nonce = Nonce([0xBBu8; 12]);
        let mut buf = [0x42u8];
        let tag = gcm
            .seal_in_place(&nonce, b"", &mut buf)
            .unwrap_or_else(|_| panic!("seal"));
        gcm.open_in_place(&nonce, b"", &mut buf, &tag)
            .unwrap_or_else(|_| panic!("open"));
        assert_eq!(buf, [0x42u8]);
    }

    #[test]
    fn roundtrip_multi_block_with_aad() {
        let gcm = make_gcm([0xDEu8; 32]);
        let nonce = Nonce([0xADu8; 12]);
        let aad = b"authenticated but not encrypted";
        let pt = [0xBEu8; 64];
        let mut buf = pt;

        let tag = gcm
            .seal_in_place(&nonce, aad, &mut buf)
            .unwrap_or_else(|_| panic!("seal"));
        gcm.open_in_place(&nonce, aad, &mut buf, &tag)
            .unwrap_or_else(|_| panic!("open"));
        assert_eq!(buf, pt);
    }

    #[test]
    fn empty_plaintext_with_aad_produces_tag() {
        let gcm = make_gcm([0x01u8; 32]);
        let nonce = Nonce([0x02u8; 12]);
        let mut buf: [u8; 0] = [];
        let tag = gcm
            .seal_in_place(&nonce, b"some aad", &mut buf)
            .unwrap_or_else(|_| panic!("seal"));
        gcm.open_in_place(&nonce, b"some aad", &mut buf, &tag)
            .unwrap_or_else(|_| panic!("open"));
    }

    // ── Authentication enforcement ────────────────────────────────────────────

    #[test]
    fn tampered_ciphertext_rejected() {
        let gcm = make_gcm([0u8; 32]);
        let nonce = Nonce([0u8; 12]);
        let pt = [0xABu8; 16];
        let mut buf = pt;

        let tag = gcm
            .seal_in_place(&nonce, b"", &mut buf)
            .unwrap_or_else(|_| panic!("seal"));
        buf[0] ^= 0xFF; // flip a bit in the ciphertext
        assert!(
            gcm.open_in_place(&nonce, b"", &mut buf, &tag).is_err(),
            "tampered ciphertext must be rejected"
        );
    }

    #[test]
    fn tampered_tag_rejected() {
        let gcm = make_gcm([0u8; 32]);
        let nonce = Nonce([0u8; 12]);
        let mut buf = [0xCDu8; 16];
        let mut tag = gcm
            .seal_in_place(&nonce, b"", &mut buf)
            .unwrap_or_else(|_| panic!("seal"));
        tag[7] ^= 0x01;
        assert!(
            gcm.open_in_place(&nonce, b"", &mut buf, &tag).is_err(),
            "tampered tag must be rejected"
        );
    }

    #[test]
    fn tampered_aad_rejected() {
        let gcm = make_gcm([0u8; 32]);
        let nonce = Nonce([0u8; 12]);
        let mut buf = [0u8; 16];
        let tag = gcm
            .seal_in_place(&nonce, b"correct aad", &mut buf)
            .unwrap_or_else(|_| panic!("seal"));
        assert!(
            gcm.open_in_place(&nonce, b"wrong aad", &mut buf, &tag)
                .is_err(),
            "tampered AAD must be rejected"
        );
    }

    #[test]
    fn wrong_key_rejected() {
        let gcm_a = make_gcm([0x00u8; 32]);
        let gcm_b = make_gcm([0xFFu8; 32]);
        let nonce = Nonce([0u8; 12]);
        let mut buf = [0u8; 16];
        let tag = gcm_a
            .seal_in_place(&nonce, b"", &mut buf)
            .unwrap_or_else(|_| panic!("seal"));
        assert!(
            gcm_b.open_in_place(&nonce, b"", &mut buf, &tag).is_err(),
            "wrong key must be rejected"
        );
    }

    #[test]
    fn wrong_nonce_rejected() {
        let gcm = make_gcm([0u8; 32]);
        let n_enc = Nonce([0u8; 12]);
        let n_dec = Nonce([1u8; 12]);
        let mut buf = [0u8; 16];
        let tag = gcm
            .seal_in_place(&n_enc, b"", &mut buf)
            .unwrap_or_else(|_| panic!("seal"));
        assert!(
            gcm.open_in_place(&n_dec, b"", &mut buf, &tag).is_err(),
            "wrong nonce must be rejected"
        );
    }

    #[test]
    fn all_zero_tag_forgery_rejected() {
        let gcm = make_gcm([0u8; 32]);
        let nonce = Nonce([0u8; 12]);
        let mut buf = [0u8; 16];
        let zero_tag = [0u8; 16];
        assert!(
            gcm.open_in_place(&nonce, b"", &mut buf, &zero_tag).is_err(),
            "all-zero tag forgery must be rejected"
        );
    }

    #[test]
    fn open_failure_leaves_buffer_as_ciphertext() {
        // The buffer must not be modified when authentication fails
        let gcm = make_gcm([0u8; 32]);
        let nonce = Nonce([0u8; 12]);
        let pt = [0xABu8; 16];
        let mut buf = pt;
        let mut tag = gcm
            .seal_in_place(&nonce, b"", &mut buf)
            .unwrap_or_else(|_| panic!("seal"));
        let ciphertext = buf; // save the ciphertext

        tag[0] ^= 0xFF; // corrupt the tag
        let result = gcm.open_in_place(&nonce, b"", &mut buf, &tag);
        assert!(result.is_err());
        assert_eq!(buf, ciphertext, "buffer must be unchanged on auth failure");
    }

    // ── AAD affects tag, not ciphertext ───────────────────────────────────────

    #[test]
    fn aad_changes_tag_not_ciphertext() {
        let gcm = make_gcm([0u8; 32]);
        let nonce = Nonce([0u8; 12]);
        let pt = [0xFFu8; 16];

        let mut buf_a = pt;
        let mut buf_b = pt;
        let tag_a = gcm
            .seal_in_place(&nonce, b"aad_a", &mut buf_a)
            .unwrap_or_else(|_| panic!("seal a"));
        let tag_b = gcm
            .seal_in_place(&nonce, b"aad_b", &mut buf_b)
            .unwrap_or_else(|_| panic!("seal b"));

        // Ciphertext must be identical (AAD doesn't affect CTR keystream)
        assert_eq!(buf_a, buf_b, "AAD must not alter ciphertext");
        // Tags must differ (AAD is authenticated)
        assert_ne!(tag_a, tag_b, "Different AAD must produce different tags");
    }

    // ── Different keys / nonces produce different ciphertexts ─────────────────

    #[test]
    fn different_keys_different_ciphertext() {
        let nonce = Nonce([0u8; 12]);
        let pt = [0u8; 16];

        let mut buf_a = pt;
        let mut buf_b = pt;
        make_gcm([0x00u8; 32])
            .seal_in_place(&nonce, b"", &mut buf_a)
            .unwrap_or_else(|_| panic!("seal a"));
        make_gcm([0xFFu8; 32])
            .seal_in_place(&nonce, b"", &mut buf_b)
            .unwrap_or_else(|_| panic!("seal b"));
        assert_ne!(buf_a, buf_b);
    }

    #[test]
    fn different_nonces_different_ciphertext() {
        let gcm = make_gcm([0u8; 32]);
        let pt = [0u8; 16];

        let mut buf_a = pt;
        let mut buf_b = pt;
        gcm.seal_in_place(&Nonce([0u8; 12]), b"", &mut buf_a)
            .unwrap_or_else(|_| panic!("seal a"));
        gcm.seal_in_place(&Nonce([1u8; 12]), b"", &mut buf_b)
            .unwrap_or_else(|_| panic!("seal b"));
        assert_ne!(buf_a, buf_b);
    }

    // ── Zeroization ───────────────────────────────────────────────────────────

    #[test]
    fn aes256gcm_zeroize_clears_h_and_schedule() {
        let mut gcm = make_gcm([0xABu8; 32]);
        gcm.zeroize();
        assert_eq!(gcm.h, [0u8; 16], "H must be zeroed");
        // KeySchedule::zeroize is tested in key_schedule.rs;
        // here we confirm it runs without panic
    }
}
