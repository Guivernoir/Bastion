/// HKDF-SHA3-512 (RFC 5869 with SHA3-512 as the underlying hash).
///
/// SHA3-512 parameters:
///   Rate (sponge block size):  72 bytes
///   Output (HashLen):          64 bytes
///
/// HMAC-SHA3-512(K, M) = SHA3-512((K ⊕ opad) ∥ SHA3-512((K ⊕ ipad) ∥ M))
///
/// HKDF-Extract(salt=∅, IKM):
///   Per RFC 5869 §2.2, empty salt is replaced with a HashLen (64-byte) zero string.
///
/// HKDF-Expand(PRK, info, L):
///   T(1) = HMAC(PRK, info ∥ 0x01)
///   T(i) = HMAC(PRK, T(i-1) ∥ info ∥ i)
///   OKM  = T(1) ∥ T(2) ∥ ... truncated to L bytes.
use super::mlkem1024::keccak::{KeccakSponge, zeroize_sponge};
use super::sha3_512::{OUTPUT_LEN as HASH_LEN, RATE, hash as sha3_512};
use crate::zeroize::zeroize_mem;
use core::sync::atomic::{Ordering, compiler_fence};

/// HMAC block size = sponge rate for SHA3-512.
const BLOCK: usize = RATE;

/// HMAC-SHA3-512(key, msg_parts[0] ∥ msg_parts[1] ∥ ...).
///
/// `msg_parts` is absorbed in order. All sensitive intermediates are zeroized
/// before returning.
fn hmac_sha3_512(key: &[u8], msg_parts: &[&[u8]], out: &mut [u8; HASH_LEN]) {
    let mut k_buf = [0u8; BLOCK];
    if key.len() > BLOCK {
        sha3_512(&[key], unsafe {
            &mut *(k_buf.as_mut_ptr() as *mut [u8; HASH_LEN])
        });
    } else {
        k_buf[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] = k_buf[i] ^ 0x36;
        opad[i] = k_buf[i] ^ 0x5c;
    }

    let mut inner = [0u8; HASH_LEN];
    {
        let mut sponge: KeccakSponge<RATE> = KeccakSponge::new();
        sponge.absorb(&ipad);
        for part in msg_parts {
            sponge.absorb(part);
        }
        sponge.finalize(0x06);
        sponge.squeeze(&mut inner);
        zeroize_sponge(&mut sponge);
    }

    {
        let mut sponge: KeccakSponge<RATE> = KeccakSponge::new();
        sponge.absorb(&opad);
        sponge.absorb(&inner);
        sponge.finalize(0x06);
        sponge.squeeze(out);
        zeroize_sponge(&mut sponge);
    }

    unsafe {
        zeroize_mem(k_buf.as_mut_ptr(), BLOCK);
        zeroize_mem(ipad.as_mut_ptr(), BLOCK);
        zeroize_mem(opad.as_mut_ptr(), BLOCK);
        zeroize_mem(inner.as_mut_ptr(), HASH_LEN);
    }
    compiler_fence(Ordering::SeqCst);
}

/// HKDF-Extract(salt=∅, IKM) → PRK (64 bytes).
fn hkdf_extract(ikm: &[u8], prk: &mut [u8; HASH_LEN]) {
    let zero_salt = [0u8; HASH_LEN];
    hmac_sha3_512(&zero_salt, &[ikm], prk);
}

/// HKDF-Expand(PRK, info, L) → OKM (`out.len()` bytes).
fn hkdf_expand(prk: &[u8; HASH_LEN], info: &[u8], out: &mut [u8]) {
    let len = out.len();
    debug_assert!(
        len <= 255 * HASH_LEN,
        "HKDF-Expand: requested output exceeds 255 * HashLen"
    );

    let rounds = len.div_ceil(HASH_LEN);
    let mut t = [0u8; HASH_LEN];
    let mut t_valid = false;
    let mut pos = 0usize;

    for counter_byte in 1..=(rounds as u8) {
        let counter = [counter_byte];
        let mut t_next = [0u8; HASH_LEN];
        if t_valid {
            hmac_sha3_512(prk, &[&t, info, &counter], &mut t_next);
        } else {
            hmac_sha3_512(prk, &[info, &counter], &mut t_next);
        }
        unsafe { zeroize_mem(t.as_mut_ptr(), HASH_LEN) };
        t = t_next;
        t_valid = true;

        let copy_len = (len - pos).min(HASH_LEN);
        out[pos..pos + copy_len].copy_from_slice(&t[..copy_len]);
        pos += copy_len;
    }

    unsafe { zeroize_mem(t.as_mut_ptr(), HASH_LEN) };
    compiler_fence(Ordering::SeqCst);
}

/// `KDF(IKM, label, out)` — HKDF-SHA3-512 with empty salt.
pub(crate) fn kdf(ikm: &[u8], label: &[u8], out: &mut [u8]) {
    let mut prk = [0u8; HASH_LEN];
    hkdf_extract(ikm, &mut prk);
    hkdf_expand(&prk, label, out);
    unsafe { zeroize_mem(prk.as_mut_ptr(), HASH_LEN) };
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_deterministic_and_sensitive_to_key() {
        let mut out_a = [0u8; HASH_LEN];
        let mut out_b = [0u8; HASH_LEN];
        hmac_sha3_512(b"key1", &[b"msg"], &mut out_a);
        hmac_sha3_512(b"key2", &[b"msg"], &mut out_b);
        assert_ne!(out_a, out_b, "different keys must produce different MACs");
    }

    #[test]
    fn hmac_deterministic() {
        let mut first = [0u8; HASH_LEN];
        let mut second = [0u8; HASH_LEN];
        hmac_sha3_512(b"key", &[b"msg"], &mut first);
        hmac_sha3_512(b"key", &[b"msg"], &mut second);
        assert_eq!(first, second);
    }

    #[test]
    fn hmac_long_key_hashed() {
        let long_key = [0xAAu8; 80];
        let mut out = [0u8; HASH_LEN];
        hmac_sha3_512(&long_key, &[b"msg"], &mut out);
        assert!(out.iter().any(|&byte| byte != 0));
    }

    #[test]
    fn hkdf_32_bytes() {
        let mut out = [0u8; 32];
        kdf(b"input key material", b"test label", &mut out);
        assert!(
            out.iter().any(|&byte| byte != 0),
            "KDF output must be non-zero"
        );
    }

    #[test]
    fn hkdf_64_bytes() {
        let mut out = [0u8; HASH_LEN];
        kdf(b"ikm", b"info", &mut out);
        assert!(out.iter().any(|&byte| byte != 0));
    }

    #[test]
    fn hkdf_deterministic() {
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        kdf(b"ikm", b"label", &mut first);
        kdf(b"ikm", b"label", &mut second);
        assert_eq!(first, second);
    }

    #[test]
    fn hkdf_label_separation() {
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        kdf(b"same ikm", b"label_a", &mut first);
        kdf(b"same ikm", b"label_b", &mut second);
        assert_ne!(
            first, second,
            "different labels must produce different outputs"
        );
    }

    #[test]
    fn hkdf_ikm_separation() {
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        kdf(b"ikm_a", b"same label", &mut first);
        kdf(b"ikm_b", b"same label", &mut second);
        assert_ne!(
            first, second,
            "different IKM must produce different outputs"
        );
    }

    #[test]
    fn hkdf_multi_block_output() {
        let mut out = [0u8; 128];
        kdf(b"ikm", b"label", &mut out);
        assert!(out.iter().any(|&byte| byte != 0));

        let mut first_block = [0u8; HASH_LEN];
        kdf(b"ikm", b"label", &mut first_block);
        assert_eq!(&out[..HASH_LEN], &first_block);
    }

    #[test]
    fn hkdf_protocol_labels_distinct() {
        let ikm = [0u8; 32];
        let mut k_aead = [0u8; 32];
        let mut k_nonce = [0u8; HASH_LEN];
        kdf(&ikm, b"MLSigcrypt-v1/K_aead", &mut k_aead);
        kdf(&ikm, b"MLSigcrypt-v1/K_nonce", &mut k_nonce);
        assert_ne!(k_aead, k_nonce[..32], "K_aead and K_nonce must be distinct");
    }
}
