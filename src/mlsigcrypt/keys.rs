/// MLSigcrypt-v1 key types and key generation.
///
/// Key hierarchy:
///   msk (32 bytes, uniform random)
///     ├─ KDF(msk, "MLSigcrypt-v1/kem_seed", 64) → kem_seed
///     │     └─ ML-KEM-1024.KeyGen(kem_seed) → (sk_enc, pk_enc)
///     └─ KDF(msk, "MLSigcrypt-v1/sig_seed", 32) → sig_seed
///           └─ ML-DSA-87.KeyGen(sig_seed) → (sk_sig, pk_sig)
///
///   key_id = Truncate32(SHA3-512("MLSigcrypt-v1/key_id" || pk_enc || pk_sig))
///
/// `UserSecretKey` holds both subordinate secret keys in one struct and is
/// zeroized on Drop. `UserPublicKey` is freely copyable (no secret data).
use super::params::*;
use crate::mlsigcrypt::specs::hkdf::kdf;
use crate::mlsigcrypt::specs::mldsa87;
use crate::mlsigcrypt::specs::mlkem1024::{self, DecapKey, EncapKey};
use crate::mlsigcrypt::specs::sha3_512::hash as sha3_512;
use crate::zeroize::zeroize_mem;

pub(crate) const ENCODED_PUBLIC_KEY_SIZE: usize = KEY_ID_LEN + KEM_EK_LEN + SIG_PK_LEN;
pub(crate) const ENCODED_SECRET_KEY_SIZE: usize = ENCODED_PUBLIC_KEY_SIZE + KEM_DK_LEN + SIG_SK_LEN;

const PUBLIC_KEY_ID_OFF: usize = 0;
const PUBLIC_PK_ENC_OFF: usize = PUBLIC_KEY_ID_OFF + KEY_ID_LEN;
const PUBLIC_PK_SIG_OFF: usize = PUBLIC_PK_ENC_OFF + KEM_EK_LEN;
const SECRET_SK_ENC_OFF: usize = ENCODED_PUBLIC_KEY_SIZE;
const SECRET_SK_SIG_OFF: usize = SECRET_SK_ENC_OFF + KEM_DK_LEN;

// ── UserSecretKey ─────────────────────────────────────────────────────────────

/// A user's unified secret key: ML-KEM-1024 decap key + ML-DSA-87 signing key.
///
/// Holding `sk_enc` and `sk_sig` together ensures callers never pass the wrong
/// component to the wrong operation — the implementation selects internally.
/// Zeroized on `Drop`.
pub(crate) struct UserSecretKey {
    pub(super) sk_enc: [u8; KEM_DK_LEN], // ML-KEM-1024 decapsulation key
    pub(super) sk_sig: [u8; SIG_SK_LEN], // ML-DSA-87 signing key
}

impl Drop for UserSecretKey {
    fn drop(&mut self) {
        // SAFETY: both arrays are valid writable allocations.
        unsafe {
            zeroize_mem(self.sk_enc.as_mut_ptr(), KEM_DK_LEN);
            zeroize_mem(self.sk_sig.as_mut_ptr(), SIG_SK_LEN);
        }
    }
}

impl UserSecretKey {
    pub(crate) fn encode_into(
        &self,
        public_key: &UserPublicKey,
        out: &mut [u8; ENCODED_SECRET_KEY_SIZE],
    ) {
        out[PUBLIC_KEY_ID_OFF..PUBLIC_KEY_ID_OFF + KEY_ID_LEN].copy_from_slice(&public_key.key_id);
        out[PUBLIC_PK_ENC_OFF..PUBLIC_PK_ENC_OFF + KEM_EK_LEN].copy_from_slice(&public_key.pk_enc);
        out[PUBLIC_PK_SIG_OFF..PUBLIC_PK_SIG_OFF + SIG_PK_LEN].copy_from_slice(&public_key.pk_sig);
        out[SECRET_SK_ENC_OFF..SECRET_SK_ENC_OFF + KEM_DK_LEN].copy_from_slice(&self.sk_enc);
        out[SECRET_SK_SIG_OFF..SECRET_SK_SIG_OFF + SIG_SK_LEN].copy_from_slice(&self.sk_sig);
    }
}

// ── UserPublicKey ─────────────────────────────────────────────────────────────

/// A user's public identity object.
///
/// Contains both cryptographic public keys and the derived `key_id`.
/// No secret data; no zeroization required.
///
/// This is not "one keypair." It is the public half of two keypairs derived
/// from a single master secret. Callers must not assume algebraic unification
/// between the encryption and signing domains.
#[derive(Clone)]
pub(crate) struct UserPublicKey {
    pub(super) pk_enc: [u8; KEM_EK_LEN], // ML-KEM-1024 encapsulation key
    pub(super) pk_sig: [u8; SIG_PK_LEN], // ML-DSA-87 verification key
    pub(super) key_id: [u8; KEY_ID_LEN], // Truncate32(SHA3-512("MLSigcrypt-v1/key_id" || pk_enc || pk_sig))
}

impl UserPublicKey {
    /// Verify internal consistency: recompute key_id and compare.
    ///
    /// Returns true iff the key_id in this object matches the expected value
    /// derived from pk_enc and pk_sig. Uses a constant-time byte accumulator
    /// to prevent timing side channels.
    pub(super) fn verify_consistency(&self) -> bool {
        let mut hash = [0u8; SHA3_512_OUT];
        sha3_512(
            &[b"MLSigcrypt-v1/key_id", &self.pk_enc, &self.pk_sig],
            &mut hash,
        );
        let mut diff = 0u8;
        for i in 0..KEY_ID_LEN {
            diff |= self.key_id[i] ^ hash[i];
        }
        unsafe { zeroize_mem(hash.as_mut_ptr(), SHA3_512_OUT) };
        diff == 0
    }

    pub(crate) fn encode_into(&self, out: &mut [u8; ENCODED_PUBLIC_KEY_SIZE]) {
        out[PUBLIC_KEY_ID_OFF..PUBLIC_KEY_ID_OFF + KEY_ID_LEN].copy_from_slice(&self.key_id);
        out[PUBLIC_PK_ENC_OFF..PUBLIC_PK_ENC_OFF + KEM_EK_LEN].copy_from_slice(&self.pk_enc);
        out[PUBLIC_PK_SIG_OFF..PUBLIC_PK_SIG_OFF + SIG_PK_LEN].copy_from_slice(&self.pk_sig);
    }

    /// Access the ML-KEM-1024 encapsulation key.
    #[inline]
    pub(crate) fn pk_enc(&self) -> &[u8; KEM_EK_LEN] {
        &self.pk_enc
    }

    /// Access the ML-DSA-87 public verification key.
    #[inline]
    pub(crate) fn pk_sig(&self) -> &[u8; SIG_PK_LEN] {
        &self.pk_sig
    }

    /// Access the key identifier.
    #[inline]
    pub(crate) fn key_id(&self) -> &[u8; KEY_ID_LEN] {
        &self.key_id
    }
}

pub(crate) fn decode_public_key(bytes: &[u8]) -> Option<UserPublicKey> {
    if bytes.len() != ENCODED_PUBLIC_KEY_SIZE {
        return None;
    }

    let mut key_id = [0u8; KEY_ID_LEN];
    let mut pk_enc = [0u8; KEM_EK_LEN];
    let mut pk_sig = [0u8; SIG_PK_LEN];
    key_id.copy_from_slice(&bytes[PUBLIC_KEY_ID_OFF..PUBLIC_KEY_ID_OFF + KEY_ID_LEN]);
    pk_enc.copy_from_slice(&bytes[PUBLIC_PK_ENC_OFF..PUBLIC_PK_ENC_OFF + KEM_EK_LEN]);
    pk_sig.copy_from_slice(&bytes[PUBLIC_PK_SIG_OFF..PUBLIC_PK_SIG_OFF + SIG_PK_LEN]);

    Some(UserPublicKey {
        pk_enc,
        pk_sig,
        key_id,
    })
}

pub(crate) fn decode_secret_key(bytes: &[u8]) -> Option<(UserSecretKey, UserPublicKey)> {
    if bytes.len() != ENCODED_SECRET_KEY_SIZE {
        return None;
    }

    let public_key = decode_public_key(&bytes[..ENCODED_PUBLIC_KEY_SIZE])?;
    let mut sk_enc = [0u8; KEM_DK_LEN];
    let mut sk_sig = [0u8; SIG_SK_LEN];
    sk_enc.copy_from_slice(&bytes[SECRET_SK_ENC_OFF..SECRET_SK_ENC_OFF + KEM_DK_LEN]);
    sk_sig.copy_from_slice(&bytes[SECRET_SK_SIG_OFF..SECRET_SK_SIG_OFF + SIG_SK_LEN]);

    Some((UserSecretKey { sk_enc, sk_sig }, public_key))
}

// ── Key generation ────────────────────────────────────────────────────────────

/// Generate a `UserSecretKey` / `UserPublicKey` pair from a 32-byte master secret.
///
/// `msk` must be 32 bytes of uniform random, generated from a CSPRNG.
/// The function is deterministic: the same `msk` always produces the same keypair.
///
/// All intermediate seed material is zeroized before returning.
pub(crate) fn keygen(msk: &[u8; MASTER_SECRET_LEN]) -> (UserSecretKey, UserPublicKey) {
    // ── Step 1: Derive a 64-byte seed for ML-KEM-1024 ────────────────────────
    // ML-KEM-1024.KeyGen requires 64 bytes (d || z per FIPS 203 §6.1).
    let mut kem_seed = [0u8; 64];
    kdf(msk, b"MLSigcrypt-v1/kem_seed", &mut kem_seed);

    // ── Step 2: Derive a 32-byte seed for ML-DSA-87 ──────────────────────────
    let mut sig_seed = [0u8; 32];
    kdf(msk, b"MLSigcrypt-v1/sig_seed", &mut sig_seed);

    // ── Step 3: Generate ML-KEM-1024 keypair ─────────────────────────────────
    let mut ek = EncapKey([0u8; KEM_EK_LEN]);
    let mut dk = DecapKey([0u8; KEM_DK_LEN]);
    mlkem1024::keygen(&kem_seed, &mut ek, &mut dk);

    // ── Step 4: Generate ML-DSA-87 keypair ───────────────────────────────────
    let mut pk_sig = [0u8; SIG_PK_LEN];
    let mut sk_sig_buf = [0u8; SIG_SK_LEN];
    mldsa87::keypair(&mut pk_sig, &mut sk_sig_buf, &sig_seed);

    // ── Step 5: Derive key_id ─────────────────────────────────────────────────
    let mut hash = [0u8; SHA3_512_OUT];
    sha3_512(
        &[b"MLSigcrypt-v1/key_id", ek.as_bytes(), &pk_sig],
        &mut hash,
    );
    let mut key_id = [0u8; KEY_ID_LEN];
    key_id.copy_from_slice(&hash[..KEY_ID_LEN]);

    // ── Step 6: Move secret key data into UserSecretKey ───────────────────────
    let mut sk_enc = [0u8; KEM_DK_LEN];
    sk_enc.copy_from_slice(dk.as_bytes());
    // dk drops here — zeroized by DecapKey::drop.

    let sk = UserSecretKey {
        sk_enc,
        sk_sig: sk_sig_buf,
    };

    // ── Step 7: Move public key data into UserPublicKey ───────────────────────
    let pk = UserPublicKey {
        pk_enc: ek.0,
        pk_sig,
        key_id,
    };

    // ── Step 8: Zeroize intermediate seed material ────────────────────────────
    // SAFETY: both are valid writable stack allocations.
    unsafe {
        zeroize_mem(kem_seed.as_mut_ptr(), 64);
        zeroize_mem(sig_seed.as_mut_ptr(), 32);
        zeroize_mem(hash.as_mut_ptr(), SHA3_512_OUT);
    }

    (sk, pk)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_deterministic() {
        let msk = [0x42u8; MASTER_SECRET_LEN];
        let (_, pk_a) = keygen(&msk);
        let (_, pk_b) = keygen(&msk);
        assert_eq!(pk_a.pk_enc, pk_b.pk_enc, "enc keys must be deterministic");
        assert_eq!(pk_a.pk_sig, pk_b.pk_sig, "sig keys must be deterministic");
        assert_eq!(pk_a.key_id, pk_b.key_id, "key_ids must be deterministic");
    }

    #[test]
    fn keygen_different_msk_different_keys() {
        let (_, pk_a) = keygen(&[0x01u8; MASTER_SECRET_LEN]);
        let (_, pk_b) = keygen(&[0x02u8; MASTER_SECRET_LEN]);
        assert_ne!(pk_a.pk_enc, pk_b.pk_enc);
        assert_ne!(pk_a.pk_sig, pk_b.pk_sig);
    }

    #[test]
    fn pk_verify_consistency_passes_for_valid_key() {
        let (_, pk) = keygen(&[0xABu8; MASTER_SECRET_LEN]);
        assert!(
            pk.verify_consistency(),
            "freshly generated key must pass consistency check"
        );
    }

    #[test]
    fn pk_verify_consistency_fails_for_tampered_key_id() {
        let (_, mut pk) = keygen(&[0x55u8; MASTER_SECRET_LEN]);
        pk.key_id[0] ^= 0xFF; // corrupt one byte
        assert!(
            !pk.verify_consistency(),
            "tampered key_id must fail consistency check"
        );
    }

    #[test]
    fn pk_verify_consistency_fails_for_tampered_pk_enc() {
        let (_, mut pk) = keygen(&[0x77u8; MASTER_SECRET_LEN]);
        pk.pk_enc[100] ^= 0x01;
        assert!(!pk.verify_consistency());
    }

    #[test]
    fn sk_is_nonzero() {
        let msk = [0xFFu8; MASTER_SECRET_LEN];
        let (sk, _) = keygen(&msk);
        assert!(sk.sk_enc.iter().any(|&b| b != 0), "sk_enc must be non-zero");
        assert!(sk.sk_sig.iter().any(|&b| b != 0), "sk_sig must be non-zero");
    }

    #[test]
    fn encoded_public_key_roundtrips() {
        let (_, pk) = keygen(&[0x33u8; MASTER_SECRET_LEN]);
        let mut encoded = [0u8; ENCODED_PUBLIC_KEY_SIZE];
        pk.encode_into(&mut encoded);

        let decoded = decode_public_key(&encoded).expect("decode must succeed");
        assert_eq!(decoded.key_id, pk.key_id);
        assert_eq!(decoded.pk_enc, pk.pk_enc);
        assert_eq!(decoded.pk_sig, pk.pk_sig);
        assert!(decoded.verify_consistency());
    }

    #[test]
    fn encoded_secret_key_roundtrips() {
        let (sk, pk) = keygen(&[0x44u8; MASTER_SECRET_LEN]);
        let mut encoded = [0u8; ENCODED_SECRET_KEY_SIZE];
        sk.encode_into(&pk, &mut encoded);

        let (decoded_sk, decoded_pk) = decode_secret_key(&encoded).expect("decode must succeed");
        assert_eq!(decoded_sk.sk_enc, sk.sk_enc);
        assert_eq!(decoded_sk.sk_sig, sk.sk_sig);
        assert_eq!(decoded_pk.key_id, pk.key_id);
        assert_eq!(decoded_pk.pk_enc, pk.pk_enc);
        assert_eq!(decoded_pk.pk_sig, pk.pk_sig);
        assert!(decoded_pk.verify_consistency());
    }
}
