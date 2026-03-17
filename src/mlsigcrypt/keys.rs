/// MLSigcrypt-v2 level-2 key types and key generation.
///
/// Key hierarchy:
///   msk (32 bytes, uniform random)
///     ├─ SHA3-512("MLSigcrypt-v2/matrix_seed" || msk)[0..32] → matrix_seed
///     │     └─ SHAKE-128(matrix_seed)[0..32] → ρ_shared
///     ├─ SHA3-512("MLSigcrypt-v2/kem_seed" || msk)[0..64] → kem_seed
///     │     └─ ML-KEM-1024.KeyGen(kem_seed, ρ_shared) → (sk_enc, pk_enc)
///     └─ SHA3-512("MLSigcrypt-v2/sig_seed" || msk)[0..32] → sig_seed
///           └─ ML-DSA-87.KeyGen(sig_seed, ρ_shared) → (sk_sig, pk_sig)
///
///   key_id = Truncate32(SHA3-512("MLSigcrypt-v2/key_id" || pk_enc || pk_sig || ρ_shared))
///
/// `UserSecretKey` holds both subordinate secret keys in one struct and is
/// zeroized on Drop. `UserPublicKey` is freely copyable (no secret data).
use super::params::*;
use crate::mlsigcrypt::specs::mldsa87;
use crate::mlsigcrypt::specs::mlkem1024::hash::shake128;
use crate::mlsigcrypt::specs::mlkem1024::serialize::ek_rho;
use crate::mlsigcrypt::specs::mlkem1024::{self, DecapKey, EncapKey};
use crate::mlsigcrypt::specs::sha3_512::hash as sha3_512;
use crate::zeroize::zeroize_mem;

const MATRIX_SEED_LEN: usize = 32;
const MATRIX_SEED_DOMAIN: &[u8] = b"MLSigcrypt-v2/matrix_seed";
const KEM_SEED_DOMAIN: &[u8] = b"MLSigcrypt-v2/kem_seed";
const SIG_SEED_DOMAIN: &[u8] = b"MLSigcrypt-v2/sig_seed";
const KEY_ID_DOMAIN: &[u8] = b"MLSigcrypt-v2/key_id";

pub(crate) const ENCODED_PUBLIC_KEY_SIZE: usize = KEY_ID_LEN + KEM_EK_LEN + SIG_PK_LEN;
pub(crate) const ENCODED_SECRET_KEY_SIZE: usize =
    MATRIX_SEED_LEN + KEM_DK_LEN + SIG_SK_LEN + ENCODED_PUBLIC_KEY_SIZE;

const PUBLIC_KEY_ID_OFF: usize = 0;
const PUBLIC_PK_ENC_OFF: usize = PUBLIC_KEY_ID_OFF + KEY_ID_LEN;
const PUBLIC_PK_SIG_OFF: usize = PUBLIC_PK_ENC_OFF + KEM_EK_LEN;
const SECRET_MATRIX_SEED_OFF: usize = 0;
const SECRET_SK_ENC_OFF: usize = SECRET_MATRIX_SEED_OFF + MATRIX_SEED_LEN;
const SECRET_SK_SIG_OFF: usize = SECRET_SK_ENC_OFF + KEM_DK_LEN;
const SECRET_PUBLIC_KEY_OFF: usize = SECRET_SK_SIG_OFF + SIG_SK_LEN;

fn derive_matrix_rho(matrix_seed: &[u8; MATRIX_SEED_LEN], out: &mut [u8; 32]) {
    shake128(matrix_seed, out);
}

fn shared_matrix_rho(pk_enc: &[u8; KEM_EK_LEN], pk_sig: &[u8; SIG_PK_LEN]) -> Option<[u8; 32]> {
    let kem_rho = ek_rho(pk_enc);
    let mut sig_rho = [0u8; 32];
    sig_rho.copy_from_slice(&pk_sig[..32]);
    if kem_rho != &sig_rho {
        return None;
    }
    Some(sig_rho)
}

// ── UserSecretKey ─────────────────────────────────────────────────────────────

/// A user's unified secret key: shared matrix seed + ML-KEM-1024 decap key +
/// ML-DSA-87 signing key.
///
/// Holding `sk_enc` and `sk_sig` together ensures callers never pass the wrong
/// component to the wrong operation — the implementation selects internally.
/// Zeroized on `Drop`.
pub(crate) struct UserSecretKey {
    pub(super) matrix_seed: [u8; MATRIX_SEED_LEN], // MLSigcrypt-v2 shared matrix seed
    pub(super) sk_enc: [u8; KEM_DK_LEN],           // ML-KEM-1024 decapsulation key
    pub(super) sk_sig: [u8; SIG_SK_LEN],           // ML-DSA-87 signing key
}

impl Drop for UserSecretKey {
    fn drop(&mut self) {
        // SAFETY: both arrays are valid writable allocations.
        unsafe {
            zeroize_mem(self.matrix_seed.as_mut_ptr(), MATRIX_SEED_LEN);
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
        out[SECRET_MATRIX_SEED_OFF..SECRET_MATRIX_SEED_OFF + MATRIX_SEED_LEN]
            .copy_from_slice(&self.matrix_seed);
        out[SECRET_SK_ENC_OFF..SECRET_SK_ENC_OFF + KEM_DK_LEN].copy_from_slice(&self.sk_enc);
        out[SECRET_SK_SIG_OFF..SECRET_SK_SIG_OFF + SIG_SK_LEN].copy_from_slice(&self.sk_sig);
        out[SECRET_PUBLIC_KEY_OFF + PUBLIC_KEY_ID_OFF
            ..SECRET_PUBLIC_KEY_OFF + PUBLIC_KEY_ID_OFF + KEY_ID_LEN]
            .copy_from_slice(&public_key.key_id);
        out[SECRET_PUBLIC_KEY_OFF + PUBLIC_PK_ENC_OFF
            ..SECRET_PUBLIC_KEY_OFF + PUBLIC_PK_ENC_OFF + KEM_EK_LEN]
            .copy_from_slice(&public_key.pk_enc);
        out[SECRET_PUBLIC_KEY_OFF + PUBLIC_PK_SIG_OFF
            ..SECRET_PUBLIC_KEY_OFF + PUBLIC_PK_SIG_OFF + SIG_PK_LEN]
            .copy_from_slice(&public_key.pk_sig);
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
    pub(super) key_id: [u8; KEY_ID_LEN], // Truncate32(SHA3-512("MLSigcrypt-v2/key_id" || pk_enc || pk_sig || ρ_shared))
}

impl UserPublicKey {
    /// Verify internal consistency: recompute key_id and compare.
    ///
    /// Returns true iff the key_id in this object matches the expected value
    /// derived from pk_enc and pk_sig. Uses a constant-time byte accumulator
    /// to prevent timing side channels.
    pub(super) fn verify_consistency(&self) -> bool {
        let Some(mut matrix_rho) = shared_matrix_rho(&self.pk_enc, &self.pk_sig) else {
            return false;
        };
        let mut hash = [0u8; SHA3_512_OUT];
        sha3_512(
            &[KEY_ID_DOMAIN, &self.pk_enc, &self.pk_sig, &matrix_rho],
            &mut hash,
        );
        let mut diff = 0u8;
        for i in 0..KEY_ID_LEN {
            diff |= self.key_id[i] ^ hash[i];
        }
        unsafe {
            zeroize_mem(hash.as_mut_ptr(), SHA3_512_OUT);
            zeroize_mem(matrix_rho.as_mut_ptr(), MATRIX_SEED_LEN);
        }
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

    shared_matrix_rho(&pk_enc, &pk_sig)?;

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

    let public_key = decode_public_key(
        &bytes[SECRET_PUBLIC_KEY_OFF..SECRET_PUBLIC_KEY_OFF + ENCODED_PUBLIC_KEY_SIZE],
    )?;
    let mut matrix_seed = [0u8; MATRIX_SEED_LEN];
    let mut sk_enc = [0u8; KEM_DK_LEN];
    let mut sk_sig = [0u8; SIG_SK_LEN];
    matrix_seed
        .copy_from_slice(&bytes[SECRET_MATRIX_SEED_OFF..SECRET_MATRIX_SEED_OFF + MATRIX_SEED_LEN]);
    sk_enc.copy_from_slice(&bytes[SECRET_SK_ENC_OFF..SECRET_SK_ENC_OFF + KEM_DK_LEN]);
    sk_sig.copy_from_slice(&bytes[SECRET_SK_SIG_OFF..SECRET_SK_SIG_OFF + SIG_SK_LEN]);

    let public_rho = shared_matrix_rho(&public_key.pk_enc, &public_key.pk_sig)?;
    let mut derived_rho = [0u8; 32];
    derive_matrix_rho(&matrix_seed, &mut derived_rho);

    if public_rho != derived_rho {
        return None;
    }
    if sk_sig[..MATRIX_SEED_LEN] != derived_rho {
        return None;
    }
    if sk_enc[crate::mlsigcrypt::specs::mlkem1024::params::DK_OFFSET_EK_PKE
        ..crate::mlsigcrypt::specs::mlkem1024::params::DK_OFFSET_EK_PKE + KEM_EK_LEN]
        != public_key.pk_enc
    {
        return None;
    }

    Some((
        UserSecretKey {
            matrix_seed,
            sk_enc,
            sk_sig,
        },
        public_key,
    ))
}

// ── Key generation ────────────────────────────────────────────────────────────

/// Generate a `UserSecretKey` / `UserPublicKey` pair from a 32-byte master secret.
///
/// `msk` must be 32 bytes of uniform random, generated from a CSPRNG.
/// The function is deterministic: the same `msk` always produces the same keypair.
///
/// All intermediate seed material is zeroized before returning.
pub(crate) fn keygen(msk: &[u8; MASTER_SECRET_LEN]) -> (UserSecretKey, UserPublicKey) {
    // ── Step 1: Derive the shared MLSigcrypt-v2 matrix seed ──────────────────
    let mut matrix_seed_full = [0u8; SHA3_512_OUT];
    sha3_512(&[MATRIX_SEED_DOMAIN, msk], &mut matrix_seed_full);
    let mut matrix_seed = [0u8; MATRIX_SEED_LEN];
    matrix_seed.copy_from_slice(&matrix_seed_full[..MATRIX_SEED_LEN]);

    let mut rho_shared = [0u8; 32];
    derive_matrix_rho(&matrix_seed, &mut rho_shared);

    // ── Step 2: Derive a 64-byte seed for ML-KEM-1024 ────────────────────────
    // ML-KEM-1024.KeyGen requires 64 bytes (d || z per FIPS 203 §6.1).
    let mut kem_seed = [0u8; 64];
    sha3_512(&[KEM_SEED_DOMAIN, msk], &mut kem_seed);

    // ── Step 3: Derive a 32-byte seed for ML-DSA-87 ──────────────────────────
    let mut sig_seed = [0u8; 32];
    let mut sig_seed_full = [0u8; SHA3_512_OUT];
    sha3_512(&[SIG_SEED_DOMAIN, msk], &mut sig_seed_full);
    sig_seed.copy_from_slice(&sig_seed_full[..32]);

    // ── Step 4: Generate ML-KEM-1024 keypair from the shared matrix ──────────
    let mut ek = EncapKey([0u8; KEM_EK_LEN]);
    let mut dk = DecapKey([0u8; KEM_DK_LEN]);
    mlkem1024::keygen_with_rho(&kem_seed, &rho_shared, &mut ek, &mut dk);

    // ── Step 5: Generate ML-DSA-87 keypair from the shared matrix ────────────
    let mut pk_sig = [0u8; SIG_PK_LEN];
    let mut sk_sig_buf = [0u8; SIG_SK_LEN];
    mldsa87::keypair_with_rho(&mut pk_sig, &mut sk_sig_buf, &sig_seed, &rho_shared);

    // ── Step 6: Derive key_id ─────────────────────────────────────────────────
    let mut hash = [0u8; SHA3_512_OUT];
    sha3_512(
        &[KEY_ID_DOMAIN, ek.as_bytes(), &pk_sig, &rho_shared],
        &mut hash,
    );
    let mut key_id = [0u8; KEY_ID_LEN];
    key_id.copy_from_slice(&hash[..KEY_ID_LEN]);

    // ── Step 7: Move secret key data into UserSecretKey ───────────────────────
    let mut sk_enc = [0u8; KEM_DK_LEN];
    sk_enc.copy_from_slice(dk.as_bytes());
    // dk drops here — zeroized by DecapKey::drop.

    let sk = UserSecretKey {
        matrix_seed,
        sk_enc,
        sk_sig: sk_sig_buf,
    };

    // ── Step 8: Move public key data into UserPublicKey ───────────────────────
    let pk = UserPublicKey {
        pk_enc: ek.0,
        pk_sig,
        key_id,
    };

    // ── Step 9: Zeroize intermediate seed material ────────────────────────────
    // SAFETY: both are valid writable stack allocations.
    unsafe {
        zeroize_mem(matrix_seed_full.as_mut_ptr(), SHA3_512_OUT);
        zeroize_mem(rho_shared.as_mut_ptr(), MATRIX_SEED_LEN);
        zeroize_mem(kem_seed.as_mut_ptr(), 64);
        zeroize_mem(sig_seed.as_mut_ptr(), 32);
        zeroize_mem(sig_seed_full.as_mut_ptr(), SHA3_512_OUT);
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
        assert!(
            sk.matrix_seed.iter().any(|&b| b != 0),
            "matrix_seed must be non-zero"
        );
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
        assert_eq!(decoded_sk.matrix_seed, sk.matrix_seed);
        assert_eq!(decoded_sk.sk_enc, sk.sk_enc);
        assert_eq!(decoded_sk.sk_sig, sk.sk_sig);
        assert_eq!(decoded_pk.key_id, pk.key_id);
        assert_eq!(decoded_pk.pk_enc, pk.pk_enc);
        assert_eq!(decoded_pk.pk_sig, pk.pk_sig);
        assert!(decoded_pk.verify_consistency());
    }

    #[test]
    fn decode_public_key_rejects_mismatched_shared_rho() {
        let (_, pk) = keygen(&[0x45u8; MASTER_SECRET_LEN]);
        let mut encoded = [0u8; ENCODED_PUBLIC_KEY_SIZE];
        pk.encode_into(&mut encoded);
        encoded[PUBLIC_PK_SIG_OFF] ^= 0x01;
        assert!(decode_public_key(&encoded).is_none());
    }

    #[test]
    fn decode_secret_key_rejects_tampered_matrix_seed() {
        let (sk, pk) = keygen(&[0x46u8; MASTER_SECRET_LEN]);
        let mut encoded = [0u8; ENCODED_SECRET_KEY_SIZE];
        sk.encode_into(&pk, &mut encoded);
        encoded[SECRET_MATRIX_SEED_OFF] ^= 0x01;
        assert!(decode_secret_key(&encoded).is_none());
    }
}
