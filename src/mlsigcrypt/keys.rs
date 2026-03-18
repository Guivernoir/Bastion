/// MLSigcrypt-v3 level-3 key types and key generation.
///
/// Key hierarchy:
///   msk (32 bytes, uniform random)
///     ├─ SHA3-512("MLSigcrypt-v3/matrix_seed" || msk)[0..32] → matrix_seed
///     │     └─ SHAKE-128(matrix_seed)[0..32] → ρ_shared
///     ├─ SHA3-512("MLSigcrypt-v3/kem_seed" || msk)[0..32] → sk_enc_seed
///     │     └─ algebraic recipient keygen(ρ_shared, sk_enc_seed) → pk_enc
///     └─ SHA3-512("MLSigcrypt-v3/sig_seed" || msk)[0..32] → sig_seed
///           └─ ML-DSA-87.KeyGen(sig_seed, ρ_shared) → (sk_sig, pk_sig)
///
///   key_id = Truncate32(SHA3-512("MLSigcrypt-v3/key_id" || pk_enc || pk_sig || ρ_shared))
use super::params::*;
use crate::mlsigcrypt::specs::algebraic;
use crate::mlsigcrypt::specs::keccak::shake128;
use crate::mlsigcrypt::specs::ml;
use crate::mlsigcrypt::specs::ml::matrix::PolyMatrix;
use crate::mlsigcrypt::specs::ml::packing::{unpack_pk_rho, unpack_sk_rho};
use crate::mlsigcrypt::specs::ml::sampling::expand_a;
use crate::mlsigcrypt::specs::sha512::sha3_512_hash as sha3_512;
use crate::zeroize::zeroize_mem;

const MATRIX_SEED_DOMAIN: &[u8] = b"MLSigcrypt-v3/matrix_seed";
const KEM_SEED_DOMAIN: &[u8] = b"MLSigcrypt-v3/kem_seed";
const SIG_SEED_DOMAIN: &[u8] = b"MLSigcrypt-v3/sig_seed";
const KEY_ID_DOMAIN: &[u8] = b"MLSigcrypt-v3/key_id";

pub(crate) const ENCODED_PUBLIC_KEY_SIZE: usize =
    KEY_ID_LEN + MATRIX_SEED_LEN + ENC_PK_LEN + SIG_PK_LEN;
pub(crate) const ENCODED_SECRET_KEY_SIZE: usize =
    MATRIX_SEED_LEN + SK_ENC_SEED_LEN + SIG_SK_LEN + ENCODED_PUBLIC_KEY_SIZE;

const PUBLIC_KEY_ID_OFF: usize = 0;
const PUBLIC_RHO_OFF: usize = PUBLIC_KEY_ID_OFF + KEY_ID_LEN;
const PUBLIC_PK_ENC_OFF: usize = PUBLIC_RHO_OFF + MATRIX_SEED_LEN;
const PUBLIC_PK_SIG_OFF: usize = PUBLIC_PK_ENC_OFF + ENC_PK_LEN;

const SECRET_MATRIX_SEED_OFF: usize = 0;
const SECRET_SK_ENC_SEED_OFF: usize = SECRET_MATRIX_SEED_OFF + MATRIX_SEED_LEN;
const SECRET_SK_SIG_OFF: usize = SECRET_SK_ENC_SEED_OFF + SK_ENC_SEED_LEN;
const SECRET_PUBLIC_KEY_OFF: usize = SECRET_SK_SIG_OFF + SIG_SK_LEN;

fn derive_matrix_rho(matrix_seed: &[u8; MATRIX_SEED_LEN], out: &mut [u8; 32]) {
    shake128(matrix_seed, out);
}

fn compute_key_id(
    rho_shared: &[u8; 32],
    pk_enc: &[u8; ENC_PK_LEN],
    pk_sig: &[u8; SIG_PK_LEN],
    out: &mut [u8; KEY_ID_LEN],
) {
    let mut hash = [0u8; SHA3_512_OUT];
    sha3_512(&[KEY_ID_DOMAIN, pk_enc, pk_sig, rho_shared], &mut hash);
    out.copy_from_slice(&hash[..KEY_ID_LEN]);
    unsafe { zeroize_mem(hash.as_mut_ptr(), SHA3_512_OUT) };
}

// ── UserSecretKey ─────────────────────────────────────────────────────────────

pub(crate) struct UserSecretKey {
    pub(super) matrix_seed: [u8; MATRIX_SEED_LEN],
    pub(super) sk_enc_seed: [u8; SK_ENC_SEED_LEN],
    pub(super) sk_sig: [u8; SIG_SK_LEN],
}

impl Drop for UserSecretKey {
    fn drop(&mut self) {
        unsafe {
            zeroize_mem(self.matrix_seed.as_mut_ptr(), MATRIX_SEED_LEN);
            zeroize_mem(self.sk_enc_seed.as_mut_ptr(), SK_ENC_SEED_LEN);
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
        out[SECRET_SK_ENC_SEED_OFF..SECRET_SK_ENC_SEED_OFF + SK_ENC_SEED_LEN]
            .copy_from_slice(&self.sk_enc_seed);
        out[SECRET_SK_SIG_OFF..SECRET_SK_SIG_OFF + SIG_SK_LEN].copy_from_slice(&self.sk_sig);
        public_key.encode_into(
            (&mut out[SECRET_PUBLIC_KEY_OFF..SECRET_PUBLIC_KEY_OFF + ENCODED_PUBLIC_KEY_SIZE])
                .try_into()
                .expect("public-key tail size"),
        );
    }
}

// ── UserPublicKey ─────────────────────────────────────────────────────────────

pub(crate) struct UserPublicKey {
    pub(super) rho_shared: [u8; MATRIX_SEED_LEN],
    pub(super) pk_enc: [u8; ENC_PK_LEN],
    pub(super) pk_sig: [u8; SIG_PK_LEN],
    pub(super) key_id: [u8; KEY_ID_LEN],
}

impl UserPublicKey {
    pub(super) fn verify_consistency(&self) -> bool {
        let mut pk_sig_rho = [0u8; MATRIX_SEED_LEN];
        unpack_pk_rho(&mut pk_sig_rho, &self.pk_sig);
        if pk_sig_rho != self.rho_shared {
            unsafe { zeroize_mem(pk_sig_rho.as_mut_ptr(), MATRIX_SEED_LEN) };
            return false;
        }
        unsafe { zeroize_mem(pk_sig_rho.as_mut_ptr(), MATRIX_SEED_LEN) };

        let mut expected = [0u8; KEY_ID_LEN];
        compute_key_id(&self.rho_shared, &self.pk_enc, &self.pk_sig, &mut expected);
        let mut diff = 0u8;
        for i in 0..KEY_ID_LEN {
            diff |= self.key_id[i] ^ expected[i];
        }
        unsafe { zeroize_mem(expected.as_mut_ptr(), KEY_ID_LEN) };
        diff == 0
    }

    pub(crate) fn encode_into(&self, out: &mut [u8; ENCODED_PUBLIC_KEY_SIZE]) {
        out[PUBLIC_KEY_ID_OFF..PUBLIC_KEY_ID_OFF + KEY_ID_LEN].copy_from_slice(&self.key_id);
        out[PUBLIC_RHO_OFF..PUBLIC_RHO_OFF + MATRIX_SEED_LEN].copy_from_slice(&self.rho_shared);
        out[PUBLIC_PK_ENC_OFF..PUBLIC_PK_ENC_OFF + ENC_PK_LEN].copy_from_slice(&self.pk_enc);
        out[PUBLIC_PK_SIG_OFF..PUBLIC_PK_SIG_OFF + SIG_PK_LEN].copy_from_slice(&self.pk_sig);
    }

    #[inline]
    pub(crate) fn rho_shared(&self) -> &[u8; MATRIX_SEED_LEN] {
        &self.rho_shared
    }

    #[inline]
    pub(crate) fn pk_enc(&self) -> &[u8; ENC_PK_LEN] {
        &self.pk_enc
    }

    #[inline]
    pub(crate) fn pk_sig(&self) -> &[u8; SIG_PK_LEN] {
        &self.pk_sig
    }

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
    let mut rho_shared = [0u8; MATRIX_SEED_LEN];
    let mut pk_enc = [0u8; ENC_PK_LEN];
    let mut pk_sig = [0u8; SIG_PK_LEN];
    key_id.copy_from_slice(&bytes[PUBLIC_KEY_ID_OFF..PUBLIC_KEY_ID_OFF + KEY_ID_LEN]);
    rho_shared.copy_from_slice(&bytes[PUBLIC_RHO_OFF..PUBLIC_RHO_OFF + MATRIX_SEED_LEN]);
    pk_enc.copy_from_slice(&bytes[PUBLIC_PK_ENC_OFF..PUBLIC_PK_ENC_OFF + ENC_PK_LEN]);
    pk_sig.copy_from_slice(&bytes[PUBLIC_PK_SIG_OFF..PUBLIC_PK_SIG_OFF + SIG_PK_LEN]);

    let mut decoded_pk_enc = crate::mlsigcrypt::specs::ml::vec::PolyVec::<4>::zero();
    if !algebraic::decode_public_key(&pk_enc, &mut decoded_pk_enc) {
        return None;
    }
    crate::mlsigcrypt::specs::ml::vec::zeroize_polyvec(&mut decoded_pk_enc);

    let public = UserPublicKey {
        rho_shared,
        pk_enc,
        pk_sig,
        key_id,
    };
    if !public.verify_consistency() {
        return None;
    }
    Some(public)
}

pub(crate) fn decode_secret_key(bytes: &[u8]) -> Option<(UserSecretKey, UserPublicKey)> {
    if bytes.len() != ENCODED_SECRET_KEY_SIZE {
        return None;
    }

    let public_key = decode_public_key(
        &bytes[SECRET_PUBLIC_KEY_OFF..SECRET_PUBLIC_KEY_OFF + ENCODED_PUBLIC_KEY_SIZE],
    )?;

    let mut matrix_seed = [0u8; MATRIX_SEED_LEN];
    let mut sk_enc_seed = [0u8; SK_ENC_SEED_LEN];
    let mut sk_sig = [0u8; SIG_SK_LEN];
    matrix_seed
        .copy_from_slice(&bytes[SECRET_MATRIX_SEED_OFF..SECRET_MATRIX_SEED_OFF + MATRIX_SEED_LEN]);
    sk_enc_seed
        .copy_from_slice(&bytes[SECRET_SK_ENC_SEED_OFF..SECRET_SK_ENC_SEED_OFF + SK_ENC_SEED_LEN]);
    sk_sig.copy_from_slice(&bytes[SECRET_SK_SIG_OFF..SECRET_SK_SIG_OFF + SIG_SK_LEN]);

    let mut derived_rho = [0u8; MATRIX_SEED_LEN];
    derive_matrix_rho(&matrix_seed, &mut derived_rho);
    if derived_rho != public_key.rho_shared {
        return None;
    }
    let mut sk_sig_rho = [0u8; MATRIX_SEED_LEN];
    unpack_sk_rho(&mut sk_sig_rho, &sk_sig);
    if sk_sig_rho != derived_rho {
        unsafe { zeroize_mem(sk_sig_rho.as_mut_ptr(), MATRIX_SEED_LEN) };
        return None;
    }
    unsafe { zeroize_mem(sk_sig_rho.as_mut_ptr(), MATRIX_SEED_LEN) };

    let mut expected_pk_enc = [0u8; ENC_PK_LEN];
    algebraic::derive_public_key(&derived_rho, &sk_enc_seed, &mut expected_pk_enc);
    if expected_pk_enc != public_key.pk_enc {
        return None;
    }

    unsafe {
        zeroize_mem(derived_rho.as_mut_ptr(), MATRIX_SEED_LEN);
        zeroize_mem(expected_pk_enc.as_mut_ptr(), ENC_PK_LEN);
    }

    Some((
        UserSecretKey {
            matrix_seed,
            sk_enc_seed,
            sk_sig,
        },
        public_key,
    ))
}

pub(crate) fn keygen(msk: &[u8; MASTER_SECRET_LEN]) -> (UserSecretKey, UserPublicKey) {
    let mut matrix_seed_full = [0u8; SHA3_512_OUT];
    sha3_512(&[MATRIX_SEED_DOMAIN, msk], &mut matrix_seed_full);
    let mut matrix_seed = [0u8; MATRIX_SEED_LEN];
    matrix_seed.copy_from_slice(&matrix_seed_full[..MATRIX_SEED_LEN]);

    let mut rho_shared = [0u8; MATRIX_SEED_LEN];
    derive_matrix_rho(&matrix_seed, &mut rho_shared);

    let mut sk_enc_seed_full = [0u8; SHA3_512_OUT];
    sha3_512(&[KEM_SEED_DOMAIN, msk], &mut sk_enc_seed_full);
    let mut sk_enc_seed = [0u8; SK_ENC_SEED_LEN];
    sk_enc_seed.copy_from_slice(&sk_enc_seed_full[..SK_ENC_SEED_LEN]);

    let mut sig_seed_full = [0u8; SHA3_512_OUT];
    sha3_512(&[SIG_SEED_DOMAIN, msk], &mut sig_seed_full);
    let mut sig_seed = [0u8; 32];
    sig_seed.copy_from_slice(&sig_seed_full[..32]);

    let mut mat_a = PolyMatrix::zero();
    expand_a(&mut mat_a, &rho_shared);

    let mut pk_enc = [0u8; ENC_PK_LEN];
    algebraic::derive_public_key_from_matrix(&mat_a, &sk_enc_seed, &mut pk_enc);

    let mut pk_sig = [0u8; SIG_PK_LEN];
    let mut sk_sig = [0u8; SIG_SK_LEN];
    ml::keypair_with_matrix(&mut pk_sig, &mut sk_sig, &sig_seed, &rho_shared, &mat_a);

    let mut key_id = [0u8; KEY_ID_LEN];
    compute_key_id(&rho_shared, &pk_enc, &pk_sig, &mut key_id);

    let sk = UserSecretKey {
        matrix_seed,
        sk_enc_seed,
        sk_sig,
    };
    let pk = UserPublicKey {
        rho_shared,
        pk_enc,
        pk_sig,
        key_id,
    };

    unsafe {
        zeroize_mem(matrix_seed_full.as_mut_ptr(), SHA3_512_OUT);
        zeroize_mem(sk_enc_seed_full.as_mut_ptr(), SHA3_512_OUT);
        zeroize_mem(sig_seed_full.as_mut_ptr(), SHA3_512_OUT);
        zeroize_mem(sig_seed.as_mut_ptr(), 32);
    }

    (sk, pk)
}

#[cfg(test)]
pub(crate) struct KeygenTrace {
    pub(crate) msk: [u8; MASTER_SECRET_LEN],
    pub(crate) matrix_seed: [u8; MATRIX_SEED_LEN],
    pub(crate) rho_shared: [u8; MATRIX_SEED_LEN],
    pub(crate) sk_enc_seed: [u8; SK_ENC_SEED_LEN],
    pub(crate) sig_seed: [u8; 32],
    pub(crate) key_id: [u8; KEY_ID_LEN],
    pub(crate) pk_enc: [u8; ENC_PK_LEN],
    pub(crate) pk_sig: [u8; SIG_PK_LEN],
    pub(crate) encoded_public_key: [u8; ENCODED_PUBLIC_KEY_SIZE],
    pub(crate) encoded_secret_key: [u8; ENCODED_SECRET_KEY_SIZE],
}

#[cfg(test)]
pub(crate) fn keygen_trace(msk: &[u8; MASTER_SECRET_LEN]) -> KeygenTrace {
    let (secret_key, public_key) = keygen(msk);
    let mut encoded_public_key = [0u8; ENCODED_PUBLIC_KEY_SIZE];
    let mut encoded_secret_key = [0u8; ENCODED_SECRET_KEY_SIZE];
    let mut matrix_seed_full = [0u8; SHA3_512_OUT];
    let mut sk_enc_seed_full = [0u8; SHA3_512_OUT];
    let mut sig_seed_full = [0u8; SHA3_512_OUT];
    let mut matrix_seed = [0u8; MATRIX_SEED_LEN];
    let mut rho_shared = [0u8; MATRIX_SEED_LEN];
    let mut sk_enc_seed = [0u8; SK_ENC_SEED_LEN];
    let mut sig_seed = [0u8; 32];

    sha3_512(&[MATRIX_SEED_DOMAIN, msk], &mut matrix_seed_full);
    matrix_seed.copy_from_slice(&matrix_seed_full[..MATRIX_SEED_LEN]);
    derive_matrix_rho(&matrix_seed, &mut rho_shared);

    sha3_512(&[KEM_SEED_DOMAIN, msk], &mut sk_enc_seed_full);
    sk_enc_seed.copy_from_slice(&sk_enc_seed_full[..SK_ENC_SEED_LEN]);

    sha3_512(&[SIG_SEED_DOMAIN, msk], &mut sig_seed_full);
    sig_seed.copy_from_slice(&sig_seed_full[..32]);

    public_key.encode_into(&mut encoded_public_key);
    secret_key.encode_into(&public_key, &mut encoded_secret_key);

    unsafe {
        zeroize_mem(matrix_seed_full.as_mut_ptr(), SHA3_512_OUT);
        zeroize_mem(sk_enc_seed_full.as_mut_ptr(), SHA3_512_OUT);
        zeroize_mem(sig_seed_full.as_mut_ptr(), SHA3_512_OUT);
    }

    KeygenTrace {
        msk: *msk,
        matrix_seed,
        rho_shared,
        sk_enc_seed,
        sig_seed,
        key_id: public_key.key_id,
        pk_enc: public_key.pk_enc,
        pk_sig: public_key.pk_sig,
        encoded_public_key,
        encoded_secret_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_deterministic() {
        let msk = [0x42u8; MASTER_SECRET_LEN];
        let (_, pk_a) = keygen(&msk);
        let (_, pk_b) = keygen(&msk);
        assert_eq!(pk_a.pk_enc, pk_b.pk_enc);
        assert_eq!(pk_a.pk_sig, pk_b.pk_sig);
        assert_eq!(pk_a.key_id, pk_b.key_id);
        assert_eq!(pk_a.rho_shared, pk_b.rho_shared);
    }

    #[test]
    fn keygen_different_msk_different_keys() {
        let (_, pk_a) = keygen(&[0x01u8; MASTER_SECRET_LEN]);
        let (_, pk_b) = keygen(&[0x02u8; MASTER_SECRET_LEN]);
        assert_ne!(pk_a.pk_enc, pk_b.pk_enc);
        assert_ne!(pk_a.pk_sig, pk_b.pk_sig);
        assert_ne!(pk_a.key_id, pk_b.key_id);
    }

    #[test]
    fn pk_verify_consistency_passes_for_valid_key() {
        let (_, pk) = keygen(&[0xABu8; MASTER_SECRET_LEN]);
        assert!(pk.verify_consistency());
    }

    #[test]
    fn pk_verify_consistency_fails_for_tampered_key_id() {
        let (_, mut pk) = keygen(&[0x55u8; MASTER_SECRET_LEN]);
        pk.key_id[0] ^= 0xFF;
        assert!(!pk.verify_consistency());
    }

    #[test]
    fn pk_verify_consistency_fails_for_tampered_rho() {
        let (_, mut pk) = keygen(&[0x56u8; MASTER_SECRET_LEN]);
        pk.rho_shared[0] ^= 0x01;
        assert!(!pk.verify_consistency());
    }

    #[test]
    fn encoded_public_key_roundtrips() {
        let (_, pk) = keygen(&[0x33u8; MASTER_SECRET_LEN]);
        let mut encoded = [0u8; ENCODED_PUBLIC_KEY_SIZE];
        pk.encode_into(&mut encoded);
        let decoded = decode_public_key(&encoded).expect("decode succeeds");
        assert_eq!(decoded.key_id, pk.key_id);
        assert_eq!(decoded.rho_shared, pk.rho_shared);
        assert_eq!(decoded.pk_enc, pk.pk_enc);
        assert_eq!(decoded.pk_sig, pk.pk_sig);
        assert!(decoded.verify_consistency());
    }

    #[test]
    fn encoded_secret_key_roundtrips() {
        let (sk, pk) = keygen(&[0x44u8; MASTER_SECRET_LEN]);
        let mut encoded = [0u8; ENCODED_SECRET_KEY_SIZE];
        sk.encode_into(&pk, &mut encoded);
        let (decoded_sk, decoded_pk) = decode_secret_key(&encoded).expect("decode succeeds");
        assert_eq!(decoded_sk.matrix_seed, sk.matrix_seed);
        assert_eq!(decoded_sk.sk_enc_seed, sk.sk_enc_seed);
        assert_eq!(decoded_sk.sk_sig, sk.sk_sig);
        assert_eq!(decoded_pk.key_id, pk.key_id);
        assert_eq!(decoded_pk.rho_shared, pk.rho_shared);
        assert_eq!(decoded_pk.pk_enc, pk.pk_enc);
        assert_eq!(decoded_pk.pk_sig, pk.pk_sig);
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
