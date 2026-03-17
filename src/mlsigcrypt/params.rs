//! MLSigcrypt-v3 level-3 parameter constants.
//!
//! Level 3 replaces the level-2 ML-KEM packet component with an algebraic
//! encapsulation derived from the signing mask. The public API is unchanged,
//! but both the key format and packet layout are different from earlier levels.

/// Protocol identifier string, ASCII, no null terminator.
pub(super) const ALG_ID: &[u8] = b"MLSigcrypt-v3";

/// Byte length of ALG_ID.
pub(super) const ALG_ID_LEN: usize = 13;

/// Protocol version byte.
pub(super) const VERSION: u8 = 0x03;

/// SHAKE-256 rate in bytes.
pub(super) const SHAKE256_RATE: usize = 136;

/// SHAKE domain-separation suffix.
pub(super) const SHAKE_SUFFIX: u8 = 0x1F;

/// Challenge sponge domain separator.
pub(super) const DOMAIN_CHAL: &[u8] = b"MLSigcrypt-v3/chal\x03";

/// Encryption sponge domain separator.
pub(super) const DOMAIN_ENC: &[u8] = b"MLSigcrypt-v3/enc\x03";

/// AAD normalization domain separator.
pub(super) const DOMAIN_AAD: &[u8] = b"MLSigcrypt-v3/aad\x03";

/// Master secret seed length (bytes).
pub(crate) const MASTER_SECRET_LEN: usize = 32;

/// Key-identifier length.
pub(crate) const KEY_ID_LEN: usize = 32;

/// Shared matrix seed length.
pub(crate) const MATRIX_SEED_LEN: usize = 32;

/// Encapsulation seed length.
pub(crate) const SK_ENC_SEED_LEN: usize = crate::mlsigcrypt::specs::algebraic::SECRET_SEED_BYTES;

/// SHA3-512 output length.
pub(super) const SHA3_512_OUT: usize = crate::mlsigcrypt::specs::sha512::SHA3_512_OUTPUT_LEN;

/// AAD digest length.
pub(super) const AAD_DIGEST_LEN: usize = 64;

/// ML-DSA-87 verification key size.
pub(crate) const SIG_PK_LEN: usize = crate::mlsigcrypt::specs::ml::PK_BYTES;

/// ML-DSA-87 signing key size.
pub(crate) const SIG_SK_LEN: usize = crate::mlsigcrypt::specs::ml::SK_BYTES;

/// Exact encoded recipient encapsulation public key size.
pub(crate) const ENC_PK_LEN: usize = crate::mlsigcrypt::specs::algebraic::PUBLIC_KEY_BYTES;

/// Exact encoded algebraic encapsulation packet field size.
pub(crate) const ENCAP_LEN: usize = crate::mlsigcrypt::specs::algebraic::ENCAP_BYTES;

/// ML-DSA commitment hash size.
pub(crate) const SIG_CTILDE_LEN: usize = crate::mlsigcrypt::specs::ml::params::LAMBDA2_BYTES;

/// ML-DSA z-vector size.
pub(crate) const SIG_Z_LEN: usize =
    crate::mlsigcrypt::specs::ml::params::L * crate::mlsigcrypt::specs::ml::params::POLYZ_BYTES;

/// ML-DSA hint size.
pub(crate) const SIG_HINT_LEN: usize =
    crate::mlsigcrypt::specs::ml::params::OMEGA + crate::mlsigcrypt::specs::ml::params::K;

/// Packet layout offsets.
pub(crate) const PKT_ALG_ID_OFF: usize = 0;
pub(crate) const PKT_VERSION_OFF: usize = PKT_ALG_ID_OFF + ALG_ID_LEN; // 13
pub(crate) const PKT_KEY_ID_S_OFF: usize = PKT_VERSION_OFF + 1; // 14
pub(crate) const PKT_KEY_ID_R_OFF: usize = PKT_KEY_ID_S_OFF + KEY_ID_LEN; // 46
pub(crate) const PKT_ENCAP_OFF: usize = PKT_KEY_ID_R_OFF + KEY_ID_LEN; // 78
pub(crate) const PKT_Z_OFF: usize = PKT_ENCAP_OFF + ENCAP_LEN;
pub(crate) const PKT_CTILDE_OFF: usize = PKT_Z_OFF + SIG_Z_LEN;
pub(crate) const PKT_HINT_OFF: usize = PKT_CTILDE_OFF + SIG_CTILDE_LEN;
pub(crate) const PKT_CT_LEN_OFF: usize = PKT_HINT_OFF + SIG_HINT_LEN;
pub(crate) const PKT_CT_OFF: usize = PKT_CT_LEN_OFF + 8;

/// Fixed per-packet overhead in bytes (excluding the variable-length ciphertext).
pub(crate) const PACKET_FIXED_OVERHEAD: usize = ALG_ID_LEN
    + 1
    + KEY_ID_LEN
    + KEY_ID_LEN
    + ENCAP_LEN
    + SIG_Z_LEN
    + SIG_CTILDE_LEN
    + SIG_HINT_LEN
    + 8;

const _: () = {
    assert!(ALG_ID.len() == ALG_ID_LEN, "ALG_ID_LEN mismatch");
    assert!(ENC_PK_LEN == 2944, "ENC_PK_LEN must be 2944");
    assert!(ENCAP_LEN == 2944, "ENCAP_LEN must be 2944");
    assert!(SIG_PK_LEN == 2592, "SIG_PK_LEN must be 2592");
    assert!(SIG_SK_LEN == 4896, "SIG_SK_LEN must be 4896");
    assert!(SIG_Z_LEN == 4480, "SIG_Z_LEN must be 4480");
    assert!(SIG_CTILDE_LEN == 64, "SIG_CTILDE_LEN must be 64");
    assert!(SIG_HINT_LEN == 83, "SIG_HINT_LEN must be 83");
    assert!(
        PACKET_FIXED_OVERHEAD == 7657,
        "PACKET_FIXED_OVERHEAD must be 7657"
    );
    assert!(PKT_CT_OFF == 7657, "PKT_CT_OFF must be 7657");
};
