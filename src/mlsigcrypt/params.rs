//! MLSigcrypt-v2 level-2 parameter constants.
//!
//! The packet format remains the same as MLSigcrypt-v2 level 1; the level-2
//! change is the shared-matrix key hierarchy used by key generation.

/// Protocol identifier string, ASCII, no null terminator.
pub(super) const ALG_ID: &[u8] = b"MLSigcrypt-v2";

/// Byte length of ALG_ID.
pub(super) const ALG_ID_LEN: usize = 13;

/// Protocol version byte.
pub(super) const VERSION: u8 = 0x02;

/// SHAKE-256 rate in bytes.
pub(super) const SHAKE256_RATE: usize = 136;

/// SHAKE domain-separation suffix.
pub(super) const SHAKE_SUFFIX: u8 = 0x1F;

/// Transcript sponge domain separator.
pub(super) const DOMAIN_TRANSCRIPT: &[u8] = b"MLSigcrypt-v2/transcript\x02";

/// Encryption sponge domain separator.
pub(super) const DOMAIN_ENC: &[u8] = b"MLSigcrypt-v2/enc\x02";

/// AAD normalization domain separator.
pub(super) const DOMAIN_AAD: &[u8] = b"MLSigcrypt-v2/aad\x02";

/// Master secret seed length (bytes).
pub(crate) const MASTER_SECRET_LEN: usize = 32;

/// Key-identifier length.
pub(crate) const KEY_ID_LEN: usize = 32;

/// SHA3-512 output length.
pub(super) const SHA3_512_OUT: usize = crate::mlsigcrypt::specs::sha3_512::OUTPUT_LEN;

/// AAD digest length.
pub(super) const AAD_DIGEST_LEN: usize = 64;

/// Transcript output length.
pub(super) const TRANSCRIPT_LEN: usize = 64;

/// ML-KEM-1024 encapsulation key size.
pub(crate) const KEM_EK_LEN: usize = crate::mlsigcrypt::specs::mlkem1024::EK_BYTES;

/// ML-KEM-1024 decapsulation key size.
pub(crate) const KEM_DK_LEN: usize = crate::mlsigcrypt::specs::mlkem1024::DK_BYTES;

/// ML-KEM-1024 ciphertext size.
pub(crate) const KEM_CT_LEN: usize = crate::mlsigcrypt::specs::mlkem1024::CT_BYTES;

/// ML-KEM-1024 shared secret size.
pub(super) const KEM_SS_LEN: usize = crate::mlsigcrypt::specs::mlkem1024::SS_BYTES;

/// ML-DSA-87 public key size.
pub(crate) const SIG_PK_LEN: usize = crate::mlsigcrypt::specs::mldsa87::PK_BYTES;

/// ML-DSA-87 secret key size.
pub(crate) const SIG_SK_LEN: usize = crate::mlsigcrypt::specs::mldsa87::SK_BYTES;

/// ML-DSA-87 signature size.
pub(crate) const SIG_LEN: usize = crate::mlsigcrypt::specs::mldsa87::SIG_BYTES;

/// Packet layout offsets.
pub(crate) const PKT_ALG_ID_OFF: usize = 0;
pub(crate) const PKT_VERSION_OFF: usize = PKT_ALG_ID_OFF + ALG_ID_LEN; // 13
pub(crate) const PKT_KEY_ID_S_OFF: usize = PKT_VERSION_OFF + 1; // 14
pub(crate) const PKT_KEY_ID_R_OFF: usize = PKT_KEY_ID_S_OFF + KEY_ID_LEN; // 46
pub(crate) const PKT_KEM_CT_OFF: usize = PKT_KEY_ID_R_OFF + KEY_ID_LEN; // 78
pub(crate) const PKT_CT_LEN_OFF: usize = PKT_KEM_CT_OFF + KEM_CT_LEN; // 1646
pub(crate) const PKT_CT_OFF: usize = PKT_CT_LEN_OFF + 8; // 1654

/// Fixed per-packet overhead in bytes (excluding the variable-length ciphertext).
pub(crate) const PACKET_FIXED_OVERHEAD: usize =
    ALG_ID_LEN + 1 + KEY_ID_LEN + KEY_ID_LEN + KEM_CT_LEN + 8 + SIG_LEN;

const _: () = {
    assert!(ALG_ID.len() == ALG_ID_LEN, "ALG_ID_LEN mismatch");
    assert!(
        PACKET_FIXED_OVERHEAD == 6281,
        "PACKET_FIXED_OVERHEAD must be 6281"
    );
    assert!(KEM_EK_LEN == 1568, "KEM_EK_LEN must be 1568");
    assert!(KEM_CT_LEN == 1568, "KEM_CT_LEN must be 1568");
    assert!(SIG_PK_LEN == 2592, "SIG_PK_LEN must be 2592");
    assert!(SIG_SK_LEN == 4896, "SIG_SK_LEN must be 4896");
    assert!(SIG_LEN == 4627, "SIG_LEN must be 4627");
    assert!(PKT_CT_OFF == 1654, "PKT_CT_OFF must be 1654");
};
