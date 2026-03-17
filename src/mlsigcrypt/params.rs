//! MLSigcrypt-v1 parameter constants.
//!
//! All sizes, offsets, and identifiers for the protocol are defined here.
//! No numeric literals should appear in other module files.

// ── Algorithm identity ────────────────────────────────────────────────────────

/// Protocol identifier string, ASCII, no null terminator.
pub(super) const ALG_ID: &[u8] = b"MLSigcrypt-v1";

/// Byte length of ALG_ID.
pub(super) const ALG_ID_LEN: usize = 13;

/// Protocol version byte.
pub(super) const VERSION: u8 = 0x01;

// ── Key sizes ─────────────────────────────────────────────────────────────────

/// Master secret seed length (bytes).
pub(crate) const MASTER_SECRET_LEN: usize = 32;

/// Key-identifier length: Truncate32(SHA3-512(label || pk_enc || pk_sig)).
pub(crate) const KEY_ID_LEN: usize = 32;

// ── Hash / KDF output sizes ───────────────────────────────────────────────────

/// SHA3-512 output length (bytes).
pub(super) const SHA3_512_OUT: usize = crate::mlsigcrypt::specs::sha3_512::OUTPUT_LEN;

/// aad_digest length: SHA3-512("MLSigcrypt-v1/aad" || aad).
pub(super) const AAD_DIGEST_LEN: usize = 64;

/// Transcript hash length T.
pub(super) const TRANSCRIPT_LEN: usize = 64;

// ── Session key sizes ─────────────────────────────────────────────────────────

/// AES-256-GCM key length.
pub(super) const K_AEAD_LEN: usize = 32;

/// Nonce-derivation material K_nonce length.
pub(super) const K_NONCE_LEN: usize = 64;

// ── AEAD sizes ────────────────────────────────────────────────────────────────

/// AES-256-GCM nonce length (96 bits).
pub(super) const NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length.
pub(super) const TAG_LEN: usize = 16;

// ── Primitive sizes (re-derived from sub-modules to avoid magic numbers) ──────

/// ML-KEM-1024 encapsulation key size.
pub(crate) const KEM_EK_LEN: usize = crate::mlsigcrypt::specs::mlkem1024::EK_BYTES; // 1568

/// ML-KEM-1024 decapsulation key size.
pub(crate) const KEM_DK_LEN: usize = crate::mlsigcrypt::specs::mlkem1024::DK_BYTES; // 3168

/// ML-KEM-1024 ciphertext size.
pub(crate) const KEM_CT_LEN: usize = crate::mlsigcrypt::specs::mlkem1024::CT_BYTES; // 1568

/// ML-KEM-1024 shared secret size.
pub(super) const KEM_SS_LEN: usize = crate::mlsigcrypt::specs::mlkem1024::SS_BYTES; // 32

/// ML-DSA-87 public key size.
pub(crate) const SIG_PK_LEN: usize = crate::mlsigcrypt::specs::mldsa87::PK_BYTES; // 2592

/// ML-DSA-87 secret key size.
pub(crate) const SIG_SK_LEN: usize = crate::mlsigcrypt::specs::mldsa87::SK_BYTES; // 4896

/// ML-DSA-87 signature size.
pub(crate) const SIG_LEN: usize = crate::mlsigcrypt::specs::mldsa87::SIG_BYTES; // 4627

// ── Packet wire-format layout ─────────────────────────────────────────────────
//
// Byte layout (fixed-width fields first, variable ct in the middle):
//
//   [0  ..13 ) alg_id         13 bytes  ALG_ID
//   [13 ..14 ) version         1 byte   VERSION
//   [14 ..46 ) key_id_S       32 bytes
//   [46 ..78 ) key_id_R       32 bytes
//   [78 ..1646) kem_ct       1568 bytes  ML-KEM-1024 ciphertext
//   [1646..1654) ct_len        8 bytes  u64 big-endian
//   [1654..1654+N) ct          N bytes  AES-256-GCM ciphertext
//   [1654+N..1670+N) tag      16 bytes  AES-256-GCM tag
//   [1670+N..6297+N) sig    4627 bytes  ML-DSA-87 signature
//
// Fixed overhead (everything except ct): 6297 bytes.

pub(crate) const PKT_ALG_ID_OFF: usize = 0;
pub(crate) const PKT_VERSION_OFF: usize = PKT_ALG_ID_OFF + ALG_ID_LEN; // 13
pub(crate) const PKT_KEY_ID_S_OFF: usize = PKT_VERSION_OFF + 1; // 14
pub(crate) const PKT_KEY_ID_R_OFF: usize = PKT_KEY_ID_S_OFF + KEY_ID_LEN; // 46
pub(crate) const PKT_KEM_CT_OFF: usize = PKT_KEY_ID_R_OFF + KEY_ID_LEN; // 78
pub(crate) const PKT_CT_LEN_OFF: usize = PKT_KEM_CT_OFF + KEM_CT_LEN; // 1646
pub(crate) const PKT_CT_OFF: usize = PKT_CT_LEN_OFF + 8; // 1654
// tag and sig offsets are PKT_CT_OFF + ct_len and PKT_CT_OFF + ct_len + TAG_LEN respectively.

/// Fixed per-packet overhead in bytes (excluding the variable-length ciphertext).
pub(crate) const PACKET_FIXED_OVERHEAD: usize =
    ALG_ID_LEN + 1 + KEY_ID_LEN + KEY_ID_LEN + KEM_CT_LEN + 8 + TAG_LEN + SIG_LEN;

// ── Compile-time sanity checks ────────────────────────────────────────────────

const _: () = {
    assert!(ALG_ID.len() == ALG_ID_LEN, "ALG_ID_LEN mismatch");
    assert!(
        PACKET_FIXED_OVERHEAD == 6297,
        "PACKET_FIXED_OVERHEAD must be 6297"
    );
    assert!(KEM_EK_LEN == 1568, "KEM_EK_LEN must be 1568");
    assert!(KEM_CT_LEN == 1568, "KEM_CT_LEN must be 1568");
    assert!(SIG_PK_LEN == 2592, "SIG_PK_LEN must be 2592");
    assert!(SIG_SK_LEN == 4896, "SIG_SK_LEN must be 4896");
    assert!(SIG_LEN == 4627, "SIG_LEN must be 4627");
    assert!(
        PKT_CT_OFF == 1654,
        "PKT_CT_OFF (fixed header width) must be 1654"
    );
};
