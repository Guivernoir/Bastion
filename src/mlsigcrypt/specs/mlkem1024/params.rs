//! ML-KEM-1024 parameters — FIPS 203, §2.
//!
//! Every numeric constant lives here. Nothing else does.
//! If a number appears in any other file without a `params::` prefix,
//! that is a tactical error and should be corrected.

// ── Module dimension ─────────────────────────────────────────────────────────

/// Rank k = 4 for ML-KEM-1024.
pub(crate) const K: usize = 4;

/// Polynomial degree. The ring is Z_q[X]/(X^256 + 1).
pub(crate) const N: usize = 256;

/// NTT size: N/2 factor pairs per polynomial.
pub(crate) const N_HALF: usize = N / 2;

// ── Prime modulus ─────────────────────────────────────────────────────────────

/// Prime modulus q = 3329.
pub(crate) const Q: u32 = 3329;
pub(crate) const Q16: i16 = 3329;
pub(crate) const Q32: i32 = 3329;

// ── Noise parameters ─────────────────────────────────────────────────────────

/// η₁ = 2: binomial distribution width for s and e in KeyGen.
pub(crate) const ETA1: usize = 2;

/// η₂ = 2: binomial distribution width for r, e₁, e₂ in Encaps.
pub(crate) const ETA2: usize = 2;

/// PRF output bytes for a single CBD-η1 polynomial: 64*η1.
pub(crate) const ETA1_PRF_BYTES: usize = 64 * ETA1; // 128

/// PRF output bytes for a single CBD-η2 polynomial: 64*η2.
pub(crate) const ETA2_PRF_BYTES: usize = 64 * ETA2; // 128 (same for η1=η2=2)

// ── Compression bit-widths ────────────────────────────────────────────────────

/// d_u = 11: bits per coefficient in the u ciphertext component.
pub(crate) const DU: usize = 11;

/// d_v = 5: bits per coefficient in the v ciphertext component.
pub(crate) const DV: usize = 5;

// ── Serialised sizes in bytes ─────────────────────────────────────────────────

/// Bytes for a single 12-bit-per-coefficient encoded polynomial.
/// Used for keys: 256 × 12 / 8 = 384.
pub(crate) const POLY_BYTES: usize = N * 12 / 8; // 384

/// Bytes for a K-vector of 12-bit-packed polynomials.
pub(crate) const POLYVEC_BYTES: usize = K * POLY_BYTES; // 1536

/// Bytes for a single polynomial compressed to d_u bits.
pub(crate) const POLY_COMPRESSED_U: usize = N * DU / 8; // 352

/// Bytes for a single polynomial compressed to d_v bits.
pub(crate) const POLY_COMPRESSED_V: usize = N * DV / 8; // 160

/// Bytes for the u component of a ciphertext (K compressed polys).
pub(crate) const POLYVEC_COMPRESSED_U: usize = K * POLY_COMPRESSED_U; // 1408

// ── Key and ciphertext sizes ──────────────────────────────────────────────────

/// Size of the K-PKE decryption key: ByteEncode₁₂(ŝ).
pub(crate) const DK_PKE_BYTES: usize = POLYVEC_BYTES; // 1536

/// Size of the K-PKE encryption key: ByteEncode₁₂(t̂) ‖ ρ.
pub(crate) const EK_PKE_BYTES: usize = POLYVEC_BYTES + 32; // 1568

/// ML-KEM encapsulation key size = EK_PKE_BYTES.
pub(crate) const EK_BYTES: usize = EK_PKE_BYTES; // 1568

/// ML-KEM decapsulation key: dk_pke ‖ ek_pke ‖ H(ek) ‖ z.
pub(crate) const DK_BYTES: usize = DK_PKE_BYTES + EK_PKE_BYTES + 32 + 32; // 3168

/// Ciphertext: c₁ ‖ c₂ = ByteEncode_du(Compress_du(u)) ‖ ByteEncode_dv(Compress_dv(v)).
pub(crate) const CT_BYTES: usize = POLYVEC_COMPRESSED_U + POLY_COMPRESSED_V; // 1568

/// Shared-secret size.
pub(crate) const SS_BYTES: usize = 32;

/// Seed / randomness sizes.
pub(crate) const SEED_BYTES: usize = 32;
pub(crate) const KEYGEN_SEED_BYTES: usize = 64; // d ‖ z for KeyGen

// ── Byte offsets within the decapsulation key ─────────────────────────────────

pub(crate) const DK_OFFSET_DK_PKE: usize = 0;
pub(crate) const DK_OFFSET_EK_PKE: usize = DK_PKE_BYTES;
pub(crate) const DK_OFFSET_H: usize = DK_PKE_BYTES + EK_PKE_BYTES;
pub(crate) const DK_OFFSET_Z: usize = DK_PKE_BYTES + EK_PKE_BYTES + 32;

// ── Byte offsets within the encapsulation key (= K-PKE ek) ────────────────────

pub(crate) const EK_OFFSET_T_HAT: usize = 0;
pub(crate) const EK_OFFSET_RHO: usize = POLYVEC_BYTES;

// ── Byte offsets within the ciphertext ───────────────────────────────────────

pub(crate) const CT_OFFSET_C1: usize = 0;
pub(crate) const CT_OFFSET_C2: usize = POLYVEC_COMPRESSED_U;

// ── Sanity assertions (checked at compile time) ────────────────────────────────

const _: () = {
    assert!(DK_BYTES == 3168, "DK_BYTES must be 3168 for ML-KEM-1024");
    assert!(EK_BYTES == 1568, "EK_BYTES must be 1568 for ML-KEM-1024");
    assert!(CT_BYTES == 1568, "CT_BYTES must be 1568 for ML-KEM-1024");
    assert!(SS_BYTES == 32, "SS_BYTES must be 32");
    assert!(DK_OFFSET_Z + SEED_BYTES == DK_BYTES, "DK layout overflow");
};
