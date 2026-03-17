/// SHA3 and SHAKE hash functions required by ML-KEM (FIPS 203 §4).
///
/// All built over `keccak::KeccakSponge`. No state escapes into heap.
/// Sponges over sensitive data are explicitly zeroized before returning.
///
/// Function mapping (FIPS 203 §4.1):
///   H(m)      = SHA3-256(m)      — 32-byte digest
///   G(m)      = SHA3-512(m)      — 64-byte digest, split into (ρ/K, σ/K')
///   J(m, len) = SHAKE-256(m)     — variable-length XOF, 32 bytes for implicit rejection
///   PRF(σ, b) = SHAKE-256(σ‖b)  — variable-length XOF for CBD input
///   XOF(ρ,i,j)= SHAKE-128(ρ‖i‖j)— matrix row expansion
use crate::mlsigcrypt::specs::mlkem1024::keccak::{KeccakSponge, zeroize_sponge};

// ── Rate constants ────────────────────────────────────────────────────────────

/// Sponge rate in bytes for SHA3-256 and SHAKE-256.
const RATE_136: usize = 136; // 1088 bits / 8
/// Sponge rate in bytes for SHA3-512.
const RATE_72: usize = 72; // 576 bits / 8
/// Sponge rate in bytes for SHAKE-128.
const RATE_168: usize = 168; // 1344 bits / 8

/// Domain separation suffix for SHA3 functions.
const SHA3_SUFFIX: u8 = 0x06;
/// Domain separation suffix for SHAKE XOFs.
const SHAKE_SUFFIX: u8 = 0x1F;

// ── SHA3-256 ──────────────────────────────────────────────────────────────────

/// H(m) = SHA3-256(m). Produces a 32-byte digest.
///
/// Used for H(ek) in ML-KEM KeyGen and as the hash-of-ciphertext check in Decaps.
#[inline]
pub(crate) fn sha3_256(data: &[u8], out: &mut [u8; 32]) {
    let mut s: KeccakSponge<RATE_136> = KeccakSponge::new();
    s.absorb(data);
    s.finalize(SHA3_SUFFIX);
    s.squeeze(out);
    // SHA3-256 input is not secret in these call sites, but be defensive.
    zeroize_sponge(&mut s);
}

/// Streaming SHA3-256: absorb two slices without concatenating them in a buffer.
#[inline]
pub(crate) fn sha3_256_x2(a: &[u8], b: &[u8], out: &mut [u8; 32]) {
    let mut s: KeccakSponge<RATE_136> = KeccakSponge::new();
    s.absorb(a);
    s.absorb(b);
    s.finalize(SHA3_SUFFIX);
    s.squeeze(out);
    zeroize_sponge(&mut s);
}

// ── SHA3-512 ──────────────────────────────────────────────────────────────────

/// G(m) = SHA3-512(m). Produces a 64-byte digest.
///
/// Used in K-PKE.KeyGen to split seed into (ρ, σ) and in Encaps to derive (K, r).
/// Input may contain secret seed material; sponge is zeroized after use.
#[inline]
pub(crate) fn sha3_512(data: &[u8], out: &mut [u8; 64]) {
    let mut s: KeccakSponge<RATE_72> = KeccakSponge::new();
    s.absorb(data);
    s.finalize(SHA3_SUFFIX);
    s.squeeze(out);
    zeroize_sponge(&mut s);
}

/// Streaming SHA3-512: absorb two slices without a temporary concatenation buffer.
/// Typical call: sha3_512_x2(m, &[K as u8], out) for K-PKE.KeyGen.
#[inline]
pub(crate) fn sha3_512_x2(a: &[u8], b: &[u8], out: &mut [u8; 64]) {
    let mut s: KeccakSponge<RATE_72> = KeccakSponge::new();
    s.absorb(a);
    s.absorb(b);
    s.finalize(SHA3_SUFFIX);
    s.squeeze(out);
    zeroize_sponge(&mut s);
}

// ── SHAKE-256 ─────────────────────────────────────────────────────────────────

/// J(m) = SHAKE-256(m, 32 bytes). Variable-length XOF, here fixed to 32 bytes.
///
/// Used for implicit rejection key: J(z ‖ c).
#[inline]
pub(crate) fn shake256_32(data: &[u8], out: &mut [u8; 32]) {
    let mut s: KeccakSponge<RATE_136> = KeccakSponge::new();
    s.absorb(data);
    s.finalize(SHAKE_SUFFIX);
    s.squeeze(out);
    zeroize_sponge(&mut s);
}

/// Streaming SHAKE-256 producing exactly `out.len()` bytes.
/// Used by PRF(σ, b) = SHAKE-256(σ ‖ b, 64*η bytes) for CBD input.
#[inline]
pub(crate) fn shake256_prf(sigma: &[u8; 32], b: u8, out: &mut [u8]) {
    let mut s: KeccakSponge<RATE_136> = KeccakSponge::new();
    s.absorb(sigma);
    s.absorb(core::slice::from_ref(&b));
    s.finalize(SHAKE_SUFFIX);
    s.squeeze(out);
    zeroize_sponge(&mut s);
}

/// Two-slice streaming SHAKE-256 for cases like J(z ‖ c) without allocation.
#[inline]
pub(crate) fn shake256_x2(a: &[u8], b: &[u8], out: &mut [u8]) {
    let mut s: KeccakSponge<RATE_136> = KeccakSponge::new();
    s.absorb(a);
    s.absorb(b);
    s.finalize(SHAKE_SUFFIX);
    s.squeeze(out);
    zeroize_sponge(&mut s);
}

// ── SHAKE-128 ─────────────────────────────────────────────────────────────────

/// XOF for matrix generation: XOF(ρ ‖ j ‖ i) = SHAKE-128(ρ, j, i; ∞).
///
/// Returns a configured, finalised sponge ready for repeated `squeeze()` calls.
/// The caller is responsible for zeroizing the returned sponge after use.
///
/// Why return a sponge rather than a fixed buffer? Matrix generation performs
/// rejection sampling; the exact number of bytes needed is data-dependent.
/// We avoid over-generating into a large stack buffer by squeezing on demand.
#[inline]
pub(crate) fn shake128_xof_init(rho: &[u8; 32], i: u8, j: u8) -> KeccakSponge<RATE_168> {
    let mut s: KeccakSponge<RATE_168> = KeccakSponge::new();
    s.absorb(rho);
    s.absorb(core::slice::from_ref(&i));
    s.absorb(core::slice::from_ref(&j));
    s.finalize(SHAKE_SUFFIX);
    s
}
