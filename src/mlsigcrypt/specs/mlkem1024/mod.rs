pub(crate) mod field;
pub(crate) mod hash;
pub(crate) mod keccak;
pub(crate) mod kem;
pub(crate) mod matrix;
pub(crate) mod ntt;
/// ML-KEM-1024 (FIPS 203) — pure-Rust, no_alloc, zeroizing implementation.
///
/// Public surface:
///   [`keygen`]  — generate an (EncapKey, DecapKey) pair
///   [`encaps`]  — encapsulate to produce (Ciphertext, SharedSecret)
///   [`decaps`]  — decapsulate to recover SharedSecret
///
/// Typed wrappers enforce that secrets are never accidentally copied:
///   [`EncapKey`], [`DecapKey`], [`Ciphertext`], [`SharedSecret`]
///
/// All secret types implement Drop with volatile-write zeroization.
///
/// # Example (pseudo-code)
/// ```rust,ignore
/// use crate::mlkem1024::{keygen, encaps, decaps};
///
/// let seed = get_random_bytes::<64>();
/// let (ek, dk) = {
///     let mut ek = EncapKey([0u8; EK_BYTES]);
///     let mut dk = DecapKey([0u8; DK_BYTES]);
///     keygen(&seed, &mut ek, &mut dk);
///     (ek, dk)
/// };
///
/// let entropy = get_random_bytes::<32>();
/// let (ct, ss_a) = {
///     let mut ct = Ciphertext([0u8; CT_BYTES]);
///     let mut ss = SharedSecret([0u8; 32]);
///     encaps(&ek, &entropy, &mut ct, &mut ss);
///     (ct, ss)
/// };
///
/// let ss_b = {
///     let mut ss = SharedSecret([0u8; 32]);
///     decaps(&dk, &ct, &mut ss);
///     ss
/// };
///
/// assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
/// ```
///
/// # Security notes
/// * `keygen` requires 64 bytes of uniform random (`d ‖ z`). Use a CSPRNG.
/// * `encaps` requires 32 bytes of uniform random. Use a CSPRNG.
/// * The caller is responsible for generating and securely erasing the random inputs.
/// * [`DecapKey`] and [`SharedSecret`] zeroize automatically on drop.
/// * All sensitive stack intermediates (s, e, r, σ, m) are explicitly zeroized
///   inside `keygen`, `encaps`, and `decaps` before returning.
/// * The SHAKE-128 sponge used for matrix generation is zeroized after each row.
/// * Decaps performs a constant-time ciphertext comparison to prevent oracle attacks.
// ── Sub-modules ───────────────────────────────────────────────────────────────
pub(crate) mod params;
pub(crate) mod poly;
pub(crate) mod sampling;
pub(crate) mod serialize;
pub(crate) mod vec;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub(crate) use kem::{Ciphertext, DecapKey, EncapKey, SharedSecret};
pub(crate) use params::{CT_BYTES, DK_BYTES, EK_BYTES, KEYGEN_SEED_BYTES, SS_BYTES};

// ── Top-level API ─────────────────────────────────────────────────────────────

/// Generate an ML-KEM-1024 key pair.
///
/// `seed` must be exactly 64 bytes of cryptographically uniform randomness:
/// the first 32 bytes seed the K-PKE key generation, the last 32 bytes become
/// the implicit-rejection secret z stored in the decapsulation key.
///
/// Use a hardware RNG or OS entropy source (e.g. `getrandom`) to fill `seed`.
/// Never reuse the same seed for two key pairs.
#[inline]
pub(crate) fn keygen(seed: &[u8; KEYGEN_SEED_BYTES], ek: &mut EncapKey, dk: &mut DecapKey) {
    kem::keygen(seed, ek, dk);
}

/// Generate an ML-KEM-1024 key pair using a caller-supplied public matrix seed.
///
/// This is used by MLSigcrypt-v2 level 2 so the KEM and DSA keys share the
/// same matrix `ρ`.
#[inline]
pub(crate) fn keygen_with_rho(
    seed: &[u8; KEYGEN_SEED_BYTES],
    rho: &[u8; 32],
    ek: &mut EncapKey,
    dk: &mut DecapKey,
) {
    kem::keygen_with_rho(seed, rho, ek, dk);
}

/// Encapsulate to the holder of `ek`.
///
/// `entropy` must be 32 bytes of uniform randomness.
/// Returns the ciphertext in `ct` and the shared secret in `ss`.
///
/// The same shared secret will be recovered by the key holder via [`decaps`].
#[inline]
pub(crate) fn encaps(
    ek: &EncapKey,
    entropy: &[u8; 32],
    ct: &mut Ciphertext,
    ss: &mut SharedSecret,
) {
    kem::encaps(ek, entropy, ct, ss);
}

/// Decapsulate `ct` using the decapsulation key `dk`.
///
/// Always returns exactly 32 bytes in `ss`. If the ciphertext is invalid or
/// was tampered with, the output is an unpredictable but deterministic function
/// of the implicit rejection secret z (implicit rejection / Fujisaki-Okamoto).
///
/// Timing is constant with respect to whether decapsulation succeeds.
#[inline]
pub(crate) fn decaps(dk: &DecapKey, ct: &Ciphertext, ss: &mut SharedSecret) {
    kem::decaps(dk, ct, ss);
}
