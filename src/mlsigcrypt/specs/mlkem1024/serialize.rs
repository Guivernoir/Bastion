/// Byte serialisation for ML-KEM keys and ciphertext.
///
/// Key material uses 12-bit/coefficient encoding (POLY_BYTES = 384 per polynomial).
/// Ciphertext u component uses d_u=11 bits/coefficient, v uses d_v=5 bits.
///
/// These are thin wrappers over `poly.rs` primitives, providing the typed
/// byte-slice views that `kem.rs` needs without raw pointer arithmetic there.
use crate::mlsigcrypt::specs::mlkem1024::params::{
    CT_OFFSET_C1, CT_OFFSET_C2, DK_PKE_BYTES, EK_BYTES, EK_OFFSET_RHO, EK_OFFSET_T_HAT,
    POLY_COMPRESSED_V, POLYVEC_BYTES, POLYVEC_COMPRESSED_U,
};
use crate::mlsigcrypt::specs::mlkem1024::poly::Poly;
use crate::mlsigcrypt::specs::mlkem1024::vec::PolyVec;

// ── PolyVec serialisation (key material) ─────────────────────────────────────

/// Encode K polynomials into 1536 bytes (12 bits/coefficient, big-endian packing).
/// Used for: ŝ → dk_pke, t̂ → ek_pke prefix.
#[inline]
pub(crate) fn encode_polyvec12(v: &PolyVec, out: &mut [u8; POLYVEC_BYTES]) {
    v.encode12(out);
}

/// Decode 1536 bytes into K polynomials.
/// Used for loading ŝ from dk_pke, t̂ from ek_pke prefix.
#[inline]
pub(crate) fn decode_polyvec12(bytes: &[u8; POLYVEC_BYTES], v: &mut PolyVec) {
    v.decode12(bytes);
}

// ── Encapsulation key (ek) encode/decode ─────────────────────────────────────

/// Build the 1568-byte encapsulation key: ByteEncode₁₂(t̂) ‖ ρ.
///
/// Layout: ek[0..1536] = encoded t̂, ek[1536..1568] = ρ.
pub(crate) fn encode_ek(t_hat: &PolyVec, rho: &[u8; 32], ek: &mut [u8; EK_BYTES]) {
    // Encode t̂ into the first POLYVEC_BYTES.
    let t_hat_slice: &mut [u8; POLYVEC_BYTES] = unsafe {
        // SAFETY: EK_BYTES = POLYVEC_BYTES + 32; the first POLYVEC_BYTES bytes are in range.
        &mut *(ek.as_mut_ptr().add(EK_OFFSET_T_HAT) as *mut [u8; POLYVEC_BYTES])
    };
    encode_polyvec12(t_hat, t_hat_slice);

    // Copy ρ into the final 32 bytes.
    ek[EK_OFFSET_RHO..].copy_from_slice(rho);
}

/// Decode the encapsulation key: t̂ and ρ.
pub(crate) fn decode_ek(ek: &[u8; EK_BYTES], t_hat: &mut PolyVec, rho: &mut [u8; 32]) {
    let t_hat_bytes: &[u8; POLYVEC_BYTES] = unsafe {
        // SAFETY: same layout as above.
        &*(ek.as_ptr().add(EK_OFFSET_T_HAT) as *const [u8; POLYVEC_BYTES])
    };
    decode_polyvec12(t_hat_bytes, t_hat);
    rho.copy_from_slice(&ek[EK_OFFSET_RHO..]);
}

// ── Decapsulation key (dk_pke) encode/decode ─────────────────────────────────

/// Encode ŝ as the 1536-byte K-PKE decryption key.
pub(crate) fn encode_dk_pke(s_hat: &PolyVec, dk_pke: &mut [u8; DK_PKE_BYTES]) {
    encode_polyvec12(s_hat, dk_pke);
}

/// Decode ŝ from the K-PKE decryption key.
pub(crate) fn decode_dk_pke(dk_pke: &[u8; DK_PKE_BYTES], s_hat: &mut PolyVec) {
    decode_polyvec12(dk_pke, s_hat);
}

// ── Ciphertext encode/decode ──────────────────────────────────────────────────

/// Encode the u vector (K polynomials compressed to d_u bits): 1408 bytes.
pub(crate) fn encode_u(u: &PolyVec, out: &mut [u8; POLYVEC_COMPRESSED_U]) {
    u.compress_du(out);
}

/// Decode the u vector.
pub(crate) fn decode_u(bytes: &[u8; POLYVEC_COMPRESSED_U], u: &mut PolyVec) {
    u.decompress_du(bytes);
}

/// Encode the v polynomial compressed to d_v bits: 160 bytes.
pub(crate) fn encode_v(v: &Poly, out: &mut [u8; POLY_COMPRESSED_V]) {
    v.compress_dv(out);
}

/// Decode the v polynomial.
pub(crate) fn decode_v(bytes: &[u8; POLY_COMPRESSED_V], v: &mut Poly) {
    v.decompress_dv(bytes);
}

// ── Typed views into byte buffers ─────────────────────────────────────────────
//
// These helpers let kem.rs treat raw byte arrays as typed sub-slices
// without unsafe pointer arithmetic at the call site.

/// Borrow the 1536-byte t̂ portion of an encapsulation key.
#[inline]
pub(crate) fn ek_t_hat_bytes(ek: &[u8; EK_BYTES]) -> &[u8; POLYVEC_BYTES] {
    // SAFETY: layout: ek[0..1536] is t̂; POLYVEC_BYTES == 1536.
    unsafe { &*(ek.as_ptr().add(EK_OFFSET_T_HAT) as *const [u8; POLYVEC_BYTES]) }
}

/// Borrow the 32-byte ρ portion of an encapsulation key.
#[inline]
pub(crate) fn ek_rho(ek: &[u8; EK_BYTES]) -> &[u8; 32] {
    // SAFETY: layout: ek[1536..1568] is ρ.
    unsafe { &*(ek.as_ptr().add(EK_OFFSET_RHO) as *const [u8; 32]) }
}

/// Borrow the c1 portion of a ciphertext (1408 bytes).
#[inline]
pub(crate) fn ct_c1(
    ct: &[u8; crate::mlsigcrypt::specs::mlkem1024::params::CT_BYTES],
) -> &[u8; POLYVEC_COMPRESSED_U] {
    unsafe { &*(ct.as_ptr().add(CT_OFFSET_C1) as *const [u8; POLYVEC_COMPRESSED_U]) }
}

/// Borrow the c2 portion of a ciphertext (160 bytes).
#[inline]
pub(crate) fn ct_c2(
    ct: &[u8; crate::mlsigcrypt::specs::mlkem1024::params::CT_BYTES],
) -> &[u8; POLY_COMPRESSED_V] {
    unsafe { &*(ct.as_ptr().add(CT_OFFSET_C2) as *const [u8; POLY_COMPRESSED_V]) }
}

/// Mutable borrow of c1.
#[inline]
pub(crate) fn ct_c1_mut(
    ct: &mut [u8; crate::mlsigcrypt::specs::mlkem1024::params::CT_BYTES],
) -> &mut [u8; POLYVEC_COMPRESSED_U] {
    unsafe { &mut *(ct.as_mut_ptr().add(CT_OFFSET_C1) as *mut [u8; POLYVEC_COMPRESSED_U]) }
}

/// Mutable borrow of c2.
#[inline]
pub(crate) fn ct_c2_mut(
    ct: &mut [u8; crate::mlsigcrypt::specs::mlkem1024::params::CT_BYTES],
) -> &mut [u8; POLY_COMPRESSED_V] {
    unsafe { &mut *(ct.as_mut_ptr().add(CT_OFFSET_C2) as *mut [u8; POLY_COMPRESSED_V]) }
}
