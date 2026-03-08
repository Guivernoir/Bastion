/// ML-KEM-1024 key generation, encapsulation, and decapsulation.
///
/// Implements FIPS 203 §6.1 (ML-KEM.KeyGen), §6.2 (ML-KEM.Encaps),
/// §6.3 (ML-KEM.Decaps) via the K-PKE sub-scheme in §5.
///
/// Security requirements enforced here:
///   • Decaps re-encrypts m' and compares ciphertexts in constant time.
///   • If ciphertext check fails, the implicit rejection key J(z‖c) is returned.
///   • All secret intermediates (s, e, r, m, seed derivatives) are zeroized.
///   • No branch on secret values.
use crate::algos::mlkem1024::hash::{sha3_256, sha3_512_x2, shake256_x2};
use crate::algos::mlkem1024::matrix::PolyMatrix;
use crate::algos::mlkem1024::params::{
    CT_BYTES, DK_BYTES, DK_OFFSET_DK_PKE, DK_OFFSET_EK_PKE, DK_OFFSET_H, DK_OFFSET_Z, DK_PKE_BYTES,
    EK_BYTES, EK_PKE_BYTES, K, KEYGEN_SEED_BYTES, SS_BYTES,
};
use crate::algos::mlkem1024::poly::{Poly, zeroize_poly};
use crate::algos::mlkem1024::sampling::{
    gen_matrix, sample_noise_eta2, sample_noise_vec_eta1, sample_noise_vec_eta2,
};
use crate::algos::mlkem1024::serialize::{
    ct_c1, ct_c1_mut, ct_c2, ct_c2_mut, decode_dk_pke, decode_ek, decode_u, decode_v,
    encode_dk_pke, encode_ek, encode_u, encode_v,
};
use crate::algos::mlkem1024::vec::{PolyVec, zeroize_polyvec};
use crate::constant_time::{ct_cmov_bytes, ct_eq_mask};
use crate::zeroize::zeroize_mem;

// ── Sensitive wrapper types ───────────────────────────────────────────────────

/// ML-KEM-1024 encapsulation key (1568 bytes).
/// Public; no zeroization required.
pub(crate) struct EncapKey(pub(crate) [u8; EK_BYTES]);

/// ML-KEM-1024 decapsulation key (3168 bytes).
/// Secret; zeroized on Drop.
pub(crate) struct DecapKey(pub(crate) [u8; DK_BYTES]);

/// ML-KEM-1024 shared secret (32 bytes).
/// Secret; zeroized on Drop.
pub(crate) struct SharedSecret(pub(crate) [u8; SS_BYTES]);

/// ML-KEM-1024 ciphertext (1568 bytes).
/// Public; no zeroization required.
pub(crate) struct Ciphertext(pub(crate) [u8; CT_BYTES]);

impl Drop for DecapKey {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid writable array.
        unsafe { zeroize_mem(self.0.as_mut_ptr(), self.0.len()) };
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid writable array.
        unsafe { zeroize_mem(self.0.as_mut_ptr(), self.0.len()) };
    }
}

impl EncapKey {
    pub(crate) fn as_bytes(&self) -> &[u8; EK_BYTES] {
        &self.0
    }
}
impl DecapKey {
    pub(crate) fn as_bytes(&self) -> &[u8; DK_BYTES] {
        &self.0
    }
}
impl SharedSecret {
    pub(crate) fn as_bytes(&self) -> &[u8; SS_BYTES] {
        &self.0
    }
}
impl Ciphertext {
    pub(crate) fn as_bytes(&self) -> &[u8; CT_BYTES] {
        &self.0
    }
}

// ── KeyGen ────────────────────────────────────────────────────────────────────

/// ML-KEM.KeyGen (FIPS 203 §6.1).
///
/// `seed` must be 64 bytes of uniform random: d ‖ z.
/// `d` (first 32 bytes) seeds the K-PKE key generation.
/// `z` (last 32 bytes) is stored as the implicit-rejection secret.
///
/// On return `ek` and `dk` are fully populated.
/// All secret intermediates are zeroized before returning.
pub(crate) fn keygen(seed: &[u8; KEYGEN_SEED_BYTES], ek: &mut EncapKey, dk: &mut DecapKey) {
    let d = &seed[..32];
    let z = &seed[32..];

    // ── K-PKE.KeyGen(d) ───────────────────────────────────────────────────────

    // 1. (ρ, σ) ← G(d ‖ k) where k = K as byte.
    let mut g_out = [0u8; 64];
    sha3_512_x2(d, &[K as u8], &mut g_out);
    let rho: &[u8; 32] = unsafe { &*(g_out.as_ptr() as *const [u8; 32]) };
    let sigma: &[u8; 32] = unsafe { &*(g_out.as_ptr().add(32) as *const [u8; 32]) };

    // 2. Generate public matrix A from ρ.
    let mut a_hat = PolyMatrix::zero();
    gen_matrix(&mut a_hat, rho, false); // A (not transposed)

    // 3. Sample secret vector s ← CBD_η1(σ, 0..K-1).
    let mut s = PolyVec::zero();
    sample_noise_vec_eta1(&mut s, sigma, 0);

    // 4. Sample error vector e ← CBD_η1(σ, K..2K-1).
    let mut e = PolyVec::zero();
    sample_noise_vec_eta1(&mut e, sigma, K as u8);

    // 5. ŝ ← NTT(s).
    s.ntt();

    // 6. ê ← NTT(e).
    e.ntt();

    // 7. t̂ = Â·ŝ + ê.
    let mut t_hat = PolyVec::zero();
    a_hat.matvec_ntt(&s, &mut t_hat);
    t_hat.add_reduce(&e);

    // ── Encode ek_pke ─────────────────────────────────────────────────────────

    // ek_pke = ByteEncode₁₂(t̂) ‖ ρ  → first EK_PKE_BYTES of dk, and into ek.
    let ek_pke_slice: &mut [u8; EK_BYTES] =
        unsafe { &mut *(ek.0.as_mut_ptr() as *mut [u8; EK_BYTES]) };
    encode_ek(&t_hat, rho, ek_pke_slice);

    // ── Encode dk ─────────────────────────────────────────────────────────────

    // dk = dk_pke ‖ ek_pke ‖ H(ek_pke) ‖ z

    // dk_pke = ByteEncode₁₂(ŝ) — NTT-domain secret key.
    let dk_pke_slice: &mut [u8; DK_PKE_BYTES] =
        unsafe { &mut *(dk.0.as_mut_ptr().add(DK_OFFSET_DK_PKE) as *mut [u8; DK_PKE_BYTES]) };
    encode_dk_pke(&s, dk_pke_slice);

    // Copy ek_pke into dk.
    dk.0[DK_OFFSET_EK_PKE..DK_OFFSET_EK_PKE + EK_PKE_BYTES].copy_from_slice(&ek.0);

    // H(ek_pke) — 32-byte hash of the encapsulation key.
    let h_out: &mut [u8; 32] =
        unsafe { &mut *(dk.0.as_mut_ptr().add(DK_OFFSET_H) as *mut [u8; 32]) };
    sha3_256(&ek.0, h_out);

    // z — implicit rejection secret.
    dk.0[DK_OFFSET_Z..DK_OFFSET_Z + 32].copy_from_slice(z);

    // ── Zeroize secrets ───────────────────────────────────────────────────────
    zeroize_polyvec(&mut s);
    zeroize_polyvec(&mut e);
    // SAFETY: `g_out` is a valid writable array.
    unsafe { zeroize_mem(g_out.as_mut_ptr(), g_out.len()) };
    // t_hat, a_hat are public values; no need to zeroize.
}

// ── Encapsulation ─────────────────────────────────────────────────────────────

/// ML-KEM.Encaps (FIPS 203 §6.2).
///
/// `ek` is the recipient's encapsulation key.
/// `entropy` is 32 bytes of uniform random (the message m before hashing).
///
/// On return `ct` contains the ciphertext and `ss` the shared secret.
pub(crate) fn encaps(
    ek: &EncapKey,
    entropy: &[u8; 32],
    ct: &mut Ciphertext,
    ss: &mut SharedSecret,
) {
    // 1. (K_bar, r) ← G(m ‖ H(ek))  — bind encapsulation to the key.
    let mut h_ek = [0u8; 32];
    sha3_256(&ek.0, &mut h_ek);

    let mut g_out = [0u8; 64];
    // G(entropy ‖ H(ek))
    sha3_512_x2(entropy, &h_ek, &mut g_out);

    let k_bar: &[u8; 32] = unsafe { &*(g_out.as_ptr() as *const [u8; 32]) };
    let r: &[u8; 32] = unsafe { &*(g_out.as_ptr().add(32) as *const [u8; 32]) };

    // 2. c ← K-PKE.Enc(ek_pke, m, r).
    kpke_enc(&ek.0, entropy, r, ct);

    // 3. K = k_bar.  (No further KDF needed per FIPS 203 §6.2.)
    ss.0.copy_from_slice(k_bar);

    // ── Zeroize ───────────────────────────────────────────────────────────────
    // SAFETY: both buffers are valid writable arrays.
    unsafe {
        zeroize_mem(g_out.as_mut_ptr(), g_out.len());
        zeroize_mem(h_ek.as_mut_ptr(), h_ek.len());
    }
    // entropy, ek are inputs; caller manages their lifetime.
}

// ── Decapsulation ─────────────────────────────────────────────────────────────

/// ML-KEM.Decaps (FIPS 203 §6.3).
///
/// Timing: constant w.r.t. decryption failure. The implicit rejection key
/// is derived from z and the ciphertext; the real key from m'.
/// The correct key is selected via constant-time conditional move — never a branch.
pub(crate) fn decaps(dk: &DecapKey, ct: &Ciphertext, ss: &mut SharedSecret) {
    // ── Unpack dk ─────────────────────────────────────────────────────────────
    let dk_pke: &[u8; DK_PKE_BYTES] =
        unsafe { &*(dk.0.as_ptr().add(DK_OFFSET_DK_PKE) as *const [u8; DK_PKE_BYTES]) };
    let ek_pke: &[u8; EK_PKE_BYTES] =
        unsafe { &*(dk.0.as_ptr().add(DK_OFFSET_EK_PKE) as *const [u8; EK_PKE_BYTES]) };
    let h_ek: &[u8; 32] = unsafe { &*(dk.0.as_ptr().add(DK_OFFSET_H) as *const [u8; 32]) };
    let z: &[u8; 32] = unsafe { &*(dk.0.as_ptr().add(DK_OFFSET_Z) as *const [u8; 32]) };

    // 1. m' ← K-PKE.Dec(dk_pke, c).
    let mut m_prime = [0u8; 32];
    kpke_dec(dk_pke, ct, &mut m_prime);

    // 2. (K'_bar, r') ← G(m' ‖ H(ek)).
    let mut g_out = [0u8; 64];
    sha3_512_x2(&m_prime, h_ek, &mut g_out);
    let k_prime: &[u8; 32] = unsafe { &*(g_out.as_ptr() as *const [u8; 32]) };
    let r_prime: &[u8; 32] = unsafe { &*(g_out.as_ptr().add(32) as *const [u8; 32]) };

    // 3. K̄ ← J(z ‖ c) — implicit rejection shared secret.
    let mut k_reject = [0u8; 32];
    shake256_x2(z, &ct.0, &mut k_reject);

    // 4. c' ← K-PKE.Enc(ek_pke, m', r').
    let mut ct_prime = Ciphertext([0u8; CT_BYTES]);
    kpke_enc(ek_pke, &m_prime, r_prime, &mut ct_prime);

    // 5. Constant-time comparison: select K' if c == c', else K̄.
    let eq = ct_eq_mask(&ct.0, &ct_prime.0); // 1 if equal, 0 if not
    // Start with rejection key; overwrite with real key if ciphertexts match.
    ss.0.copy_from_slice(&k_reject);
    ct_cmov_bytes(&mut ss.0, k_prime, eq);

    // ── Zeroize all secret intermediates ─────────────────────────────────────
    // SAFETY: all buffers are valid writable arrays.
    unsafe {
        zeroize_mem(m_prime.as_mut_ptr(), m_prime.len());
        zeroize_mem(g_out.as_mut_ptr(), g_out.len());
        zeroize_mem(k_reject.as_mut_ptr(), k_reject.len());
        zeroize_mem(ct_prime.0.as_mut_ptr(), ct_prime.0.len());
    }
}

// ── K-PKE sub-scheme ─────────────────────────────────────────────────────────

/// K-PKE.Enc (FIPS 203 §5.2).
///
/// All sensitive intermediates (r, e1, e2) are zeroized on return.
fn kpke_enc(
    ek_pke: &[u8; EK_PKE_BYTES], // encapsulation key = ByteEncode₁₂(t̂) ‖ ρ
    msg: &[u8; 32],              // plaintext message (32 bytes)
    r_seed: &[u8; 32],           // randomness seed
    ct: &mut Ciphertext,
) {
    // ── Decode ek ─────────────────────────────────────────────────────────────
    let mut t_hat = PolyVec::zero();
    {
        let ek_typed: &[u8; EK_BYTES] = ek_pke; // EK_PKE_BYTES == EK_BYTES
        let mut rho_buf = [0u8; 32];
        decode_ek(ek_typed, &mut t_hat, &mut rho_buf);
        // Need to keep rho alive; use a local.
        let rho_local = rho_buf;
        // Convert t̂ to Montgomery domain for NTT multiply.
        for p in t_hat.polys.iter_mut() {
            crate::algos::mlkem1024::poly::poly_to_mont(p);
        }

        // ── Generate Aᵀ ───────────────────────────────────────────────────────
        let mut a_hat = PolyMatrix::zero();
        gen_matrix(&mut a_hat, &rho_local, true); // transposed

        // ── Sample r, e₁, e₂ ─────────────────────────────────────────────────
        let mut r_vec = PolyVec::zero();
        sample_noise_vec_eta1(&mut r_vec, r_seed, 0);

        let mut e1 = PolyVec::zero();
        sample_noise_vec_eta2(&mut e1, r_seed, K as u8);

        let mut e2 = Poly::zero();
        sample_noise_eta2(&mut e2, r_seed, 2 * K as u8);

        // ── r̂ = NTT(r) ────────────────────────────────────────────────────────
        r_vec.ntt();

        // ── u = INTT(Âᵀ · r̂) + e₁ ───────────────────────────────────────────
        let mut u = PolyVec::zero();
        a_hat.matvec_transpose_ntt(&r_vec, &mut u);
        u.inv_ntt();
        u.add_reduce(&e1);

        // ── v = INTT(t̂ᵀ · r̂) + e₂ + μ ───────────────────────────────────────
        let mut v = Poly::zero();
        t_hat.dot_ntt(&r_vec, &mut v);
        v.inv_ntt();
        v.add_assign(&e2);
        let mut mu = Poly::from_msg(msg);
        v.add_assign(&mu);
        v.reduce();

        // ── Encode ciphertext ─────────────────────────────────────────────────
        encode_u(&u, ct_c1_mut(&mut ct.0));
        encode_v(&v, ct_c2_mut(&mut ct.0));

        // ── Zeroize secrets ───────────────────────────────────────────────────
        zeroize_polyvec(&mut r_vec);
        zeroize_polyvec(&mut e1);
        zeroize_poly(&mut e2);
        zeroize_poly(&mut mu);
        zeroize_poly(&mut v); // v combines e₂ and μ — treat as sensitive
    }
}

/// K-PKE.Dec (FIPS 203 §5.3).
///
/// Decrypts the ciphertext to a 32-byte message.
/// Secret key material (s) zeroized after use.
fn kpke_dec(
    dk_pke: &[u8; DK_PKE_BYTES], // secret key = ByteEncode₁₂(ŝ)
    ct: &Ciphertext,
    msg: &mut [u8; 32],
) {
    // ── Decode ciphertext ─────────────────────────────────────────────────────
    let mut u = PolyVec::zero();
    decode_u(ct_c1(&ct.0), &mut u);

    let mut v = Poly::zero();
    decode_v(ct_c2(&ct.0), &mut v);

    // ── Decode secret key ŝ ───────────────────────────────────────────────────
    let mut s_hat = PolyVec::zero();
    decode_dk_pke(dk_pke, &mut s_hat);
    // Convert to Montgomery domain.
    for p in s_hat.polys.iter_mut() {
        crate::algos::mlkem1024::poly::poly_to_mont(p);
    }

    // ── w = v − INTT(ŝᵀ · NTT(u)) ───────────────────────────────────────────
    u.ntt();

    let mut inner = Poly::zero();
    s_hat.dot_ntt(&u, &mut inner);
    inner.inv_ntt();

    v.sub_assign(&inner);
    v.reduce();

    // ── Compress₁ and encode as message ─────────────────────────────────────
    v.to_msg(msg);

    // ── Zeroize ───────────────────────────────────────────────────────────────
    zeroize_polyvec(&mut s_hat);
    zeroize_polyvec(&mut u); // u = NTT(u) after transform — may hold intermediate data
    zeroize_poly(&mut v);
    zeroize_poly(&mut inner);
}
