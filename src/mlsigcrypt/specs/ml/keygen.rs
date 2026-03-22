use crate::mlsigcrypt::specs::ml::matrix::PolyMatrix;
use crate::mlsigcrypt::specs::ml::packing::{pack_pk, pack_sk};
/// ML-DSA-87 key generation — FIPS 204 Algorithm 1.
///
/// # Algorithm
///
///   Input:  ξ (seed, 32 bytes)
///   Output: pk (2592 bytes), sk (4896 bytes)
///
///   1.  (ρ, ρ', K) ← G(ξ ‖ k_byte ‖ l_byte)    G = SHAKE-256, 128-byte output
///   2.  A ← ExpandA(ρ)
///   3.  (s1, s2) ← ExpandS(ρ', η)
///   4.  t ← INTT(A × NTT(s1)) + s2
///   5.  (t1, t0) ← Power2Round(t, d)
///   6.  pk ← pkEncode(ρ, t1)
///   7.  tr ← H(pk, 64)                            H = SHAKE-256
///   8.  sk ← skEncode(ρ, K, tr, s1, s2, t0)
///
/// Domain separation in step 1: the single byte k (=K=8) and l (=L=7)
/// are appended to ξ so that different ML-DSA parameter sets produce
/// independent key material from the same seed.
///
/// # Memory note
/// Stack usage: 1× PolyMatrix (≈56 KB) + several PolyVec<K/L> (≈8 KB each).
/// On constrained targets, consider splitting or using a static allocation.
use crate::mlsigcrypt::specs::ml::params::{K, L, PK_BYTES, SK_BYTES};
use crate::mlsigcrypt::specs::ml::sampling::{expand_a, expand_s, shake256_absorb_squeeze};
use crate::mlsigcrypt::specs::ml::vec::{PolyVec, zeroize_polyvec};
use crate::zeroize::zeroize_array;

// ── Public API ────────────────────────────────────────────────────────────────

/// Generate an ML-DSA-87 key pair from a 32-byte seed.
///
/// # Arguments
/// * `pk`   — output buffer for the public key  (2592 bytes)
/// * `sk`   — output buffer for the secret key  (4896 bytes)
/// * `seed` — 32-byte uniformly random seed (must be secret and never reused)
///
/// The caller is responsible for generating `seed` from a CSPRNG.
/// For deterministic test-vector generation, a fixed seed may be used.
pub(crate) fn keypair(pk: &mut [u8; PK_BYTES], sk: &mut [u8; SK_BYTES], seed: &[u8; 32]) {
    // ── Step 1: Expand seed → (ρ, ρ', K_seed) ────────────────────────────────
    //
    // G(ξ ‖ k ‖ l) = SHAKE-256(ξ ‖ [K as u8, L as u8], 128 bytes).
    // k and l bytes domain-separate ML-DSA-87 from other parameter sets.
    let mut expanded = [0u8; 128];
    shake256_absorb_squeeze(&[seed.as_slice(), &[K as u8, L as u8]], &mut expanded);

    let rho: [u8; 32] = expanded[0..32].try_into().unwrap();
    let mut rho_prime: [u8; 64] = expanded[32..96].try_into().unwrap();
    let mut k_seed: [u8; 32] = expanded[96..128].try_into().unwrap();

    keypair_from_rho(pk, sk, &rho, &mut rho_prime, &mut k_seed);

    zeroize_array(&mut expanded);
    zeroize_array(&mut rho_prime);
    zeroize_array(&mut k_seed);
}

/// Generate an ML-DSA-87 key pair using a caller-supplied public matrix seed `ρ`.
///
/// MLSigcrypt shared-matrix profiles use this entry point so the signature key
/// can be derived against a caller-chosen public matrix. Secret sampling
/// remains derived from `seed`.
pub(crate) fn keypair_with_rho(
    pk: &mut [u8; PK_BYTES],
    sk: &mut [u8; SK_BYTES],
    seed: &[u8; 32],
    rho: &[u8; 32],
) {
    let mut expanded = [0u8; 96];
    shake256_absorb_squeeze(&[seed.as_slice(), &[K as u8, L as u8]], &mut expanded);

    let mut rho_prime: [u8; 64] = expanded[0..64].try_into().unwrap();
    let mut k_seed: [u8; 32] = expanded[64..96].try_into().unwrap();

    keypair_from_rho(pk, sk, rho, &mut rho_prime, &mut k_seed);

    zeroize_array(&mut expanded);
    zeroize_array(&mut rho_prime);
    zeroize_array(&mut k_seed);
}

/// Generate an ML-DSA-87 key pair using a caller-supplied expanded public matrix.
pub(crate) fn keypair_with_matrix(
    pk: &mut [u8; PK_BYTES],
    sk: &mut [u8; SK_BYTES],
    seed: &[u8; 32],
    rho: &[u8; 32],
    mat_a: &PolyMatrix,
) {
    let mut expanded = [0u8; 96];
    shake256_absorb_squeeze(&[seed.as_slice(), &[K as u8, L as u8]], &mut expanded);

    let mut rho_prime: [u8; 64] = expanded[0..64].try_into().unwrap();
    let mut k_seed: [u8; 32] = expanded[64..96].try_into().unwrap();

    keypair_from_matrix(pk, sk, rho, &mut rho_prime, &mut k_seed, mat_a);

    zeroize_array(&mut expanded);
    zeroize_array(&mut rho_prime);
    zeroize_array(&mut k_seed);
}

#[cfg(test)]
pub(crate) struct KeypairTrace {
    pub(crate) seed: [u8; 32],
    pub(crate) rho: [u8; 32],
    pub(crate) rho_prime: [u8; 64],
    pub(crate) k_seed: [u8; 32],
    pub(crate) s1: PolyVec<L>,
    pub(crate) s2: PolyVec<K>,
    pub(crate) t: PolyVec<K>,
    pub(crate) t1: PolyVec<K>,
    pub(crate) t0: PolyVec<K>,
    pub(crate) tr: [u8; 64],
    pub(crate) pk: [u8; PK_BYTES],
    pub(crate) sk: [u8; SK_BYTES],
}

#[cfg(test)]
pub(crate) fn keypair_trace(seed: &[u8; 32]) -> KeypairTrace {
    let mut expanded = [0u8; 128];
    shake256_absorb_squeeze(&[seed.as_slice(), &[K as u8, L as u8]], &mut expanded);

    let mut rho = [0u8; 32];
    let mut rho_prime = [0u8; 64];
    let mut k_seed = [0u8; 32];
    rho.copy_from_slice(&expanded[..32]);
    rho_prime.copy_from_slice(&expanded[32..96]);
    k_seed.copy_from_slice(&expanded[96..128]);

    let mut mat_a = PolyMatrix::zero();
    expand_a(&mut mat_a, &rho);

    let mut s1: PolyVec<L> = PolyVec::zero();
    let mut s2: PolyVec<K> = PolyVec::zero();
    expand_s(&mut s1, &mut s2, &rho_prime);

    let mut s1_hat: PolyVec<L> = PolyVec::zero();
    for i in 0..L {
        s1_hat.polys[i].coeffs.copy_from_slice(&s1.polys[i].coeffs);
        s1_hat.polys[i].ntt();
    }

    let mut w_hat: PolyVec<K> = PolyVec::zero();
    mat_a.matvec_ntt(&s1_hat, &mut w_hat);

    let mut t: PolyVec<K> = PolyVec::zero();
    for i in 0..K {
        t.polys[i].coeffs.copy_from_slice(&w_hat.polys[i].coeffs);
        t.polys[i].inv_ntt();
        t.polys[i].caddq();
        t.polys[i].add_assign(&s2.polys[i]);
        t.polys[i].caddq();
    }

    let mut t1: PolyVec<K> = PolyVec::zero();
    let mut t0: PolyVec<K> = PolyVec::zero();
    for i in 0..K {
        t.polys[i].power2round_split(&mut t1.polys[i], &mut t0.polys[i]);
    }

    let mut pk = [0u8; PK_BYTES];
    pack_pk(&mut pk, &rho, &t1);

    let mut tr = [0u8; 64];
    shake256_absorb_squeeze(&[pk.as_slice()], &mut tr);

    let mut sk = [0u8; SK_BYTES];
    pack_sk(&mut sk, &rho, &k_seed, &tr, &s1, &s2, &t0);

    zeroize_polyvec(&mut s1_hat);
    zeroize_polyvec(&mut w_hat);
    zeroize_array(&mut expanded);

    KeypairTrace {
        seed: *seed,
        rho,
        rho_prime,
        k_seed,
        s1,
        s2,
        t,
        t1,
        t0,
        tr,
        pk,
        sk,
    }
}

fn keypair_from_rho(
    pk: &mut [u8; PK_BYTES],
    sk: &mut [u8; SK_BYTES],
    rho: &[u8; 32],
    rho_prime: &mut [u8; 64],
    k_seed: &mut [u8; 32],
) {
    // ── Step 2: Generate public matrix A in NTT domain ────────────────────────
    let mut mat_a = PolyMatrix::zero();
    expand_a(&mut mat_a, rho);
    keypair_from_matrix(pk, sk, rho, rho_prime, k_seed, &mat_a);
}

fn keypair_from_matrix(
    pk: &mut [u8; PK_BYTES],
    sk: &mut [u8; SK_BYTES],
    rho: &[u8; 32],
    rho_prime: &mut [u8; 64],
    k_seed: &mut [u8; 32],
    mat_a: &PolyMatrix,
) {
    // ── Step 3: Sample secret vectors s1 (L) and s2 (K) ──────────────────────
    let mut s1: PolyVec<L> = PolyVec::zero();
    let mut s2: PolyVec<K> = PolyVec::zero();
    expand_s(&mut s1, &mut s2, rho_prime);

    // ── Step 4: t = INTT(A × NTT(s1)) + s2 ──────────────────────────────────
    //
    // Compute NTT(s1) into a temporary; s1 is kept for sk packing.
    let mut s1_hat: PolyVec<L> = PolyVec::zero();
    for i in 0..L {
        s1_hat.polys[i].coeffs.copy_from_slice(&s1.polys[i].coeffs);
        s1_hat.polys[i].ntt();
    }

    // w_hat = A × s1_hat in NTT domain.
    let mut w_hat: PolyVec<K> = PolyVec::zero();
    mat_a.matvec_ntt(&s1_hat, &mut w_hat);

    // t = INTT(w_hat) + s2. caddq ensures t ∈ [0, q) for Power2Round.
    let mut t: PolyVec<K> = PolyVec::zero();
    for i in 0..K {
        t.polys[i].coeffs.copy_from_slice(&w_hat.polys[i].coeffs);
        t.polys[i].inv_ntt();
        t.polys[i].caddq();
        t.polys[i].add_assign(&s2.polys[i]);
        t.polys[i].caddq();
    }

    // ── Step 5: Power2Round(t, d) → (t1, t0) ─────────────────────────────────
    let mut t1: PolyVec<K> = PolyVec::zero();
    let mut t0: PolyVec<K> = PolyVec::zero();
    for i in 0..K {
        t.polys[i].power2round_split(&mut t1.polys[i], &mut t0.polys[i]);
    }

    // ── Step 6: Pack public key ───────────────────────────────────────────────
    pack_pk(pk, rho, &t1);

    // ── Step 7: tr = H(pk, 64 bytes) ─────────────────────────────────────────
    let mut tr = [0u8; 64];
    shake256_absorb_squeeze(&[pk.as_slice()], &mut tr);

    // ── Step 8: Pack secret key ───────────────────────────────────────────────
    pack_sk(sk, rho, k_seed, &tr, &s1, &s2, &t0);

    // ── Zeroize all sensitive intermediates ───────────────────────────────────
    zeroize_polyvec(&mut s1);
    zeroize_polyvec(&mut s1_hat);
    zeroize_polyvec(&mut s2);
    zeroize_polyvec(&mut w_hat);
    zeroize_polyvec(&mut t);
    zeroize_polyvec(&mut t0);
    zeroize_array(&mut tr);
}
