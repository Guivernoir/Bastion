use crate::mlsigcrypt::specs::keccak::{KeccakSponge, zeroize_sponge};
use crate::mlsigcrypt::specs::ml::matrix::PolyMatrix;
use crate::mlsigcrypt::specs::ml::packing::polyz_pack;
use crate::mlsigcrypt::specs::ml::params::{L, N, POLYZ_BYTES, Q, Q32};
use crate::mlsigcrypt::specs::ml::poly::{Poly, zeroize_poly};
use crate::mlsigcrypt::specs::ml::sampling::{expand_a, shake256_absorb_squeeze};
use crate::mlsigcrypt::specs::ml::vec::{PolyVec, zeroize_polyvec};
use crate::zeroize::zeroize_array;

const SHAKE256_RATE: usize = 136;
const SHAKE_SUFFIX: u8 = 0x1F;

pub(crate) const ENC_K: usize = 4;
const ENCAP_POLYS: usize = ENC_K + 1;
const POLY23_BYTES: usize = N * 23 / 8;
const SK_ENC_DOMAIN: &[u8] = b"MLSigcrypt-v3/sk_enc";
const ENCAP_MASK_DOMAIN: &[u8] = b"MLSigcrypt-v3/encap_mask";

pub(crate) const SECRET_SEED_BYTES: usize = 32;
pub(crate) const PUBLIC_KEY_BYTES: usize = ENC_K * POLY23_BYTES;
pub(crate) const ENCAP_BYTES: usize = ENCAP_POLYS * POLY23_BYTES;

fn pack_poly23(out: &mut [u8; POLY23_BYTES], poly: &Poly) {
    out.fill(0);
    let mut acc = 0u64;
    let mut acc_bits = 0usize;
    let mut out_pos = 0usize;

    for &coeff in poly.coeffs.iter() {
        let value = coeff as u32;
        acc |= (value as u64) << acc_bits;
        acc_bits += 23;
        while acc_bits >= 8 {
            out[out_pos] = acc as u8;
            out_pos += 1;
            acc >>= 8;
            acc_bits -= 8;
        }
    }

    if acc_bits != 0 {
        out[out_pos] = acc as u8;
    }
}

fn unpack_poly23(poly: &mut Poly, input: &[u8; POLY23_BYTES]) -> bool {
    let mut acc = 0u64;
    let mut acc_bits = 0usize;
    let mut in_pos = 0usize;

    for coeff in poly.coeffs.iter_mut() {
        while acc_bits < 23 {
            acc |= (input[in_pos] as u64) << acc_bits;
            in_pos += 1;
            acc_bits += 8;
        }
        let value = (acc & 0x7F_FFFF) as u32;
        if value >= Q {
            return false;
        }
        *coeff = value as i32;
        acc >>= 23;
        acc_bits -= 23;
    }

    true
}

fn encode_poly23(out: &mut [u8; POLY23_BYTES], poly: &Poly) {
    pack_poly23(out, poly);
}

fn decode_poly23(out: &mut Poly, input: &[u8; POLY23_BYTES]) -> bool {
    unpack_poly23(out, input)
}

fn encode_polyvec23(vec: &PolyVec<ENC_K>, out: &mut [u8; PUBLIC_KEY_BYTES]) {
    for i in 0..ENC_K {
        let start = i * POLY23_BYTES;
        let end = start + POLY23_BYTES;
        let chunk = &mut out[start..end];
        let chunk: &mut [u8; POLY23_BYTES] = chunk.try_into().expect("fixed-size poly23 chunk");
        pack_poly23(chunk, &vec.polys[i]);
    }
}

fn decode_polyvec23(out: &mut PolyVec<ENC_K>, input: &[u8; PUBLIC_KEY_BYTES]) -> bool {
    for i in 0..ENC_K {
        let start = i * POLY23_BYTES;
        let end = start + POLY23_BYTES;
        let chunk: &[u8; POLY23_BYTES] = input[start..end]
            .try_into()
            .expect("fixed-size poly23 chunk");
        if !unpack_poly23(&mut out.polys[i], chunk) {
            return false;
        }
    }
    true
}

fn encode_encap(u: &PolyVec<ENC_K>, v: &Poly, out: &mut [u8; ENCAP_BYTES]) {
    for i in 0..ENC_K {
        let start = i * POLY23_BYTES;
        let end = start + POLY23_BYTES;
        let chunk: &mut [u8; POLY23_BYTES] = (&mut out[start..end])
            .try_into()
            .expect("fixed-size poly23 chunk");
        encode_poly23(chunk, &u.polys[i]);
    }

    let start = ENC_K * POLY23_BYTES;
    let end = start + POLY23_BYTES;
    let chunk: &mut [u8; POLY23_BYTES] = (&mut out[start..end])
        .try_into()
        .expect("fixed-size poly23 chunk");
    encode_poly23(chunk, v);
}

fn decode_encap(u: &mut PolyVec<ENC_K>, v: &mut Poly, input: &[u8; ENCAP_BYTES]) -> bool {
    for i in 0..ENC_K {
        let start = i * POLY23_BYTES;
        let end = start + POLY23_BYTES;
        let chunk: &[u8; POLY23_BYTES] = input[start..end]
            .try_into()
            .expect("fixed-size poly23 chunk");
        if !decode_poly23(&mut u.polys[i], chunk) {
            return false;
        }
    }

    let start = ENC_K * POLY23_BYTES;
    let end = start + POLY23_BYTES;
    let chunk: &[u8; POLY23_BYTES] = input[start..end]
        .try_into()
        .expect("fixed-size poly23 chunk");
    decode_poly23(v, chunk)
}

fn derive_small_rho(domain: &[u8], seed: &[u8; SECRET_SEED_BYTES], out: &mut [u8; 64]) {
    shake256_absorb_squeeze(&[domain, seed], out);
}

fn sample_small_poly(seed: &[u8; 64], nonce: u8, out: &mut Poly) {
    let nonce_bytes = [nonce];
    let mut sponge = KeccakSponge::<SHAKE256_RATE>::new();
    let mut buf = [0u8; SHAKE256_RATE * 2];
    let mut coeff_pos = 0usize;

    sponge.absorb(seed);
    sponge.absorb(&nonce_bytes);
    sponge.finalize(SHAKE_SUFFIX);

    while coeff_pos < N {
        sponge.squeeze(&mut buf);
        for &byte in &buf {
            let lo = byte & 0x0F;
            if lo < 15 && coeff_pos < N {
                out.coeffs[coeff_pos] = (lo % 5) as i32 - 2;
                coeff_pos += 1;
            }

            let hi = byte >> 4;
            if hi < 15 && coeff_pos < N {
                out.coeffs[coeff_pos] = (hi % 5) as i32 - 2;
                coeff_pos += 1;
            }
        }
    }

    zeroize_array(&mut buf);
    zeroize_sponge(&mut sponge);
}

fn derive_small_vec(seed: &[u8; 64], nonce_base: u8, out: &mut PolyVec<ENC_K>) {
    for i in 0..ENC_K {
        sample_small_poly(seed, nonce_base.wrapping_add(i as u8), &mut out.polys[i]);
    }
}

fn derive_secret_error(
    seed: &[u8; SECRET_SEED_BYTES],
    secret: &mut PolyVec<ENC_K>,
    error: &mut PolyVec<ENC_K>,
) {
    let mut rho = [0u8; 64];
    derive_small_rho(SK_ENC_DOMAIN, seed, &mut rho);
    derive_small_vec(&rho, 0, secret);
    derive_small_vec(&rho, ENC_K as u8, error);
    zeroize_array(&mut rho);
}

pub(crate) fn derive_secret_vector(seed: &[u8; SECRET_SEED_BYTES], out: &mut PolyVec<ENC_K>) {
    let mut rho = [0u8; 64];
    derive_small_rho(SK_ENC_DOMAIN, seed, &mut rho);
    derive_small_vec(&rho, 0, out);
    zeroize_array(&mut rho);
}

fn derive_encap_seed_from_mask(y: &PolyVec<L>, out: &mut [u8; 64]) {
    let mut sponge = KeccakSponge::<SHAKE256_RATE>::new();
    let mut packed = [0u8; POLYZ_BYTES];

    sponge.absorb(ENCAP_MASK_DOMAIN);
    for poly in &y.polys {
        polyz_pack(&mut packed, poly);
        sponge.absorb(&packed);
    }
    sponge.finalize(SHAKE_SUFFIX);
    sponge.squeeze(out);

    zeroize_array(&mut packed);
    zeroize_sponge(&mut sponge);
}

fn mat_kem_vec_ntt(mat_a: &PolyMatrix, s_hat: &PolyVec<ENC_K>, out: &mut PolyVec<ENC_K>) {
    for row in 0..ENC_K {
        out.polys[row].coeffs.fill(0);
        for col in 0..ENC_K {
            out.polys[row].pointwise_acc(&mat_a.rows[row].polys[col], &s_hat.polys[col]);
        }
        out.polys[row].reduce();
    }
}

fn mat_kem_t_vec_ntt(mat_a: &PolyMatrix, r_hat: &PolyVec<ENC_K>, out: &mut PolyVec<ENC_K>) {
    for col in 0..ENC_K {
        out.polys[col].coeffs.fill(0);
        for row in 0..ENC_K {
            out.polys[col].pointwise_acc(&mat_a.rows[row].polys[col], &r_hat.polys[row]);
        }
        out.polys[col].reduce();
    }
}

fn dot_ntt<const M: usize>(lhs_hat: &PolyVec<M>, rhs_hat: &PolyVec<M>, out: &mut Poly) {
    out.coeffs.fill(0);
    for i in 0..M {
        out.pointwise_acc(&lhs_hat.polys[i], &rhs_hat.polys[i]);
    }
    out.reduce();
}

fn encode_message_key_poly(message_key: &[u8; 32], out: &mut Poly) {
    out.coeffs.fill(0);
    for i in 0..N {
        let bit = (message_key[i / 8] >> (i & 7)) & 1;
        out.coeffs[i] = if bit == 1 { (Q / 2) as i32 } else { 0 };
    }
}

fn decode_message_key_poly(poly: &Poly, out: &mut [u8; 32]) {
    let mut tmp = Poly::zero();
    let low = Q32 / 4;
    let high = 3 * Q32 / 4;

    tmp.coeffs.copy_from_slice(&poly.coeffs);
    tmp.reduce();
    tmp.caddq();

    out.fill(0);
    for i in 0..N {
        let coeff = tmp.coeffs[i];
        let bit = (coeff > low && coeff < high) as u8;
        out[i / 8] |= bit << (i & 7);
    }

    zeroize_poly(&mut tmp);
}

pub(crate) fn derive_public_key(
    rho_shared: &[u8; 32],
    seed: &[u8; SECRET_SEED_BYTES],
    out: &mut [u8; PUBLIC_KEY_BYTES],
) {
    let mut mat_a = PolyMatrix::zero();
    expand_a(&mut mat_a, rho_shared);
    derive_public_key_from_matrix(&mat_a, seed, out);
}

pub(crate) fn derive_public_key_from_matrix(
    mat_a: &PolyMatrix,
    seed: &[u8; SECRET_SEED_BYTES],
    out: &mut [u8; PUBLIC_KEY_BYTES],
) {
    let mut secret = PolyVec::<ENC_K>::zero();
    let mut error = PolyVec::<ENC_K>::zero();
    derive_secret_error(seed, &mut secret, &mut error);

    let mut secret_hat = PolyVec::<ENC_K>::zero();
    for i in 0..ENC_K {
        secret_hat.polys[i]
            .coeffs
            .copy_from_slice(&secret.polys[i].coeffs);
        secret_hat.polys[i].ntt();
    }

    let mut public = PolyVec::<ENC_K>::zero();
    mat_kem_vec_ntt(&mat_a, &secret_hat, &mut public);
    public.inv_ntt();
    public.reduce();
    public.caddq();
    public.add_assign(&error);
    public.reduce();
    public.caddq();
    encode_polyvec23(&public, out);

    zeroize_polyvec(&mut secret);
    zeroize_polyvec(&mut error);
    zeroize_polyvec(&mut secret_hat);
    zeroize_polyvec(&mut public);
}

pub(crate) fn decode_public_key(bytes: &[u8; PUBLIC_KEY_BYTES], out: &mut PolyVec<ENC_K>) -> bool {
    decode_polyvec23(out, bytes)
}

pub(crate) fn encapsulate_from_mask(
    mat_a: &PolyMatrix,
    recipient_pk_hat: &PolyVec<ENC_K>,
    y: &PolyVec<L>,
    message_key: &[u8; 32],
    encap_out: &mut [u8; ENCAP_BYTES],
) {
    let mut encap_seed = [0u8; 64];
    derive_encap_seed_from_mask(y, &mut encap_seed);

    let mut r = PolyVec::<ENC_K>::zero();
    let mut e1 = PolyVec::<ENC_K>::zero();
    let mut e2 = Poly::zero();
    derive_small_vec(&encap_seed, 0, &mut r);
    derive_small_vec(&encap_seed, ENC_K as u8, &mut e1);
    sample_small_poly(&encap_seed, (2 * ENC_K) as u8, &mut e2);

    let mut r_hat = PolyVec::<ENC_K>::zero();
    for i in 0..ENC_K {
        r_hat.polys[i].coeffs.copy_from_slice(&r.polys[i].coeffs);
        r_hat.polys[i].ntt();
    }

    let mut u = PolyVec::<ENC_K>::zero();
    mat_kem_t_vec_ntt(&mat_a, &r_hat, &mut u);
    u.inv_ntt();
    u.reduce();
    u.caddq();
    u.add_assign(&e1);
    u.reduce();
    u.caddq();

    let mut v = Poly::zero();
    dot_ntt(recipient_pk_hat, &r_hat, &mut v);
    v.inv_ntt();
    v.reduce();
    v.caddq();
    v.add_assign(&e2);

    let mut encoded_key = Poly::zero();
    encode_message_key_poly(message_key, &mut encoded_key);
    v.add_assign(&encoded_key);
    v.reduce();
    v.caddq();

    encode_encap(&u, &v, encap_out);

    zeroize_array(&mut encap_seed);
    zeroize_polyvec(&mut r);
    zeroize_polyvec(&mut e1);
    zeroize_polyvec(&mut r_hat);
    zeroize_polyvec(&mut u);
    zeroize_poly(&mut e2);
    zeroize_poly(&mut encoded_key);
    zeroize_poly(&mut v);
}

pub(crate) fn decapsulate_from_seed(
    seed: &[u8; SECRET_SEED_BYTES],
    encap_bytes: &[u8; ENCAP_BYTES],
    shared_out: &mut [u8; 32],
) -> bool {
    let mut secret = PolyVec::<ENC_K>::zero();
    derive_secret_vector(seed, &mut secret);

    let mut u = PolyVec::<ENC_K>::zero();
    let mut v = Poly::zero();
    if !decode_encap(&mut u, &mut v, encap_bytes) {
        zeroize_polyvec(&mut secret);
        return false;
    }

    let mut u_hat = PolyVec::<ENC_K>::zero();
    for i in 0..ENC_K {
        u_hat.polys[i].coeffs.copy_from_slice(&u.polys[i].coeffs);
        u_hat.polys[i].ntt();
    }

    let mut secret_hat = PolyVec::<ENC_K>::zero();
    for i in 0..ENC_K {
        secret_hat.polys[i]
            .coeffs
            .copy_from_slice(&secret.polys[i].coeffs);
        secret_hat.polys[i].ntt();
    }

    let mut recovered = Poly::zero();
    dot_ntt(&secret_hat, &u_hat, &mut recovered);
    recovered.inv_ntt();
    recovered.reduce();
    recovered.caddq();
    v.sub_assign(&recovered);
    v.reduce();
    v.caddq();
    decode_message_key_poly(&v, shared_out);

    zeroize_polyvec(&mut secret);
    zeroize_polyvec(&mut u);
    zeroize_polyvec(&mut u_hat);
    zeroize_polyvec(&mut secret_hat);
    zeroize_poly(&mut v);
    zeroize_poly(&mut recovered);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_roundtrip() {
        let rho = [0x42u8; 32];
        let seed = [0x24u8; 32];
        let mut encoded = [0u8; PUBLIC_KEY_BYTES];
        derive_public_key(&rho, &seed, &mut encoded);

        let mut decoded = PolyVec::<ENC_K>::zero();
        assert!(decode_public_key(&encoded, &mut decoded));
    }

    #[test]
    fn shared_key_agrees() {
        let rho = [0x19u8; 32];
        let seed = [0x73u8; 32];
        let mut pk = [0u8; PUBLIC_KEY_BYTES];
        derive_public_key(&rho, &seed, &mut pk);

        let mut rho_prime = [0u8; 64];
        shake256_absorb_squeeze(&[b"test-y"], &mut rho_prime);
        let mut y = PolyVec::<L>::zero();
        crate::mlsigcrypt::specs::ml::sampling::expand_mask(&mut y, &rho_prime, 0);
        let mut mat_a = PolyMatrix::zero();
        expand_a(&mut mat_a, &rho);
        let mut recipient_pk = PolyVec::<ENC_K>::zero();
        assert!(decode_public_key(&pk, &mut recipient_pk));
        let mut recipient_pk_hat = PolyVec::<ENC_K>::zero();
        for i in 0..ENC_K {
            recipient_pk_hat.polys[i]
                .coeffs
                .copy_from_slice(&recipient_pk.polys[i].coeffs);
            recipient_pk_hat.polys[i].ntt();
        }

        let mut encap = [0u8; ENCAP_BYTES];
        let mut shared_a = [0xA5u8; 32];
        let mut shared_b = [0u8; 32];
        encapsulate_from_mask(&mat_a, &recipient_pk_hat, &y, &shared_a, &mut encap);
        assert!(decapsulate_from_seed(&seed, &encap, &mut shared_b));
        assert_eq!(shared_a, shared_b);

        zeroize_array(&mut rho_prime);
        zeroize_polyvec(&mut y);
        zeroize_polyvec(&mut recipient_pk);
        zeroize_polyvec(&mut recipient_pk_hat);
        zeroize_array(&mut encap);
        zeroize_array(&mut shared_a);
        zeroize_array(&mut shared_b);
    }
}
