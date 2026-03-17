use crate::mlsigcrypt::specs::ml::matrix::PolyMatrix;
use crate::mlsigcrypt::specs::ml::params::{L, N, Q};
use crate::mlsigcrypt::specs::ml::poly::{Poly, zeroize_poly};
use crate::mlsigcrypt::specs::ml::sampling::{expand_a, shake256_absorb_squeeze};
use crate::mlsigcrypt::specs::ml::vec::{PolyVec, zeroize_polyvec};
use crate::mlsigcrypt::specs::sha512::sha3_512_hash as sha3_512;
use crate::zeroize::zeroize_array;

const ENC_K: usize = 4;
const POLY23_BYTES: usize = N * 23 / 8;
const SHARED_KEY_DOMAIN: &[u8] = b"MLSigcrypt-v3/shared_key";
const SK_ENC_DOMAIN: &[u8] = b"MLSigcrypt-v3/sk_enc";

pub(crate) const SECRET_SEED_BYTES: usize = 32;
pub(crate) const PUBLIC_KEY_BYTES: usize = ENC_K * POLY23_BYTES;
pub(crate) const ENCAP_BYTES: usize = PUBLIC_KEY_BYTES;

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

fn derive_secret_rho(seed: &[u8; SECRET_SEED_BYTES], out: &mut [u8; 64]) {
    shake256_absorb_squeeze(&[SK_ENC_DOMAIN, seed], out);
}

pub(crate) fn derive_secret_vector(seed: &[u8; SECRET_SEED_BYTES], out: &mut PolyVec<ENC_K>) {
    let mut rho = [0u8; 64];
    derive_secret_rho(seed, &mut rho);

    for i in 0..ENC_K {
        let nonce = (L + i) as u8;
        let mut stream = [0u8; 256];
        let nonce_bytes = nonce.to_le_bytes();
        shake256_absorb_squeeze(&[&rho, &nonce_bytes], &mut stream);

        let mut coeff_pos = 0usize;
        let mut nibble_pos = 0usize;
        while coeff_pos < N {
            let byte = stream[nibble_pos / 2];
            let nibble = if nibble_pos & 1 == 0 {
                byte & 0x0F
            } else {
                byte >> 4
            };
            nibble_pos += 1;
            if nibble < 15 {
                out.polys[i].coeffs[coeff_pos] = (nibble % 5) as i32 - 2;
                coeff_pos += 1;
            }
        }

        zeroize_array(&mut stream);
    }

    zeroize_array(&mut rho);
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

fn hash_shared_poly(poly: &Poly, out: &mut [u8; 32]) {
    let mut packed = [0u8; POLY23_BYTES];
    let mut tmp = Poly::zero();
    tmp.coeffs.copy_from_slice(&poly.coeffs);
    tmp.reduce();
    tmp.caddq();
    pack_poly23(&mut packed, &tmp);
    let mut hash = [0u8; 64];
    sha3_512(&[SHARED_KEY_DOMAIN, &packed], &mut hash);
    out.copy_from_slice(&hash[..32]);
    zeroize_array(&mut packed);
    zeroize_array(&mut hash);
    zeroize_poly(&mut tmp);
}

pub(crate) fn derive_public_key(
    rho_shared: &[u8; 32],
    seed: &[u8; SECRET_SEED_BYTES],
    out: &mut [u8; PUBLIC_KEY_BYTES],
) {
    let mut secret = PolyVec::<ENC_K>::zero();
    derive_secret_vector(seed, &mut secret);

    let mut secret_hat = PolyVec::<ENC_K>::zero();
    for i in 0..ENC_K {
        secret_hat.polys[i]
            .coeffs
            .copy_from_slice(&secret.polys[i].coeffs);
        secret_hat.polys[i].ntt();
    }

    let mut mat_a = PolyMatrix::zero();
    expand_a(&mut mat_a, rho_shared);

    let mut public = PolyVec::<ENC_K>::zero();
    mat_kem_vec_ntt(&mat_a, &secret_hat, &mut public);
    public.inv_ntt();
    public.reduce();
    public.caddq();
    encode_polyvec23(&public, out);

    zeroize_polyvec(&mut secret);
    zeroize_polyvec(&mut secret_hat);
    zeroize_polyvec(&mut public);
}

pub(crate) fn decode_public_key(bytes: &[u8; PUBLIC_KEY_BYTES], out: &mut PolyVec<ENC_K>) -> bool {
    decode_polyvec23(out, bytes)
}

pub(crate) fn encapsulate_from_mask(
    rho_shared: &[u8; 32],
    recipient_pk_bytes: &[u8; PUBLIC_KEY_BYTES],
    y_hat_full: &PolyVec<L>,
    encap_out: &mut [u8; ENCAP_BYTES],
    shared_out: &mut [u8; 32],
) -> bool {
    let mut mat_a = PolyMatrix::zero();
    expand_a(&mut mat_a, rho_shared);

    let mut r_hat = PolyVec::<ENC_K>::zero();
    for i in 0..ENC_K {
        r_hat.polys[i]
            .coeffs
            .copy_from_slice(&y_hat_full.polys[i].coeffs);
    }

    let mut encap = PolyVec::<ENC_K>::zero();
    mat_kem_t_vec_ntt(&mat_a, &r_hat, &mut encap);
    encap.inv_ntt();
    encap.reduce();
    encap.caddq();
    encode_polyvec23(&encap, encap_out);

    let mut recipient_pk = PolyVec::<ENC_K>::zero();
    if !decode_public_key(recipient_pk_bytes, &mut recipient_pk) {
        zeroize_polyvec(&mut r_hat);
        zeroize_polyvec(&mut encap);
        return false;
    }

    let mut recipient_pk_hat = PolyVec::<ENC_K>::zero();
    for i in 0..ENC_K {
        recipient_pk_hat.polys[i]
            .coeffs
            .copy_from_slice(&recipient_pk.polys[i].coeffs);
        recipient_pk_hat.polys[i].ntt();
    }

    let mut shared_poly = Poly::zero();
    dot_ntt(&recipient_pk_hat, &r_hat, &mut shared_poly);
    shared_poly.inv_ntt();
    shared_poly.reduce();
    shared_poly.caddq();
    hash_shared_poly(&shared_poly, shared_out);

    zeroize_polyvec(&mut r_hat);
    zeroize_polyvec(&mut encap);
    zeroize_polyvec(&mut recipient_pk);
    zeroize_polyvec(&mut recipient_pk_hat);
    zeroize_poly(&mut shared_poly);
    true
}

pub(crate) fn decapsulate_from_seed(
    seed: &[u8; SECRET_SEED_BYTES],
    encap_bytes: &[u8; ENCAP_BYTES],
    shared_out: &mut [u8; 32],
) -> bool {
    let mut secret = PolyVec::<ENC_K>::zero();
    derive_secret_vector(seed, &mut secret);

    let mut encap = PolyVec::<ENC_K>::zero();
    if !decode_polyvec23(&mut encap, encap_bytes) {
        zeroize_polyvec(&mut secret);
        return false;
    }

    let mut encap_hat = PolyVec::<ENC_K>::zero();
    for i in 0..ENC_K {
        encap_hat.polys[i]
            .coeffs
            .copy_from_slice(&encap.polys[i].coeffs);
        encap_hat.polys[i].ntt();
    }

    let mut secret_hat = PolyVec::<ENC_K>::zero();
    for i in 0..ENC_K {
        secret_hat.polys[i]
            .coeffs
            .copy_from_slice(&secret.polys[i].coeffs);
        secret_hat.polys[i].ntt();
    }

    let mut shared_poly = Poly::zero();
    dot_ntt(&secret_hat, &encap_hat, &mut shared_poly);
    shared_poly.inv_ntt();
    shared_poly.reduce();
    shared_poly.caddq();
    hash_shared_poly(&shared_poly, shared_out);

    zeroize_polyvec(&mut secret);
    zeroize_polyvec(&mut encap);
    zeroize_polyvec(&mut encap_hat);
    zeroize_polyvec(&mut secret_hat);
    zeroize_poly(&mut shared_poly);
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
        let mut y_hat = PolyVec::<L>::zero();
        for i in 0..L {
            y_hat.polys[i].coeffs.copy_from_slice(&y.polys[i].coeffs);
            y_hat.polys[i].ntt();
        }

        let mut encap = [0u8; ENCAP_BYTES];
        let mut shared_a = [0u8; 32];
        let mut shared_b = [0u8; 32];
        assert!(encapsulate_from_mask(
            &rho,
            &pk,
            &y_hat,
            &mut encap,
            &mut shared_a
        ));
        assert!(decapsulate_from_seed(&seed, &encap, &mut shared_b));
        assert_eq!(shared_a, shared_b);

        zeroize_array(&mut rho_prime);
        zeroize_polyvec(&mut y);
        zeroize_polyvec(&mut y_hat);
        zeroize_array(&mut encap);
        zeroize_array(&mut shared_a);
        zeroize_array(&mut shared_b);
    }
}
