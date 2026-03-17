/// MLSigcrypt-v3 level-3 signcrypt and unsigncrypt algorithms.
///
/// Level 3 fuses the signing mask and the encapsulation randomness: the same
/// `y` sampled for the ML-DSA response also drives the algebraic encapsulation
/// under the recipient public key.
use super::keys::{UserPublicKey, UserSecretKey};
use super::params::*;
use crate::constant_time::ct_eq;
use crate::mlsigcrypt::specs::algebraic;
use crate::mlsigcrypt::specs::keccak::{KeccakSponge, zeroize_sponge};
use crate::mlsigcrypt::specs::ml::field::{decompose, fqmul, make_hint, reduce32};
use crate::mlsigcrypt::specs::ml::matrix::PolyMatrix;
use crate::mlsigcrypt::specs::ml::packing::{
    pack_sig, polyw1_pack, unpack_pk, unpack_sig, unpack_sk,
};
use crate::mlsigcrypt::specs::ml::params::{
    BETA, GAMMA1, GAMMA2, K, L, LAMBDA2_BYTES, N, OMEGA, POLYW1_BYTES, SIG_BYTES,
};
use crate::mlsigcrypt::specs::ml::poly::{Poly, zeroize_poly};
use crate::mlsigcrypt::specs::ml::sampling::{
    expand_a, expand_mask, sample_in_ball, shake256_absorb_squeeze,
};
use crate::mlsigcrypt::specs::ml::vec::{PolyVec, zeroize_polyvec};
use crate::mlsigcrypt::specs::sha512::sha3_512_hash as sha3_512;
use crate::os_random::fill_os_random_array;
use crate::zeroize::{zeroize_array, zeroize_mem, zeroize_slice};
use core::sync::atomic::{Ordering, compiler_fence};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SigncryptOpenFailed;

impl core::fmt::Display for SigncryptOpenFailed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "signcrypt open failed")
    }
}

struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    fn new() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        unsafe { zeroize_mem(self.0.as_mut_ptr(), N) };
        compiler_fence(Ordering::SeqCst);
    }
}

fn compute_aad_digest(aad: &[u8], out: &mut [u8; AAD_DIGEST_LEN]) {
    sha3_512(&[DOMAIN_AAD, aad], out);
}

fn compute_challenge(
    w1_packed: &[u8; K * POLYW1_BYTES],
    encap: &[u8; ENCAP_LEN],
    aad_digest: &[u8; AAD_DIGEST_LEN],
    pk_sig_s: &[u8; SIG_PK_LEN],
    pk_enc_r: &[u8; ENC_PK_LEN],
    ct: &[u8],
    out: &mut [u8; LAMBDA2_BYTES],
) {
    let ct_len_be = (ct.len() as u64).to_be_bytes();
    shake256_absorb_squeeze(
        &[
            DOMAIN_CHAL,
            w1_packed,
            encap,
            aad_digest,
            pk_sig_s,
            pk_enc_r,
            &ct_len_be,
            ct,
        ],
        out,
    );
}

fn xor_keystream_in_place(
    message_key: &[u8; 32],
    key_id_s: &[u8; KEY_ID_LEN],
    key_id_r: &[u8; KEY_ID_LEN],
    encap: &[u8; ENCAP_LEN],
    buf: &mut [u8],
) {
    let mut sponge = KeccakSponge::<SHAKE256_RATE>::new();
    let mut block = [0u8; SHAKE256_RATE];

    sponge.absorb(DOMAIN_ENC);
    sponge.absorb(message_key);
    sponge.absorb(key_id_s);
    sponge.absorb(key_id_r);
    sponge.absorb(encap);
    sponge.finalize(SHAKE_SUFFIX);

    let mut offset = 0usize;
    while offset < buf.len() {
        let take = (buf.len() - offset).min(SHAKE256_RATE);
        sponge.squeeze(&mut block[..take]);
        for i in 0..take {
            buf[offset + i] ^= block[i];
        }
        zeroize_slice(&mut block[..take]);
        offset += take;
    }

    zeroize_slice(&mut block);
    zeroize_sponge(&mut sponge);
}

fn verify_signature_challenge(
    c_tilde: &[u8; LAMBDA2_BYTES],
    z_bytes: &[u8; SIG_Z_LEN],
    hint_bytes: &[u8; SIG_HINT_LEN],
    pk_sig_s: &[u8; SIG_PK_LEN],
    pk_enc_r: &[u8; ENC_PK_LEN],
    encap: &[u8; ENCAP_LEN],
    aad_digest: &[u8; AAD_DIGEST_LEN],
    ct: &[u8],
) -> bool {
    let mut pk_rho = [0u8; 32];
    let mut t1 = PolyVec::<K>::zero();
    unpack_pk(&mut pk_rho, &mut t1, pk_sig_s);

    let mut sig = [0u8; SIG_BYTES];
    sig[..SIG_CTILDE_LEN].copy_from_slice(c_tilde);
    sig[SIG_CTILDE_LEN..SIG_CTILDE_LEN + SIG_Z_LEN].copy_from_slice(z_bytes);
    sig[SIG_CTILDE_LEN + SIG_Z_LEN..].copy_from_slice(hint_bytes);

    let mut z = PolyVec::<L>::zero();
    let mut h = PolyVec::<K>::zero();
    let mut parsed_ctilde = [0u8; LAMBDA2_BYTES];
    if !unpack_sig(&mut parsed_ctilde, &mut z, &mut h, &sig) {
        zeroize_array(&mut sig);
        zeroize_polyvec(&mut z);
        zeroize_polyvec(&mut h);
        return false;
    }
    zeroize_array(&mut sig);

    if !z.check_norm_lt(GAMMA1 - BETA) {
        zeroize_polyvec(&mut z);
        zeroize_polyvec(&mut h);
        return false;
    }

    let mut mat_a = PolyMatrix::zero();
    expand_a(&mut mat_a, &pk_rho);

    let mut c_hat = Poly::zero();
    sample_in_ball(&mut c_hat, &parsed_ctilde);
    c_hat.ntt();

    z.ntt();
    let mut az = PolyVec::<K>::zero();
    mat_a.matvec_ntt(&z, &mut az);

    let mut ct1 = PolyVec::<K>::zero();
    for i in 0..K {
        ct1.polys[i].coeffs.copy_from_slice(&t1.polys[i].coeffs);
        ct1.polys[i].shiftl();
        ct1.polys[i].ntt();
        for j in 0..N {
            ct1.polys[i].coeffs[j] = fqmul(c_hat.coeffs[j], ct1.polys[i].coeffs[j]);
        }
    }

    let mut w = PolyVec::<K>::zero();
    PolyMatrix::verify_product(&az, &ct1, &mut w);
    w.inv_ntt();
    w.reduce();
    w.caddq();

    let mut w1 = PolyVec::<K>::zero();
    PolyVec::<K>::use_hint_into(&h, &w, &mut w1);

    let mut w1_packed = [0u8; K * POLYW1_BYTES];
    for i in 0..K {
        let start = i * POLYW1_BYTES;
        let end = start + POLYW1_BYTES;
        let packed: &mut [u8; POLYW1_BYTES] = (&mut w1_packed[start..end])
            .try_into()
            .expect("fixed-size w1 chunk");
        polyw1_pack(packed, &w1.polys[i]);
    }

    let mut expected = [0u8; LAMBDA2_BYTES];
    compute_challenge(
        &w1_packed,
        encap,
        aad_digest,
        pk_sig_s,
        pk_enc_r,
        ct,
        &mut expected,
    );

    let mut diff = 0u8;
    for i in 0..LAMBDA2_BYTES {
        diff |= expected[i] ^ parsed_ctilde[i];
    }

    zeroize_polyvec(&mut z);
    zeroize_polyvec(&mut h);
    zeroize_polyvec(&mut az);
    zeroize_polyvec(&mut ct1);
    zeroize_polyvec(&mut w);
    zeroize_polyvec(&mut w1);
    zeroize_poly(&mut c_hat);
    zeroize_array(&mut pk_rho);
    zeroize_array(&mut parsed_ctilde);
    zeroize_array(&mut w1_packed);
    zeroize_array(&mut expected);

    diff == 0
}

pub(crate) fn signcrypt(
    sk_user_s: &UserSecretKey,
    pk_user_s: &UserPublicKey,
    pk_user_r: &UserPublicKey,
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, SigncryptOpenFailed> {
    let pt_len = plaintext.len();
    let packet_len = pt_len
        .checked_add(PACKET_FIXED_OVERHEAD)
        .ok_or(SigncryptOpenFailed)?;

    if out.len() < packet_len {
        return Err(SigncryptOpenFailed);
    }

    if !pk_user_s.verify_consistency() || !pk_user_r.verify_consistency() {
        return Err(SigncryptOpenFailed);
    }

    out[PKT_ALG_ID_OFF..PKT_VERSION_OFF].copy_from_slice(ALG_ID);
    out[PKT_VERSION_OFF] = VERSION;
    out[PKT_KEY_ID_S_OFF..PKT_KEY_ID_S_OFF + KEY_ID_LEN].copy_from_slice(pk_user_s.key_id());
    out[PKT_KEY_ID_R_OFF..PKT_KEY_ID_R_OFF + KEY_ID_LEN].copy_from_slice(pk_user_r.key_id());

    let mut aad_digest = Secret::<{ AAD_DIGEST_LEN }>::new();
    compute_aad_digest(aad, &mut aad_digest.0);

    let mut rho = [0u8; 32];
    let mut k_seed = [0u8; 32];
    let mut tr = [0u8; 64];
    let mut s1 = PolyVec::<L>::zero();
    let mut s2 = PolyVec::<K>::zero();
    let mut t0 = PolyVec::<K>::zero();
    unpack_sk(
        &mut rho,
        &mut k_seed,
        &mut tr,
        &mut s1,
        &mut s2,
        &mut t0,
        &sk_user_s.sk_sig,
    );
    s1.ntt();
    s2.ntt();
    t0.ntt();

    let mut rnd = Secret::<32>::new();
    fill_os_random_array(&mut rnd.0).map_err(|_| SigncryptOpenFailed)?;

    let mut rho_prime = [0u8; 64];
    shake256_absorb_squeeze(
        &[
            &k_seed,
            &rnd.0,
            &aad_digest.0,
            pk_user_s.key_id(),
            pk_user_r.key_id(),
        ],
        &mut rho_prime,
    );
    drop(rnd);

    let mut mat_a = PolyMatrix::zero();
    expand_a(&mut mat_a, &rho);

    let ct_len_be = (pt_len as u64).to_be_bytes();
    out[PKT_CT_LEN_OFF..PKT_CT_OFF].copy_from_slice(&ct_len_be);

    let mut kappa: u16 = 0;
    let mut y = PolyVec::<L>::zero();
    let mut y_hat = PolyVec::<L>::zero();
    let mut w_hat = PolyVec::<K>::zero();
    let mut w = PolyVec::<K>::zero();
    let mut w1 = PolyVec::<K>::zero();
    let mut w0 = PolyVec::<K>::zero();
    let mut c_hat = Poly::zero();
    let mut cs1 = PolyVec::<L>::zero();
    let mut cs2 = PolyVec::<K>::zero();
    let mut ct0 = PolyVec::<K>::zero();
    let mut z = PolyVec::<L>::zero();
    let mut h = PolyVec::<K>::zero();
    let mut c_tilde = [0u8; LAMBDA2_BYTES];
    let mut w1_packed = [0u8; K * POLYW1_BYTES];
    let mut encap = [0u8; ENCAP_LEN];
    let mut message_key = Secret::<32>::new();

    'outer: loop {
        expand_mask(&mut y, &rho_prime, kappa);
        kappa = kappa.wrapping_add(L as u16);

        for i in 0..L {
            y_hat.polys[i].coeffs.copy_from_slice(&y.polys[i].coeffs);
            y_hat.polys[i].ntt();
        }
        mat_a.matvec_ntt(&y_hat, &mut w_hat);

        for i in 0..K {
            w.polys[i].coeffs.copy_from_slice(&w_hat.polys[i].coeffs);
            w.polys[i].inv_ntt();
            w.polys[i].reduce();
            w.polys[i].caddq();
        }

        for i in 0..K {
            for j in 0..N {
                let (r1, r0) = decompose(w.polys[i].coeffs[j]);
                w1.polys[i].coeffs[j] = r1;
                w0.polys[i].coeffs[j] = r0;
            }
        }

        for i in 0..K {
            let start = i * POLYW1_BYTES;
            let end = start + POLYW1_BYTES;
            let packed: &mut [u8; POLYW1_BYTES] = (&mut w1_packed[start..end])
                .try_into()
                .expect("fixed-size w1 chunk");
            polyw1_pack(packed, &w1.polys[i]);
        }

        if !algebraic::encapsulate_from_mask(
            pk_user_r.rho_shared(),
            pk_user_r.pk_enc(),
            &y_hat,
            &mut encap,
            &mut message_key.0,
        ) {
            zeroize_slice(out);
            return Err(SigncryptOpenFailed);
        }

        out[PKT_CT_OFF..PKT_CT_OFF + pt_len].copy_from_slice(plaintext);
        xor_keystream_in_place(
            &message_key.0,
            pk_user_s.key_id(),
            pk_user_r.key_id(),
            &encap,
            &mut out[PKT_CT_OFF..PKT_CT_OFF + pt_len],
        );

        compute_challenge(
            &w1_packed,
            &encap,
            &aad_digest.0,
            pk_user_s.pk_sig(),
            pk_user_r.pk_enc(),
            &out[PKT_CT_OFF..PKT_CT_OFF + pt_len],
            &mut c_tilde,
        );

        sample_in_ball(&mut c_hat, &c_tilde);
        c_hat.ntt();

        for i in 0..L {
            for j in 0..N {
                cs1.polys[i].coeffs[j] = fqmul(c_hat.coeffs[j], s1.polys[i].coeffs[j]);
            }
            cs1.polys[i].inv_ntt();
            cs1.polys[i].reduce();
        }
        for i in 0..K {
            for j in 0..N {
                cs2.polys[i].coeffs[j] = fqmul(c_hat.coeffs[j], s2.polys[i].coeffs[j]);
            }
            cs2.polys[i].inv_ntt();
            cs2.polys[i].reduce();

            for j in 0..N {
                ct0.polys[i].coeffs[j] = fqmul(c_hat.coeffs[j], t0.polys[i].coeffs[j]);
            }
            ct0.polys[i].inv_ntt();
            ct0.polys[i].reduce();
        }

        for i in 0..L {
            for j in 0..N {
                z.polys[i].coeffs[j] = y.polys[i].coeffs[j].wrapping_add(cs1.polys[i].coeffs[j]);
            }
        }
        if !z.check_norm_lt(GAMMA1 - BETA) {
            continue 'outer;
        }

        let mut reject_r0 = false;
        for i in 0..K {
            for j in 0..N {
                let value = w0.polys[i].coeffs[j].wrapping_sub(cs2.polys[i].coeffs[j]);
                let r0 = reduce32(value);
                w0.polys[i].coeffs[j] = r0;
                if r0.abs() >= GAMMA2 - BETA {
                    reject_r0 = true;
                }
            }
        }
        if reject_r0 {
            continue 'outer;
        }

        if !ct0.check_norm_lt(GAMMA2) {
            continue 'outer;
        }

        let mut hint_weight = 0usize;
        for i in 0..K {
            for j in 0..N {
                let a0 = reduce32(w0.polys[i].coeffs[j].wrapping_add(ct0.polys[i].coeffs[j]));
                w0.polys[i].coeffs[j] = a0;
                let h_bit = make_hint(a0, w1.polys[i].coeffs[j]);
                h.polys[i].coeffs[j] = h_bit;
                hint_weight += h_bit as usize;
            }
        }
        if hint_weight > OMEGA {
            continue 'outer;
        }

        break 'outer;
    }

    let mut sig = [0u8; SIG_BYTES];
    pack_sig(&mut sig, &c_tilde, &z, &h);

    out[PKT_ENCAP_OFF..PKT_ENCAP_OFF + ENCAP_LEN].copy_from_slice(&encap);
    out[PKT_Z_OFF..PKT_Z_OFF + SIG_Z_LEN]
        .copy_from_slice(&sig[SIG_CTILDE_LEN..SIG_CTILDE_LEN + SIG_Z_LEN]);
    out[PKT_CTILDE_OFF..PKT_CTILDE_OFF + SIG_CTILDE_LEN].copy_from_slice(&sig[..SIG_CTILDE_LEN]);
    out[PKT_HINT_OFF..PKT_HINT_OFF + SIG_HINT_LEN]
        .copy_from_slice(&sig[SIG_CTILDE_LEN + SIG_Z_LEN..]);

    zeroize_polyvec(&mut s1);
    zeroize_polyvec(&mut s2);
    zeroize_polyvec(&mut t0);
    zeroize_polyvec(&mut y);
    zeroize_polyvec(&mut y_hat);
    zeroize_polyvec(&mut w_hat);
    zeroize_polyvec(&mut w);
    zeroize_polyvec(&mut w1);
    zeroize_polyvec(&mut w0);
    zeroize_polyvec(&mut cs1);
    zeroize_polyvec(&mut cs2);
    zeroize_polyvec(&mut ct0);
    zeroize_polyvec(&mut z);
    zeroize_polyvec(&mut h);
    zeroize_poly(&mut c_hat);
    zeroize_array(&mut rho);
    zeroize_array(&mut k_seed);
    zeroize_array(&mut tr);
    zeroize_array(&mut rho_prime);
    zeroize_array(&mut c_tilde);
    zeroize_array(&mut w1_packed);
    zeroize_array(&mut sig);
    drop(aad_digest);
    drop(message_key);

    Ok(packet_len)
}

pub(crate) fn unsigncrypt(
    sk_user_r: &UserSecretKey,
    pk_user_s: &UserPublicKey,
    pk_user_r: &UserPublicKey,
    aad: &[u8],
    packet: &[u8],
    out: &mut [u8],
) -> Result<usize, SigncryptOpenFailed> {
    let result = unsigncrypt_inner(sk_user_r, pk_user_s, pk_user_r, aad, packet, out);
    if result.is_err() && packet.len() > PACKET_FIXED_OVERHEAD {
        let ct_len = packet.len() - PACKET_FIXED_OVERHEAD;
        let to_zero = ct_len.min(out.len());
        unsafe { zeroize_mem(out.as_mut_ptr(), to_zero) };
    }
    result
}

fn unsigncrypt_inner(
    sk_user_r: &UserSecretKey,
    pk_user_s: &UserPublicKey,
    pk_user_r: &UserPublicKey,
    aad: &[u8],
    packet: &[u8],
    out: &mut [u8],
) -> Result<usize, SigncryptOpenFailed> {
    if packet.len() < PACKET_FIXED_OVERHEAD {
        return Err(SigncryptOpenFailed);
    }

    let ct_len = {
        let bytes: [u8; 8] = packet[PKT_CT_LEN_OFF..PKT_CT_OFF]
            .try_into()
            .map_err(|_| SigncryptOpenFailed)?;
        u64::from_be_bytes(bytes) as usize
    };
    if packet.len() != PACKET_FIXED_OVERHEAD + ct_len {
        return Err(SigncryptOpenFailed);
    }
    if out.len() < ct_len {
        return Err(SigncryptOpenFailed);
    }
    if !pk_user_s.verify_consistency() || !pk_user_r.verify_consistency() {
        return Err(SigncryptOpenFailed);
    }
    if !ct_eq(&packet[PKT_ALG_ID_OFF..PKT_VERSION_OFF], ALG_ID) {
        return Err(SigncryptOpenFailed);
    }
    if packet[PKT_VERSION_OFF] != VERSION {
        return Err(SigncryptOpenFailed);
    }
    if !ct_eq(
        &packet[PKT_KEY_ID_S_OFF..PKT_KEY_ID_S_OFF + KEY_ID_LEN],
        pk_user_s.key_id(),
    ) {
        return Err(SigncryptOpenFailed);
    }
    if !ct_eq(
        &packet[PKT_KEY_ID_R_OFF..PKT_KEY_ID_R_OFF + KEY_ID_LEN],
        pk_user_r.key_id(),
    ) {
        return Err(SigncryptOpenFailed);
    }

    let encap: &[u8; ENCAP_LEN] = packet[PKT_ENCAP_OFF..PKT_ENCAP_OFF + ENCAP_LEN]
        .try_into()
        .map_err(|_| SigncryptOpenFailed)?;
    let z_bytes: &[u8; SIG_Z_LEN] = packet[PKT_Z_OFF..PKT_Z_OFF + SIG_Z_LEN]
        .try_into()
        .map_err(|_| SigncryptOpenFailed)?;
    let c_tilde: &[u8; SIG_CTILDE_LEN] = packet[PKT_CTILDE_OFF..PKT_CTILDE_OFF + SIG_CTILDE_LEN]
        .try_into()
        .map_err(|_| SigncryptOpenFailed)?;
    let hint_bytes: &[u8; SIG_HINT_LEN] = packet[PKT_HINT_OFF..PKT_HINT_OFF + SIG_HINT_LEN]
        .try_into()
        .map_err(|_| SigncryptOpenFailed)?;
    let ct = &packet[PKT_CT_OFF..PKT_CT_OFF + ct_len];

    let mut aad_digest = Secret::<{ AAD_DIGEST_LEN }>::new();
    compute_aad_digest(aad, &mut aad_digest.0);

    if !verify_signature_challenge(
        c_tilde,
        z_bytes,
        hint_bytes,
        pk_user_s.pk_sig(),
        pk_user_r.pk_enc(),
        encap,
        &aad_digest.0,
        ct,
    ) {
        return Err(SigncryptOpenFailed);
    }

    let mut message_key = Secret::<32>::new();
    if !algebraic::decapsulate_from_seed(&sk_user_r.sk_enc_seed, encap, &mut message_key.0) {
        return Err(SigncryptOpenFailed);
    }

    out[..ct_len].copy_from_slice(ct);
    xor_keystream_in_place(
        &message_key.0,
        pk_user_s.key_id(),
        pk_user_r.key_id(),
        encap,
        &mut out[..ct_len],
    );

    drop(message_key);
    drop(aad_digest);
    Ok(ct_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlsigcrypt::keys::keygen;

    fn make_keypair(seed: u8) -> (UserSecretKey, UserPublicKey) {
        keygen(&[seed; MASTER_SECRET_LEN])
    }

    #[test]
    fn packet_overhead_matches_constant() {
        let (sk_s, pk_s) = make_keypair(0x01);
        let (_, pk_r) = make_keypair(0x02);
        let mut pkt = vec![0u8; PACKET_FIXED_OVERHEAD];
        let written = signcrypt(&sk_s, &pk_s, &pk_r, b"", b"", &mut pkt).unwrap();
        assert_eq!(written, PACKET_FIXED_OVERHEAD);
    }

    #[test]
    fn roundtrip_short_message() {
        let (sk_s, pk_s) = make_keypair(0x10);
        let (sk_r, pk_r) = make_keypair(0x11);
        let msg = b"v3 short message";
        let aad = b"v3 aad";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, aad, msg, &mut pkt).unwrap();
        let mut out = vec![0u8; msg.len()];
        let out_len = unsigncrypt(&sk_r, &pk_s, &pk_r, aad, &pkt[..pkt_len], &mut out).unwrap();
        assert_eq!(&out[..out_len], msg);
    }

    #[test]
    fn roundtrip_large_message() {
        let (sk_s, pk_s) = make_keypair(0x20);
        let (sk_r, pk_r) = make_keypair(0x21);
        let msg = vec![0xABu8; 2048];
        let aad = b"v3 large";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, aad, &msg, &mut pkt).unwrap();
        let mut out = vec![0u8; msg.len()];
        let out_len = unsigncrypt(&sk_r, &pk_s, &pk_r, aad, &pkt[..pkt_len], &mut out).unwrap();
        assert_eq!(&out[..out_len], &msg);
    }

    #[test]
    fn truncated_packet_rejected() {
        let (sk_s, pk_s) = make_keypair(0x30);
        let (sk_r, pk_r) = make_keypair(0x31);
        let msg = b"truncate me";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();
        let mut out = vec![0u8; msg.len()];
        assert!(unsigncrypt(&sk_r, &pk_s, &pk_r, b"", &pkt[..pkt_len - 1], &mut out).is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (sk_s, pk_s) = make_keypair(0x40);
        let (sk_r, pk_r) = make_keypair(0x41);
        let msg = b"cipher tamper";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();
        pkt[PKT_CT_OFF] ^= 0x01;
        let mut out = vec![0u8; msg.len()];
        assert!(unsigncrypt(&sk_r, &pk_s, &pk_r, b"", &pkt[..pkt_len], &mut out).is_err());
    }

    #[test]
    fn tampered_encap_rejected() {
        let (sk_s, pk_s) = make_keypair(0x45);
        let (sk_r, pk_r) = make_keypair(0x46);
        let msg = b"encap tamper";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();
        pkt[PKT_ENCAP_OFF + 42] ^= 0x80;
        let mut out = vec![0u8; msg.len()];
        assert!(unsigncrypt(&sk_r, &pk_s, &pk_r, b"", &pkt[..pkt_len], &mut out).is_err());
    }

    #[test]
    fn tampered_signature_rejected() {
        let (sk_s, pk_s) = make_keypair(0x50);
        let (sk_r, pk_r) = make_keypair(0x51);
        let msg = b"sig tamper";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();
        pkt[PKT_HINT_OFF] ^= 0x01;
        let mut out = vec![0u8; msg.len()];
        assert!(unsigncrypt(&sk_r, &pk_s, &pk_r, b"", &pkt[..pkt_len], &mut out).is_err());
    }

    #[test]
    fn tampered_aad_rejected() {
        let (sk_s, pk_s) = make_keypair(0x60);
        let (sk_r, pk_r) = make_keypair(0x61);
        let msg = b"aad tamper";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"right", msg, &mut pkt).unwrap();
        let mut out = vec![0u8; msg.len()];
        assert!(unsigncrypt(&sk_r, &pk_s, &pk_r, b"wrong", &pkt[..pkt_len], &mut out).is_err());
    }

    #[test]
    fn tampered_key_id_s_rejected() {
        let (sk_s, pk_s) = make_keypair(0x88);
        let (sk_r, pk_r) = make_keypair(0x89);
        let msg = b"sender key id tamper";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();
        pkt[PKT_KEY_ID_S_OFF] ^= 0x01;
        let mut out = vec![0u8; msg.len()];
        assert!(unsigncrypt(&sk_r, &pk_s, &pk_r, b"", &pkt[..pkt_len], &mut out).is_err());
    }

    #[test]
    fn tampered_key_id_r_rejected() {
        let (sk_s, pk_s) = make_keypair(0x8A);
        let (sk_r, pk_r) = make_keypair(0x8B);
        let msg = b"recipient key id tamper";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();
        pkt[PKT_KEY_ID_R_OFF] ^= 0x01;
        let mut out = vec![0u8; msg.len()];
        assert!(unsigncrypt(&sk_r, &pk_s, &pk_r, b"", &pkt[..pkt_len], &mut out).is_err());
    }
}
