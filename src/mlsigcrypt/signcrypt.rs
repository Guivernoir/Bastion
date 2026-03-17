/// MLSigcrypt-v2 level-2 signcrypt and unsigncrypt algorithms.
///
/// ## Signcrypt
///
/// 1. Validate sender and recipient public identities.
/// 2. ML-KEM-1024 encapsulation -> `(kem_ct, κ)` using a level-2 key derived
///    from the shared lattice matrix.
/// 3. SHA3-512("MLSigcrypt-v2/aad\x02" || aad) -> `aad_digest`.
/// 4. Build `S_E` from `κ`, `key_id_S`, `key_id_R`, and `kem_ct`.
/// 5. XOR the SHAKE-256 keystream into the payload buffer to produce `ct`.
/// 6. Build `S_T` over the public transcript and `ct` -> `T`.
/// 7. ML-DSA-87.Sign(`sk_sig_S`, `T`) -> `sig`.
/// 8. Encode packet; zeroize all sensitive intermediates.
///
/// ## Unsigncrypt
///
/// 1. Parse packet in constant-shape form.
/// 2. Verify `alg_id`, `version`, `key_id_S`, and `key_id_R`.
/// 3. Compute `aad_digest`.
/// 4. Build `S_T` and verify the signature.
/// 5. ML-KEM-1024 decapsulate only after signature verification.
/// 6. Rebuild `S_E`, squeeze the keystream, and recover plaintext.
/// 7. Zeroize all sensitive intermediates.
///
/// All externally observable failures collapse to `SigncryptOpenFailed`.
use super::keys::{UserPublicKey, UserSecretKey};
use super::params::*;
use crate::constant_time::ct_eq;
use crate::mlsigcrypt::specs::mldsa87;
use crate::mlsigcrypt::specs::mlkem1024::keccak::{KeccakSponge, zeroize_sponge};
use crate::mlsigcrypt::specs::mlkem1024::{self, Ciphertext, DecapKey, EncapKey, SharedSecret};
use crate::mlsigcrypt::specs::sha3_512::hash as sha3_512;
use crate::os_random::fill_os_random_array;
use crate::zeroize::{zeroize_mem, zeroize_slice};
use core::sync::atomic::{Ordering, compiler_fence};

/// Opaque failure result from `unsigncrypt`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SigncryptOpenFailed;

impl core::fmt::Display for SigncryptOpenFailed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "signcrypt open failed")
    }
}

/// A fixed-size byte array that is zeroized automatically on `Drop`.
struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    fn new() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid writable array of N bytes.
        unsafe { zeroize_mem(self.0.as_mut_ptr(), N) };
        compiler_fence(Ordering::SeqCst);
    }
}

fn compute_aad_digest(aad: &[u8], out: &mut [u8; AAD_DIGEST_LEN]) {
    sha3_512(&[DOMAIN_AAD, aad], out);
}

fn compute_transcript(
    key_id_s: &[u8; KEY_ID_LEN],
    key_id_r: &[u8; KEY_ID_LEN],
    pk_enc_s: &[u8],
    pk_sig_s: &[u8],
    pk_enc_r: &[u8],
    pk_sig_r: &[u8],
    kem_ct: &[u8],
    aad_digest: &[u8; AAD_DIGEST_LEN],
    ct: &[u8],
    out: &mut [u8; TRANSCRIPT_LEN],
) {
    let mut sponge = KeccakSponge::<SHAKE256_RATE>::new();
    let ct_len_be = (ct.len() as u64).to_be_bytes();
    sponge.absorb(DOMAIN_TRANSCRIPT);
    sponge.absorb(key_id_s);
    sponge.absorb(key_id_r);
    sponge.absorb(pk_enc_s);
    sponge.absorb(pk_sig_s);
    sponge.absorb(pk_enc_r);
    sponge.absorb(pk_sig_r);
    sponge.absorb(kem_ct);
    sponge.absorb(aad_digest);
    sponge.absorb(&ct_len_be);
    sponge.absorb(ct);
    sponge.finalize(SHAKE_SUFFIX);
    sponge.squeeze(out);
    zeroize_sponge(&mut sponge);
}

fn xor_keystream_in_place(
    kappa: &[u8; KEM_SS_LEN],
    key_id_s: &[u8; KEY_ID_LEN],
    key_id_r: &[u8; KEY_ID_LEN],
    kem_ct: &[u8],
    buf: &mut [u8],
) {
    let mut sponge = KeccakSponge::<SHAKE256_RATE>::new();
    let mut block = [0u8; SHAKE256_RATE];

    sponge.absorb(DOMAIN_ENC);
    sponge.absorb(kappa);
    sponge.absorb(key_id_s);
    sponge.absorb(key_id_r);
    sponge.absorb(kem_ct);
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

    let mut entropy = Secret::<32>::new();
    fill_os_random_array(&mut entropy.0).map_err(|_| SigncryptOpenFailed)?;

    let mut ek = EncapKey([0u8; KEM_EK_LEN]);
    ek.0.copy_from_slice(pk_user_r.pk_enc());

    let mut kem_ct = Ciphertext([0u8; KEM_CT_LEN]);
    let mut ss = SharedSecret([0u8; KEM_SS_LEN]);
    mlkem1024::encaps(&ek, &entropy.0, &mut kem_ct, &mut ss);

    out[PKT_KEM_CT_OFF..PKT_KEM_CT_OFF + KEM_CT_LEN].copy_from_slice(kem_ct.as_bytes());

    let mut aad_digest = Secret::<{ AAD_DIGEST_LEN }>::new();
    compute_aad_digest(aad, &mut aad_digest.0);

    let ct_len_be = (pt_len as u64).to_be_bytes();
    out[PKT_CT_LEN_OFF..PKT_CT_OFF].copy_from_slice(&ct_len_be);
    out[PKT_CT_OFF..PKT_CT_OFF + pt_len].copy_from_slice(plaintext);

    let mut kappa = Secret::<{ KEM_SS_LEN }>::new();
    kappa.0.copy_from_slice(ss.as_bytes());
    drop(ss);
    xor_keystream_in_place(
        &kappa.0,
        pk_user_s.key_id(),
        pk_user_r.key_id(),
        kem_ct.as_bytes(),
        &mut out[PKT_CT_OFF..PKT_CT_OFF + pt_len],
    );
    drop(kappa);

    let mut transcript = Secret::<{ TRANSCRIPT_LEN }>::new();
    compute_transcript(
        pk_user_s.key_id(),
        pk_user_r.key_id(),
        pk_user_s.pk_enc(),
        pk_user_s.pk_sig(),
        pk_user_r.pk_enc(),
        pk_user_r.pk_sig(),
        &out[PKT_KEM_CT_OFF..PKT_KEM_CT_OFF + KEM_CT_LEN],
        &aad_digest.0,
        &out[PKT_CT_OFF..PKT_CT_OFF + pt_len],
        &mut transcript.0,
    );
    drop(aad_digest);

    let mut rnd = Secret::<32>::new();
    fill_os_random_array(&mut rnd.0).map_err(|_| SigncryptOpenFailed)?;

    let mut sig = [0u8; SIG_LEN];
    mldsa87::sign(&mut sig, &transcript.0, &sk_user_s.sk_sig, &rnd.0);
    drop(rnd);
    drop(transcript);

    let sig_off = PKT_CT_OFF + pt_len;
    out[sig_off..sig_off + SIG_LEN].copy_from_slice(&sig);

    // SAFETY: both arrays are valid writable buffers.
    unsafe {
        zeroize_mem(sig.as_mut_ptr(), SIG_LEN);
        zeroize_mem(kem_ct.0.as_mut_ptr(), KEM_CT_LEN);
    }

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
        // SAFETY: `out` is valid for `to_zero` bytes.
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

    // verify_consistency() above guarantees both public-key objects carry
    // canonical key_id values derived from their public components, so these
    // packet checks compare against verified identity material.
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

    let kem_ct = &packet[PKT_KEM_CT_OFF..PKT_KEM_CT_OFF + KEM_CT_LEN];
    let ct = &packet[PKT_CT_OFF..PKT_CT_OFF + ct_len];
    let sig_off = PKT_CT_OFF + ct_len;
    let sig: &[u8; SIG_LEN] = packet[sig_off..sig_off + SIG_LEN]
        .try_into()
        .map_err(|_| SigncryptOpenFailed)?;

    let mut aad_digest = Secret::<{ AAD_DIGEST_LEN }>::new();
    compute_aad_digest(aad, &mut aad_digest.0);

    let key_id_s: &[u8; KEY_ID_LEN] = packet[PKT_KEY_ID_S_OFF..PKT_KEY_ID_S_OFF + KEY_ID_LEN]
        .try_into()
        .map_err(|_| SigncryptOpenFailed)?;
    let key_id_r: &[u8; KEY_ID_LEN] = packet[PKT_KEY_ID_R_OFF..PKT_KEY_ID_R_OFF + KEY_ID_LEN]
        .try_into()
        .map_err(|_| SigncryptOpenFailed)?;

    let mut transcript = Secret::<{ TRANSCRIPT_LEN }>::new();
    compute_transcript(
        key_id_s,
        key_id_r,
        pk_user_s.pk_enc(),
        pk_user_s.pk_sig(),
        pk_user_r.pk_enc(),
        pk_user_r.pk_sig(),
        kem_ct,
        &aad_digest.0,
        ct,
        &mut transcript.0,
    );

    let sig_valid = mldsa87::verify(sig, &transcript.0, pk_user_s.pk_sig());
    drop(transcript);
    if !sig_valid {
        return Err(SigncryptOpenFailed);
    }

    let mut dk = DecapKey([0u8; KEM_DK_LEN]);
    dk.0.copy_from_slice(&sk_user_r.sk_enc);

    let mut kem_ct_typed = Ciphertext([0u8; KEM_CT_LEN]);
    kem_ct_typed.0.copy_from_slice(kem_ct);

    let mut ss = SharedSecret([0u8; KEM_SS_LEN]);
    mlkem1024::decaps(&dk, &kem_ct_typed, &mut ss);
    // SAFETY: local ciphertext buffer is writable.
    unsafe { zeroize_mem(kem_ct_typed.0.as_mut_ptr(), KEM_CT_LEN) };

    let mut kappa = Secret::<{ KEM_SS_LEN }>::new();
    kappa.0.copy_from_slice(ss.as_bytes());
    drop(ss);

    out[..ct_len].copy_from_slice(ct);
    xor_keystream_in_place(&kappa.0, key_id_s, key_id_r, kem_ct, &mut out[..ct_len]);

    drop(kappa);
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
        let msg = b"v2 short message";
        let aad = b"v2 aad";
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
        let msg = vec![0xABu8; 4096];
        let aad = b"v2 large";
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
    fn tampered_kem_ct_rejected() {
        let (sk_s, pk_s) = make_keypair(0x45);
        let (sk_r, pk_r) = make_keypair(0x46);
        let msg = b"kem ct tamper";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();
        pkt[PKT_KEM_CT_OFF + 42] ^= 0x80;
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
        pkt[pkt_len - 1] ^= 0x01;
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
    fn output_buffer_too_small_returns_err() {
        let (sk_s, pk_s) = make_keypair(0x70);
        let (_, pk_r) = make_keypair(0x71);
        let msg = b"small output";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD - 1];
        assert!(signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).is_err());
    }

    #[test]
    fn wrong_sender_key_rejected() {
        let (sk_s, pk_s) = make_keypair(0x80);
        let (sk_r, pk_r) = make_keypair(0x81);
        let (_, wrong_pk_s) = make_keypair(0x82);
        let msg = b"wrong sender";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();
        let mut out = vec![0u8; msg.len()];
        assert!(unsigncrypt(&sk_r, &wrong_pk_s, &pk_r, b"", &pkt[..pkt_len], &mut out).is_err());
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

    #[test]
    fn wrong_recipient_key_rejected() {
        let (sk_s, pk_s) = make_keypair(0x90);
        let (sk_r, pk_r) = make_keypair(0x91);
        let (_, wrong_pk_r) = make_keypair(0x92);
        let msg = b"wrong recipient";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();
        let mut out = vec![0u8; msg.len()];
        assert!(unsigncrypt(&sk_r, &pk_s, &wrong_pk_r, b"", &pkt[..pkt_len], &mut out).is_err());
    }

    #[test]
    fn two_signcrypts_same_message_different_kem_ct() {
        let (sk_s, pk_s) = make_keypair(0xA0);
        let (_, pk_r) = make_keypair(0xA1);
        let msg = b"same message";
        let mut pkt_a = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let mut pkt_b = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let len_a = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt_a).unwrap();
        let len_b = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt_b).unwrap();
        assert_eq!(len_a, len_b);
        assert_ne!(
            &pkt_a[PKT_KEM_CT_OFF..PKT_KEM_CT_OFF + KEM_CT_LEN],
            &pkt_b[PKT_KEM_CT_OFF..PKT_KEM_CT_OFF + KEM_CT_LEN]
        );
    }
}
