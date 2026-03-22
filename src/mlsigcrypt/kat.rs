//! MLSigcrypt-v3 Known-Answer Test Vectors
//!
//! Two test entry points:
//!
//! 1. Verify deterministic roundtrip and tamper rejection (runs in CI):
//!    ```
//!    cargo test kat
//!    ```
//!
//! 2. Verify against pinned hex values:
//!    ```
//!    cargo test kat::tests::known_answer_assertions -- --nocapture
//!    ```

#[cfg(test)]
mod tests {
    use crate::mlsigcrypt::keys::{ENCODED_PUBLIC_KEY_SIZE, ENCODED_SECRET_KEY_SIZE, keygen};
    use crate::mlsigcrypt::params::*;
    use crate::mlsigcrypt::signcrypt::unsigncrypt;
    use crate::mlsigcrypt::specs::algebraic;
    use crate::mlsigcrypt::specs::keccak::{KeccakSponge, zeroize_sponge};
    use crate::mlsigcrypt::specs::ml::field::{caddq, decompose, fqmul, make_hint_ct0, reduce32};
    use crate::mlsigcrypt::specs::ml::matrix::PolyMatrix;
    use crate::mlsigcrypt::specs::ml::packing::{pack_sig, polyw1_pack, unpack_sk};
    use crate::mlsigcrypt::specs::ml::params::{
        BETA, GAMMA1, GAMMA2, K, L, LAMBDA2_BYTES, N, OMEGA, POLYW1_BYTES, SIG_BYTES,
    };
    use crate::mlsigcrypt::specs::ml::poly::{Poly, zeroize_poly};
    use crate::mlsigcrypt::specs::ml::sampling::{
        expand_a, expand_mask, sample_in_ball, shake256_absorb_squeeze,
    };
    use crate::mlsigcrypt::specs::ml::vec::{PolyVec, zeroize_polyvec};
    use crate::mlsigcrypt::specs::sha512::sha3_512_hash as sha3_512;
    use crate::zeroize::{zeroize_array, zeroize_slice};

    // ── Domain separators (must match params.rs exactly) ─────────────────────

    const KAT_SHAKE256_RATE: usize = 136;
    const KAT_SHAKE_SUFFIX: u8 = 0x1F;
    const KAT_DOMAIN_AAD: &[u8] = b"MLSigcrypt-v3/aad\x03";
    const KAT_DOMAIN_CHAL: &[u8] = b"MLSigcrypt-v3/chal\x03";
    const KAT_DOMAIN_ENC: &[u8] = b"MLSigcrypt-v3/enc\x03";

    // ── Fixed test inputs ─────────────────────────────────────────────────────

    /// Sender master secret.
    const MSK_SENDER: [u8; MASTER_SECRET_LEN] = [0x01u8; MASTER_SECRET_LEN];
    /// Recipient master secret.
    const MSK_RECIPIENT: [u8; MASTER_SECRET_LEN] = [0x02u8; MASTER_SECRET_LEN];
    /// Fixed signing randomness (replaces OS entropy for hedged signing).
    const FIXED_RND: [u8; 32] = [0x00u8; 32];
    /// Fixed message key (replaces OS entropy for the payload encryption key).
    const FIXED_MESSAGE_KEY: [u8; 32] = [0xA5u8; 32];
    const KAT_AAD: &[u8] = b"mlsigcrypt-v3-testvec";
    const KAT_PLAINTEXT: &[u8] = b"test vector 0001";

    // ── KAT expected-value slots ──────────────────────────────────────────────

    /// Expected hex of sender key_id (32 bytes).
    const KAT_SENDER_KEY_ID: &str =
        "0012cd951ee1590bedd26687a2535b4388a8e6e6cdbb26676e69eddd71e37316";
    /// Expected hex of recipient key_id (32 bytes).
    const KAT_RECIPIENT_KEY_ID: &str =
        "41973fc9ee914d92bace7e324abd7354cc1893f67d1e2c127adbb94013673999";
    /// Expected hex of aad_digest (first 32 bytes).
    const KAT_AAD_DIGEST_HALF: &str =
        "6be51b49e4e472fc2b8abea53e0595e459c69aa64b6dca5ca4f37cf0211001b1";
    /// Expected hex of rho_prime (first 32 bytes).
    const KAT_RHO_PRIME_HALF: &str =
        "a0ae44a96b0c9170d09f7496d7e3d81372f1832abbf726cdb3bfe67f59520baf";
    /// Expected kappa value at first accepted iteration.
    const KAT_ACCEPTED_KAPPA: u16 = 35;
    /// Expected hex of w1_packed (first 16 bytes).
    const KAT_W1_PACKED_HEAD: &str = "ec21b7eafdecb4488248ef094faf856e";
    /// Expected hex of c_tilde (all 64 bytes).
    const KAT_C_TILDE: &str = "a2dd88964b821a240e68defe3902088a1cac303eb17b5e9b491ce35cf4830b55a6d04d2c7db088ef84a9997e2ed396d3c95b0b0a9f71cb842e141c3204678638";
    /// Expected hex of encap field (first 32 bytes, packet bytes 78..110).
    const KAT_ENCAP_HEAD: &str = "3acc2ec0e7690b2edfef110a9999f3854ad612763a7a8ebabf6d6749bc0e8c42";
    /// Expected hex of ciphertext field (all 16 bytes, for 16-byte plaintext).
    const KAT_CIPHERTEXT: &str = "eec11d4d06daa9748f71209c728b2501";
    /// Expected total packet length.
    const KAT_PACKET_LEN: usize = 8409;

    // ── Utility ───────────────────────────────────────────────────────────────

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd hex string length");
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("valid hex"))
            .collect()
    }

    // ── Private-function reimplementations (no access to signcrypt.rs privates) ──

    fn kat_aad_digest(aad: &[u8]) -> [u8; AAD_DIGEST_LEN] {
        let mut out = [0u8; AAD_DIGEST_LEN];
        sha3_512(&[KAT_DOMAIN_AAD, aad], &mut out);
        out
    }

    fn kat_compute_challenge(
        w1_packed: &[u8; K * POLYW1_BYTES],
        encap: &[u8; ENCAP_LEN],
        aad_digest: &[u8; AAD_DIGEST_LEN],
        sender_tr: &[u8; 64],
        pk_enc_r: &[u8; ENC_PK_LEN],
        ct: &[u8],
    ) -> [u8; LAMBDA2_BYTES] {
        let ct_len_be = (ct.len() as u64).to_be_bytes();
        let mut out = [0u8; LAMBDA2_BYTES];
        shake256_absorb_squeeze(
            &[
                KAT_DOMAIN_CHAL,
                w1_packed,
                encap,
                aad_digest,
                sender_tr,
                pk_enc_r,
                &ct_len_be,
                ct,
            ],
            &mut out,
        );
        out
    }

    fn kat_xor_keystream(
        message_key: &[u8; 32],
        key_id_s: &[u8; KEY_ID_LEN],
        key_id_r: &[u8; KEY_ID_LEN],
        encap: &[u8; ENCAP_LEN],
        buf: &mut [u8],
    ) {
        let mut sponge = KeccakSponge::<KAT_SHAKE256_RATE>::new();
        let mut block = [0u8; KAT_SHAKE256_RATE];
        sponge.absorb(KAT_DOMAIN_ENC);
        sponge.absorb(message_key);
        sponge.absorb(key_id_s);
        sponge.absorb(key_id_r);
        sponge.absorb(encap);
        sponge.finalize(KAT_SHAKE_SUFFIX);
        let mut offset = 0usize;
        while offset < buf.len() {
            let take = (buf.len() - offset).min(KAT_SHAKE256_RATE);
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

    // ── Intermediate value capture ────────────────────────────────────────────

    struct KatResult {
        packet: Vec<u8>,
        aad_digest: [u8; AAD_DIGEST_LEN],
        rho_prime: [u8; 64],
        accepted_kappa: u16,
        w1_packed: [u8; K * POLYW1_BYTES],
        encap: [u8; ENCAP_LEN],
        c_tilde: [u8; LAMBDA2_BYTES],
    }

    // ── Deterministic signcrypt (fixed entropy, records intermediates) ────────

    /// Reimplements signcrypt with injected randomness for test-vector generation.
    ///
    /// Differences from production `signcrypt`:
    ///   - `fixed_rnd` replaces `fill_os_random_array` for hedged signing.
    ///   - `fixed_message_key` replaces `fill_os_random_array` for the payload key.
    ///
    /// Returns both the packet and a capture of intermediate values.
    fn signcrypt_deterministic(
        sk_user_s: &crate::mlsigcrypt::keys::UserSecretKey,
        pk_user_s: &crate::mlsigcrypt::keys::UserPublicKey,
        pk_user_r: &crate::mlsigcrypt::keys::UserPublicKey,
        aad: &[u8],
        plaintext: &[u8],
        fixed_rnd: &[u8; 32],
        fixed_message_key: &[u8; 32],
    ) -> KatResult {
        let pt_len = plaintext.len();
        let packet_len = pt_len + PACKET_FIXED_OVERHEAD;
        let mut out = vec![0u8; packet_len];

        assert!(pk_user_s.verify_consistency(), "sender key inconsistent");
        assert!(pk_user_r.verify_consistency(), "recipient key inconsistent");

        // Pre-decode recipient pk for encapsulation
        let mut recipient_pk = PolyVec::<{ algebraic::ENC_K }>::zero();
        assert!(
            algebraic::decode_public_key(pk_user_r.pk_enc(), &mut recipient_pk),
            "recipient pk decode"
        );
        let mut recipient_pk_hat = PolyVec::<{ algebraic::ENC_K }>::zero();
        for i in 0..algebraic::ENC_K {
            recipient_pk_hat.polys[i]
                .coeffs
                .copy_from_slice(&recipient_pk.polys[i].coeffs);
            recipient_pk_hat.polys[i].ntt();
        }

        // Write packet header
        out[PKT_ALG_ID_OFF..PKT_VERSION_OFF].copy_from_slice(ALG_ID);
        out[PKT_VERSION_OFF] = VERSION;
        out[PKT_KEY_ID_S_OFF..PKT_KEY_ID_S_OFF + KEY_ID_LEN].copy_from_slice(pk_user_s.key_id());
        out[PKT_KEY_ID_R_OFF..PKT_KEY_ID_R_OFF + KEY_ID_LEN].copy_from_slice(pk_user_r.key_id());
        let ct_len_be = (pt_len as u64).to_be_bytes();
        out[PKT_CT_LEN_OFF..PKT_CT_OFF].copy_from_slice(&ct_len_be);

        // AAD digest
        let aad_digest = kat_aad_digest(aad);

        // Unpack sender SK
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

        // Derive rho_prime with fixed_rnd (no OS entropy)
        let mut rho_prime = [0u8; 64];
        shake256_absorb_squeeze(
            &[
                &k_seed,
                fixed_rnd,
                &aad_digest,
                pk_user_s.key_id(),
                pk_user_r.key_id(),
            ],
            &mut rho_prime,
        );

        // Expand both matrices
        let mut mat_a = PolyMatrix::zero();
        expand_a(&mut mat_a, &rho);
        let mut encap_mat_a = PolyMatrix::zero();
        expand_a(&mut encap_mat_a, pk_user_r.rho_shared());

        // Rejection sampling loop
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
        let mut w1_packed = [0u8; K * POLYW1_BYTES];
        let mut encap = [0u8; ENCAP_LEN];

        let (accepted_kappa, c_tilde) = 'outer: loop {
            let kappa_this = kappa;
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
                let packed: &mut [u8; POLYW1_BYTES] =
                    (&mut w1_packed[start..end]).try_into().expect("fixed size");
                polyw1_pack(packed, &w1.polys[i]);
            }

            // Encap uses fixed message key, derives its own randomness from y
            algebraic::encapsulate_from_mask(
                &encap_mat_a,
                &recipient_pk_hat,
                &y,
                fixed_message_key,
                &mut encap,
            );

            // Encrypt payload
            out[PKT_CT_OFF..PKT_CT_OFF + pt_len].copy_from_slice(plaintext);
            kat_xor_keystream(
                fixed_message_key,
                pk_user_s.key_id(),
                pk_user_r.key_id(),
                &encap,
                &mut out[PKT_CT_OFF..PKT_CT_OFF + pt_len],
            );

            // Compute challenge
            let c_tilde = kat_compute_challenge(
                &w1_packed,
                &encap,
                &aad_digest,
                &tr,
                pk_user_r.pk_enc(),
                &out[PKT_CT_OFF..PKT_CT_OFF + pt_len],
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
                    z.polys[i].coeffs[j] =
                        y.polys[i].coeffs[j].wrapping_add(cs1.polys[i].coeffs[j]);
                }
            }
            if !z.check_norm_lt(GAMMA1 - BETA) {
                continue 'outer;
            }

            let mut reject_r0 = false;
            for i in 0..K {
                for j in 0..N {
                    let r = caddq(reduce32(
                        w.polys[i].coeffs[j].wrapping_sub(cs2.polys[i].coeffs[j]),
                    ));
                    let (_, r0) = decompose(r);
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
                    let h_bit = make_hint_ct0(
                        ct0.polys[i].coeffs[j],
                        w.polys[i].coeffs[j],
                        cs2.polys[i].coeffs[j],
                    );
                    h.polys[i].coeffs[j] = h_bit;
                    hint_weight += h_bit as usize;
                }
            }
            if hint_weight > OMEGA {
                continue 'outer;
            }

            break 'outer (kappa_this, c_tilde);
        };

        let mut sig = [0u8; SIG_BYTES];
        pack_sig(&mut sig, &c_tilde, &z, &h);

        out[PKT_ENCAP_OFF..PKT_ENCAP_OFF + ENCAP_LEN].copy_from_slice(&encap);
        out[PKT_Z_OFF..PKT_Z_OFF + SIG_Z_LEN]
            .copy_from_slice(&sig[SIG_CTILDE_LEN..SIG_CTILDE_LEN + SIG_Z_LEN]);
        out[PKT_CTILDE_OFF..PKT_CTILDE_OFF + SIG_CTILDE_LEN]
            .copy_from_slice(&sig[..SIG_CTILDE_LEN]);
        out[PKT_HINT_OFF..PKT_HINT_OFF + SIG_HINT_LEN]
            .copy_from_slice(&sig[SIG_CTILDE_LEN + SIG_Z_LEN..]);

        // Cleanup
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
        zeroize_polyvec(&mut recipient_pk);
        zeroize_polyvec(&mut recipient_pk_hat);
        zeroize_poly(&mut c_hat);
        zeroize_array(&mut rho);
        zeroize_array(&mut k_seed);
        zeroize_array(&mut tr);

        KatResult {
            packet: out,
            aad_digest,
            rho_prime,
            accepted_kappa,
            w1_packed,
            encap,
            c_tilde,
        }
    }

    // ── Test 1: generate and print all intermediate values ────────────────────

    /// Run with:  cargo test kat::tests::generate_test_vectors -- --nocapture --ignored
    #[test]
    #[ignore]
    fn generate_test_vectors() {
        let (sk_sender, pk_sender) = keygen(&MSK_SENDER);
        let (sk_recipient, pk_recipient) = keygen(&MSK_RECIPIENT);

        println!();
        println!("=== MLSigcrypt-v3 Known-Answer Test Vectors ===");
        println!();
        println!("--- Fixed Inputs ---");
        println!("msk_sender:           {}", hex(&MSK_SENDER));
        println!("msk_recipient:        {}", hex(&MSK_RECIPIENT));
        println!("fixed_rnd:            {}", hex(&FIXED_RND));
        println!("fixed_message_key:    {}", hex(&FIXED_MESSAGE_KEY));
        println!(
            "aad:                  {:?}",
            core::str::from_utf8(KAT_AAD).unwrap()
        );
        println!(
            "plaintext:            {:?}",
            core::str::from_utf8(KAT_PLAINTEXT).unwrap()
        );
        println!();

        // --- Key derivation ---
        println!("--- Sender Key Derivation ---");
        println!("sender_key_id:        {}", hex(pk_sender.key_id()));
        println!("sender_rho_shared:    {}", hex(pk_sender.rho_shared()));
        println!("sender_pk_enc[0..32]: {}", hex(&pk_sender.pk_enc()[..32]));
        // pk_sig[0..32] = rho_shared (matrix seed embedded in ML-DSA pk)
        println!("sender_pk_sig[0..32]: {}", hex(&pk_sender.pk_sig()[..32]));
        println!(
            "consistency_check:    {}",
            if pk_sender.pk_sig()[..32] == *pk_sender.rho_shared() {
                "PASS (pk_sig[0..32] == rho_shared)"
            } else {
                "FAIL"
            }
        );
        println!();
        println!("--- Recipient Key Derivation ---");
        println!("recipient_key_id:        {}", hex(pk_recipient.key_id()));
        println!(
            "recipient_rho_shared:    {}",
            hex(pk_recipient.rho_shared())
        );
        println!(
            "recipient_pk_enc[0..32]: {}",
            hex(&pk_recipient.pk_enc()[..32])
        );
        println!(
            "recipient_pk_sig[0..32]: {}",
            hex(&pk_recipient.pk_sig()[..32])
        );
        println!();

        // --- Signcrypt with fixed entropy ---
        let kat = signcrypt_deterministic(
            &sk_sender,
            &pk_sender,
            &pk_recipient,
            KAT_AAD,
            KAT_PLAINTEXT,
            &FIXED_RND,
            &FIXED_MESSAGE_KEY,
        );

        println!("--- Signcrypt Intermediates ---");
        println!("aad_digest[0..32]:    {}", hex(&kat.aad_digest[..32]));
        println!("aad_digest[32..64]:   {}", hex(&kat.aad_digest[32..]));
        println!("rho_prime[0..32]:     {}", hex(&kat.rho_prime[..32]));
        println!("rho_prime[32..64]:    {}", hex(&kat.rho_prime[32..]));
        println!("accepted_kappa:       {}", kat.accepted_kappa);
        println!(
            "iterations:           {}",
            kat.accepted_kappa / L as u16 + 1
        );
        println!("w1_packed[0..16]:     {}", hex(&kat.w1_packed[..16]));
        println!("c_tilde:              {}", hex(&kat.c_tilde));
        println!("encap[0..32]:         {}", hex(&kat.encap[..32]));
        println!("encap[32..64]:        {}", hex(&kat.encap[32..64]));
        println!();

        // --- Packet structure ---
        let pkt = &kat.packet;
        let pt_len = KAT_PLAINTEXT.len();
        println!("--- Packet Structure ---");
        println!("packet_len:           {} bytes", pkt.len());
        println!(
            "alg_id:               {}",
            hex(&pkt[PKT_ALG_ID_OFF..PKT_VERSION_OFF])
        );
        println!("version:              {:02x}", pkt[PKT_VERSION_OFF]);
        println!(
            "key_id_S:             {}",
            hex(&pkt[PKT_KEY_ID_S_OFF..PKT_KEY_ID_S_OFF + KEY_ID_LEN])
        );
        println!(
            "key_id_R:             {}",
            hex(&pkt[PKT_KEY_ID_R_OFF..PKT_KEY_ID_R_OFF + KEY_ID_LEN])
        );
        println!(
            "encap[0..32]:         {}",
            hex(&pkt[PKT_ENCAP_OFF..PKT_ENCAP_OFF + 32])
        );
        println!(
            "ct_len_field:         {}",
            hex(&pkt[PKT_CT_LEN_OFF..PKT_CT_OFF])
        );
        println!(
            "ciphertext:           {}",
            hex(&pkt[PKT_CT_OFF..PKT_CT_OFF + pt_len])
        );
        println!();

        // --- Decapsulation check ---
        println!("--- Decapsulation Check ---");
        let mut recovered_key = [0u8; 32];
        let ok = algebraic::decapsulate_from_seed(
            &sk_recipient.sk_enc_seed,
            &kat.encap,
            &mut recovered_key,
        );
        println!("decap_ok:             {}", ok);
        println!(
            "key_match:            {}",
            if ok && recovered_key == FIXED_MESSAGE_KEY {
                "PASS (recovered == FIXED_MESSAGE_KEY)"
            } else {
                "FAIL"
            }
        );
        println!("recovered_key:        {}", hex(&recovered_key));
        println!("expected_key:         {}", hex(&FIXED_MESSAGE_KEY));
        println!();

        // --- Unsigncrypt round-trip ---
        println!("--- Round-Trip Verification ---");
        let mut plaintext_buf = vec![0u8; pt_len];
        let result = unsigncrypt(
            &sk_recipient,
            &pk_sender,
            &pk_recipient,
            KAT_AAD,
            pkt,
            &mut plaintext_buf,
        );
        println!("unsigncrypt_result:   {:?}", result.is_ok());
        if let Ok(n) = result {
            println!(
                "plaintext_match:      {}",
                if &plaintext_buf[..n] == KAT_PLAINTEXT {
                    "PASS"
                } else {
                    "FAIL"
                }
            );
            println!(
                "recovered:            {:?}",
                core::str::from_utf8(&plaintext_buf[..n]).unwrap_or("<non-utf8>")
            );
        }
        println!();

        // --- Failure vector: tamper encap[42] ---
        println!("--- Failure Vector: encap[42] ^= 0x80 ---");
        let mut tampered_pkt = pkt.clone();
        tampered_pkt[PKT_ENCAP_OFF + 42] ^= 0x80;
        let mut fail_buf = vec![0u8; pt_len];
        let fail_result = unsigncrypt(
            &sk_recipient,
            &pk_sender,
            &pk_recipient,
            KAT_AAD,
            &tampered_pkt,
            &mut fail_buf,
        );
        println!("tampered_result:      {:?}", fail_result);
        println!(
            "tamper_rejected:      {}",
            if fail_result.is_err() {
                "PASS"
            } else {
                "FAIL (tamper accepted!)"
            }
        );
        println!();

        // --- Failure vector: wrong AAD ---
        println!("--- Failure Vector: wrong AAD ---");
        let mut fail_buf2 = vec![0u8; pt_len];
        let fail_aad_result = unsigncrypt(
            &sk_recipient,
            &pk_sender,
            &pk_recipient,
            b"wrong-aad",
            pkt,
            &mut fail_buf2,
        );
        println!(
            "wrong_aad_rejected:   {}",
            if fail_aad_result.is_err() {
                "PASS"
            } else {
                "FAIL"
            }
        );
        println!();

        // --- Paste-ready KAT constants ---
        println!("--- Paste into KAT_* constants ---");
        println!(
            "const KAT_SENDER_KEY_ID: &str = \"{}\";",
            hex(pk_sender.key_id())
        );
        println!(
            "const KAT_RECIPIENT_KEY_ID: &str = \"{}\";",
            hex(pk_recipient.key_id())
        );
        println!(
            "const KAT_AAD_DIGEST_HALF: &str = \"{}\";",
            hex(&kat.aad_digest[..32])
        );
        println!(
            "const KAT_RHO_PRIME_HALF: &str = \"{}\";",
            hex(&kat.rho_prime[..32])
        );
        println!("const KAT_ACCEPTED_KAPPA: u16 = {};", kat.accepted_kappa);
        println!(
            "const KAT_W1_PACKED_HEAD: &str = \"{}\";",
            hex(&kat.w1_packed[..16])
        );
        println!("const KAT_C_TILDE: &str = \"{}\";", hex(&kat.c_tilde));
        println!(
            "const KAT_ENCAP_HEAD: &str = \"{}\";",
            hex(&kat.encap[..32])
        );
        println!(
            "const KAT_CIPHERTEXT: &str = \"{}\";",
            hex(&pkt[PKT_CT_OFF..PKT_CT_OFF + pt_len])
        );
        println!("const KAT_PACKET_LEN: usize = {};", pkt.len());
        println!();
    }

    // ── Test 2: deterministic roundtrip — always runs in CI ──────────────────

    /// Verifies that signcrypt_deterministic produces a packet that
    /// unsigncrypt can open, and that a tampered encap is rejected.
    /// Does NOT require hardcoded expected values.
    #[test]
    fn known_answer_roundtrip_deterministic() {
        let (sk_sender, pk_sender) = keygen(&MSK_SENDER);
        let (sk_recipient, pk_recipient) = keygen(&MSK_RECIPIENT);

        let kat = signcrypt_deterministic(
            &sk_sender,
            &pk_sender,
            &pk_recipient,
            KAT_AAD,
            KAT_PLAINTEXT,
            &FIXED_RND,
            &FIXED_MESSAGE_KEY,
        );

        let pkt = &kat.packet;
        let pt_len = KAT_PLAINTEXT.len();

        // -- packet structure --
        assert_eq!(pkt.len(), PACKET_FIXED_OVERHEAD + pt_len, "packet length");
        assert_eq!(&pkt[PKT_ALG_ID_OFF..PKT_VERSION_OFF], ALG_ID, "alg_id");
        assert_eq!(pkt[PKT_VERSION_OFF], VERSION, "version byte");
        assert_eq!(
            &pkt[PKT_KEY_ID_S_OFF..PKT_KEY_ID_S_OFF + KEY_ID_LEN],
            pk_sender.key_id(),
            "key_id_S"
        );
        assert_eq!(
            &pkt[PKT_KEY_ID_R_OFF..PKT_KEY_ID_R_OFF + KEY_ID_LEN],
            pk_recipient.key_id(),
            "key_id_R"
        );

        // -- decapsulation algebra --
        let mut recovered_key = [0u8; 32];
        let decap_ok = algebraic::decapsulate_from_seed(
            &sk_recipient.sk_enc_seed,
            &kat.encap,
            &mut recovered_key,
        );
        assert!(decap_ok, "decapsulation must succeed");
        assert_eq!(
            recovered_key, FIXED_MESSAGE_KEY,
            "decapsulated key must match fixed message key"
        );

        // -- full roundtrip --
        let mut plaintext_buf = vec![0u8; pt_len];
        let open_result = unsigncrypt(
            &sk_recipient,
            &pk_sender,
            &pk_recipient,
            KAT_AAD,
            pkt,
            &mut plaintext_buf,
        );
        assert!(
            open_result.is_ok(),
            "unsigncrypt must succeed: {:?}",
            open_result
        );
        assert_eq!(
            &plaintext_buf[..open_result.unwrap()],
            KAT_PLAINTEXT,
            "plaintext mismatch"
        );

        // -- determinism: same inputs produce identical packet --
        let kat2 = signcrypt_deterministic(
            &sk_sender,
            &pk_sender,
            &pk_recipient,
            KAT_AAD,
            KAT_PLAINTEXT,
            &FIXED_RND,
            &FIXED_MESSAGE_KEY,
        );
        assert_eq!(
            kat.packet, kat2.packet,
            "signcrypt must be deterministic for fixed inputs"
        );
        assert_eq!(kat.c_tilde, kat2.c_tilde, "c_tilde must be deterministic");

        // -- tampered encap rejected --
        let mut tampered = pkt.clone();
        tampered[PKT_ENCAP_OFF + 42] ^= 0x80;
        let mut fail_buf = vec![0u8; pt_len];
        assert!(
            unsigncrypt(
                &sk_recipient,
                &pk_sender,
                &pk_recipient,
                KAT_AAD,
                &tampered,
                &mut fail_buf
            )
            .is_err(),
            "tampered encap must be rejected"
        );
        assert!(
            fail_buf.iter().all(|&b| b == 0),
            "output buffer must be zeroed on failure"
        );

        // -- wrong AAD rejected --
        let mut fail_buf2 = vec![0u8; pt_len];
        assert!(
            unsigncrypt(
                &sk_recipient,
                &pk_sender,
                &pk_recipient,
                b"wrong",
                pkt,
                &mut fail_buf2
            )
            .is_err(),
            "wrong AAD must be rejected"
        );

        // -- wrong recipient identity rejected --
        // Internal `unsigncrypt` expects a matching `(sk_user_r, pk_user_r)` pair.
        // Using Charlie's secret with Charlie's public key models a distinct
        // recipient attempting to open Bob's packet.
        let (sk_charlie, pk_charlie) = keygen(&[0x03u8; MASTER_SECRET_LEN]);
        let mut fail_buf3 = vec![0u8; pt_len];
        assert!(
            unsigncrypt(
                &sk_charlie,
                &pk_sender,
                &pk_charlie,
                KAT_AAD,
                pkt,
                &mut fail_buf3
            )
            .is_err(),
            "wrong recipient SK must be rejected"
        );
    }

    // ── Test 3: pinned assertions — fill in after running generate_test_vectors ──

    /// Asserts packet structure against hardcoded expected values.
    ///
    /// This test is a no-op until all KAT_* constants are filled in.
    /// After running `generate_test_vectors --nocapture --ignored`, paste the
    /// printed constant lines into the KAT_* slots above.
    #[test]
    fn known_answer_assertions() {
        // Skip if constants haven't been filled in yet
        if KAT_PACKET_LEN == 0 {
            eprintln!(
                "[known_answer_assertions] KAT constants not yet filled. \
                Run `generate_test_vectors -- --nocapture --ignored` first."
            );
            return;
        }

        let (sk_sender, pk_sender) = keygen(&MSK_SENDER);
        let (sk_recipient, pk_recipient) = keygen(&MSK_RECIPIENT);

        // Key ID assertions
        assert_eq!(hex(pk_sender.key_id()), KAT_SENDER_KEY_ID, "sender key_id");
        assert_eq!(
            hex(pk_recipient.key_id()),
            KAT_RECIPIENT_KEY_ID,
            "recipient key_id"
        );

        let kat = signcrypt_deterministic(
            &sk_sender,
            &pk_sender,
            &pk_recipient,
            KAT_AAD,
            KAT_PLAINTEXT,
            &FIXED_RND,
            &FIXED_MESSAGE_KEY,
        );

        let pkt = &kat.packet;
        let pt_len = KAT_PLAINTEXT.len();

        // Intermediate value assertions
        assert_eq!(
            hex(&kat.aad_digest[..32]),
            KAT_AAD_DIGEST_HALF,
            "aad_digest first 32 bytes"
        );
        assert_eq!(
            hex(&kat.rho_prime[..32]),
            KAT_RHO_PRIME_HALF,
            "rho_prime first 32 bytes"
        );
        assert_eq!(kat.accepted_kappa, KAT_ACCEPTED_KAPPA, "accepted kappa");
        assert_eq!(
            hex(&kat.w1_packed[..16]),
            KAT_W1_PACKED_HEAD,
            "w1_packed head"
        );
        assert_eq!(hex(&kat.c_tilde), KAT_C_TILDE, "c_tilde");
        assert_eq!(hex(&kat.encap[..32]), KAT_ENCAP_HEAD, "encap head");

        // Packet assertions
        assert_eq!(pkt.len(), KAT_PACKET_LEN, "packet length");
        assert_eq!(
            hex(&pkt[PKT_CT_OFF..PKT_CT_OFF + pt_len]),
            KAT_CIPHERTEXT,
            "ciphertext"
        );

        // Full roundtrip still passes
        let mut plaintext_buf = vec![0u8; pt_len];
        let result = unsigncrypt(
            &sk_recipient,
            &pk_sender,
            &pk_recipient,
            KAT_AAD,
            pkt,
            &mut plaintext_buf,
        );
        assert!(result.is_ok(), "roundtrip must succeed after pinning");
        assert_eq!(&plaintext_buf[..result.unwrap()], KAT_PLAINTEXT);
    }

    // ── Test 4: algebraic encap/decap known-answer (pure, no signing) ─────────

    /// Pins the algebraic encap/decap on a fixed (rho, seed, y) triple.
    /// Runs in CI; no ignoring.
    #[test]
    fn algebraic_encap_decap_deterministic() {
        let rho = [0x19u8; 32];
        let seed = [0x73u8; 32];

        let mut pk = [0u8; algebraic::PUBLIC_KEY_BYTES];
        algebraic::derive_public_key(&rho, &seed, &mut pk);

        // Build a fixed y by expanding a known seed
        let mut rho_prime = [0u8; 64];
        shake256_absorb_squeeze(&[b"kat-algebraic-test-y"], &mut rho_prime);
        let mut y = PolyVec::<L>::zero();
        expand_mask(&mut y, &rho_prime, 0);

        let mut mat_a = PolyMatrix::zero();
        expand_a(&mut mat_a, &rho);

        let mut recipient_pk = PolyVec::<{ algebraic::ENC_K }>::zero();
        assert!(algebraic::decode_public_key(&pk, &mut recipient_pk));
        let mut recipient_pk_hat = PolyVec::<{ algebraic::ENC_K }>::zero();
        for i in 0..algebraic::ENC_K {
            recipient_pk_hat.polys[i]
                .coeffs
                .copy_from_slice(&recipient_pk.polys[i].coeffs);
            recipient_pk_hat.polys[i].ntt();
        }

        let message_key = [0xA5u8; 32];
        let mut encap = [0u8; algebraic::ENCAP_BYTES];
        algebraic::encapsulate_from_mask(&mat_a, &recipient_pk_hat, &y, &message_key, &mut encap);

        let mut recovered = [0u8; 32];
        assert!(
            algebraic::decapsulate_from_seed(&seed, &encap, &mut recovered),
            "decapsulation must succeed"
        );
        assert_eq!(recovered, message_key, "recovered key must match original");

        // Determinism: same inputs produce same encap
        let mut encap2 = [0u8; algebraic::ENCAP_BYTES];
        algebraic::encapsulate_from_mask(&mat_a, &recipient_pk_hat, &y, &message_key, &mut encap2);
        assert_eq!(encap, encap2, "encapsulate_from_mask must be deterministic");

        // Tamper: replace the algebraic ciphertext with all-zero coefficients.
        // `decode_encap` accepts this encoding, and decapsulation deterministically
        // recovers the all-zero key, which must differ from the original.
        let tampered_encap = [0u8; algebraic::ENCAP_BYTES];
        let mut tampered_recovered = [0u8; 32];
        assert!(
            algebraic::decapsulate_from_seed(&seed, &tampered_encap, &mut tampered_recovered),
            "zero encap must decode and decapsulate"
        );
        assert_ne!(
            tampered_recovered, message_key,
            "tampered encap must yield wrong key"
        );
    }

    // ── Test 5: key encoding round-trips ─────────────────────────────────────

    #[test]
    fn key_encoding_determinism() {
        let (sk, pk) = keygen(&MSK_SENDER);
        let mut enc_pk = [0u8; ENCODED_PUBLIC_KEY_SIZE];
        let mut enc_sk = [0u8; ENCODED_SECRET_KEY_SIZE];
        pk.encode_into(&mut enc_pk);
        sk.encode_into(&pk, &mut enc_sk);

        // Second keygen with same msk must produce identical encoded keys
        let (sk2, pk2) = keygen(&MSK_SENDER);
        let mut enc_pk2 = [0u8; ENCODED_PUBLIC_KEY_SIZE];
        let mut enc_sk2 = [0u8; ENCODED_SECRET_KEY_SIZE];
        pk2.encode_into(&mut enc_pk2);
        sk2.encode_into(&pk2, &mut enc_sk2);

        assert_eq!(enc_pk, enc_pk2, "public key encoding must be deterministic");
        assert_eq!(enc_sk, enc_sk2, "secret key encoding must be deterministic");

        // Decode must succeed and pass consistency check
        let decoded_pk =
            crate::mlsigcrypt::keys::decode_public_key(&enc_pk).expect("public key must decode");
        assert!(
            decoded_pk.verify_consistency(),
            "decoded key must be consistent"
        );
        let (decoded_sk, decoded_pk2) =
            crate::mlsigcrypt::keys::decode_secret_key(&enc_sk).expect("secret key must decode");
        assert_eq!(decoded_sk.matrix_seed, sk.matrix_seed);
        assert_eq!(decoded_sk.sk_enc_seed, sk.sk_enc_seed);
        assert_eq!(decoded_pk2.key_id(), pk.key_id());
    }
}
