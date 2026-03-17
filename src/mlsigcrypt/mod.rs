/// MLSigcrypt-v1 — post-quantum outsider-verifiable signcryption.
///
/// # Purpose
///
/// MLSigcrypt-v1 is a unified protocol construction providing, in one logical
/// operation:
///
/// - **IND-CCA2 confidentiality** — inherited from ML-KEM-1024 CCA security
/// - **EUF-CMA authenticity** — ML-DSA-87 over a context-bound transcript
/// - **Outsider verifiability** — any party holding `pk_sig_S` can verify
/// - **Context binding** — transcript binds both party identities, kem_ct,
///   ciphertext, tag, AAD, and scheme version
///
/// It is **not** a single new algebraic primitive. It is a unified protocol
/// composition over CCA-secure ML-KEM-1024, AES-256-GCM, and ML-DSA-87.
///
/// # Primitives
///
/// | Role | Primitive | Standard |
/// |---|---|---|
/// | Hash `H` | SHA3-512 | FIPS 202 |
/// | KDF | HKDF-SHA3-512 | RFC 5869 + FIPS 202 |
/// | AEAD | AES-256-GCM | NIST SP 800-38D |
/// | KEM | ML-KEM-1024 | FIPS 203 |
/// | Signature | ML-DSA-87 | FIPS 204 |
///
/// # Trust assumptions
///
/// - PKI / public-key authenticity is the caller's responsibility.
/// - No forward secrecy: compromise of `sk_enc_R` decrypts all historical packets.
/// - No revocation: compromised signing keys remain valid for prior packets.
///
/// # Packet format
///
/// Wire layout (fixed header + variable ciphertext):
///
/// ```text
/// [13]     alg_id = "MLSigcrypt-v1"
/// [1]      version = 0x01
/// [32]     key_id_S
/// [32]     key_id_R
/// [1568]   kem_ct   (ML-KEM-1024 ciphertext)
/// [8]      ct_len   (u64 big-endian)
/// [N]      ct       (AES-256-GCM ciphertext)
/// [16]     tag
/// [4627]   sig      (ML-DSA-87 signature over canonical transcript T)
/// ```
///
/// Nonce is NOT transmitted — derived deterministically by both sides from κ.
/// Total fixed overhead: 6297 bytes.
///
/// # Novelty
///
/// - Outsider-verifiable PQ signcryption profile under NIST-standardised primitives
/// - Transcript-bound KEM-DEM-signature integration with full identity binding
/// - Hierarchical seed-derived dual-keypair architecture from one master secret
/// - Deterministic nonce derivation from encapsulation context
///
/// # Security status
///
/// The composition security argument — that any adversary breaking MLSigcrypt-v1
/// reduces to breaking ML-KEM-1024, AES-256-GCM, ML-DSA-87, or SHA3-512/HKDF —
/// is a **design claim to be formally proved**, not yet a theorem.
pub(crate) mod keys;
pub(crate) mod params;
pub(crate) mod signcrypt;
pub(crate) mod specs;

use crate::error::{CryptoError, Result};
use crate::os_random::fill_os_random_array;
use crate::zeroize::{zeroize_array, zeroize_slice};

use self::keys::{decode_public_key, decode_secret_key, keygen};

pub(crate) const PUBLIC_KEY_SIZE: usize = keys::ENCODED_PUBLIC_KEY_SIZE;
pub(crate) const SECRET_KEY_SIZE: usize = keys::ENCODED_SECRET_KEY_SIZE;
pub(crate) const PACKET_OVERHEAD: usize = params::PACKET_FIXED_OVERHEAD;

pub(crate) fn keygen_into(
    pk_user_out: &mut [u8; PUBLIC_KEY_SIZE],
    sk_user_out: &mut [u8; SECRET_KEY_SIZE],
) -> Result<()> {
    let mut master_secret = [0u8; params::MASTER_SECRET_LEN];
    let result = (|| {
        fill_os_random_array(&mut master_secret)?;
        let (secret_key, public_key) = keygen(&master_secret);
        public_key.encode_into(pk_user_out);
        secret_key.encode_into(&public_key, sk_user_out);
        Ok(())
    })();
    zeroize_array(&mut master_secret);
    result
}

pub(crate) fn signcrypt_into(
    sk_user_sender: &[u8],
    pk_user_recipient: &[u8],
    aad: &[u8],
    message: &[u8],
    packet_out: &mut [u8],
) -> Result<usize> {
    let (sender_sk, sender_pk) = decode_secret_key(sk_user_sender)
        .ok_or_else(|| CryptoError::internal("invalid MLSigcrypt-v1 secret key length"))?;
    let recipient_pk = decode_public_key(pk_user_recipient).ok_or_else(|| {
        CryptoError::invalid_public_key("invalid MLSigcrypt-v1 public key length")
    })?;

    let result = signcrypt::signcrypt(
        &sender_sk,
        &sender_pk,
        &recipient_pk,
        aad,
        message,
        packet_out,
    )
    .map_err(|_| CryptoError::encryption_failed("MLSigcrypt-v1 signcrypt failed"));
    if result.is_err() {
        zeroize_slice(packet_out);
    }
    result
}

pub(crate) fn unsigncrypt_into(
    sk_user_recipient: &[u8],
    pk_user_sender: &[u8],
    aad: &[u8],
    packet: &[u8],
    plaintext_out: &mut [u8],
) -> Result<usize> {
    let (recipient_sk, recipient_pk) = decode_secret_key(sk_user_recipient)
        .ok_or_else(|| CryptoError::internal("invalid MLSigcrypt-v1 secret key length"))?;
    let sender_pk = decode_public_key(pk_user_sender).ok_or_else(|| {
        CryptoError::invalid_public_key("invalid MLSigcrypt-v1 public key length")
    })?;

    let result = signcrypt::unsigncrypt(
        &recipient_sk,
        &sender_pk,
        &recipient_pk,
        aad,
        packet,
        plaintext_out,
    )
    .map_err(|_| CryptoError::decryption_failed("MLSigcrypt-v1 open failed"));
    if result.is_err() {
        zeroize_slice(plaintext_out);
    }
    result
}

#[cfg(test)]
mod integration_tests {
    use super::keys::{UserPublicKey, UserSecretKey, keygen};
    use super::params::{MASTER_SECRET_LEN, PACKET_FIXED_OVERHEAD, PKT_ALG_ID_OFF};
    use super::signcrypt::{signcrypt, unsigncrypt};

    fn fresh_keypair(seed: u8) -> (UserSecretKey, UserPublicKey) {
        keygen(&[seed; MASTER_SECRET_LEN])
    }

    #[test]
    fn full_roundtrip_with_aad() {
        let (sk_alice, pk_alice) = fresh_keypair(0x01);
        let (sk_bob, pk_bob) = fresh_keypair(0x02);

        let plaintext = b"Hello, Bob. This is Alice.";
        let aad = b"session-id:f3a8c2d1";

        let mut packet = vec![0u8; plaintext.len() + PACKET_FIXED_OVERHEAD];
        let packet_len = signcrypt(&sk_alice, &pk_alice, &pk_bob, aad, plaintext, &mut packet)
            .expect("signcrypt must succeed");

        let mut recovered = vec![0u8; plaintext.len()];
        let recovered_len = unsigncrypt(
            &sk_bob,
            &pk_alice,
            &pk_bob,
            aad,
            &packet[..packet_len],
            &mut recovered,
        )
        .expect("unsigncrypt must succeed");

        assert_eq!(&recovered[..recovered_len], plaintext);
    }

    #[test]
    fn unsigncrypt_fails_with_incorrect_aad() {
        let (sk_s, pk_s) = fresh_keypair(0x10);
        let (sk_r, pk_r) = fresh_keypair(0x11);
        let msg = b"aad binding test";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"correct aad", msg, &mut pkt).unwrap();
        let mut out = vec![0u8; msg.len()];
        assert!(unsigncrypt(&sk_r, &pk_s, &pk_r, b"wrong aad", &pkt[..pkt_len], &mut out).is_err());
    }

    #[test]
    fn unsigncrypt_fails_with_swapped_roles() {
        let (sk_a, pk_a) = fresh_keypair(0x20);
        let (_sk_b, pk_b) = fresh_keypair(0x21);
        let msg = b"role swap test";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_a, &pk_a, &pk_b, b"", msg, &mut pkt).unwrap();
        let mut out = vec![0u8; msg.len()];
        assert!(
            unsigncrypt(&sk_a, &pk_b, &pk_a, b"", &pkt[..pkt_len], &mut out).is_err(),
            "swapped sender/recipient must fail"
        );
    }

    #[test]
    fn packet_alg_id_is_correct() {
        use super::params::{ALG_ID, ALG_ID_LEN, PKT_ALG_ID_OFF, PKT_VERSION_OFF, VERSION};
        let (sk_s, pk_s) = fresh_keypair(0x30);
        let (_, pk_r) = fresh_keypair(0x31);
        let mut pkt = vec![0u8; PACKET_FIXED_OVERHEAD];
        signcrypt(&sk_s, &pk_s, &pk_r, b"", b"", &mut pkt).unwrap();
        assert_eq!(&pkt[PKT_ALG_ID_OFF..PKT_VERSION_OFF], ALG_ID);
        assert_eq!(pkt[PKT_VERSION_OFF], VERSION);
        assert_eq!(ALG_ID_LEN, ALG_ID.len());
    }

    #[test]
    fn output_zeroized_on_failure() {
        let (sk_s, pk_s) = fresh_keypair(0x40);
        let (sk_r, pk_r) = fresh_keypair(0x41);
        let msg = b"zeroize check";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();

        pkt[PKT_ALG_ID_OFF] ^= 0xFF;

        let mut out = vec![0xAAu8; msg.len()];
        let _ = unsigncrypt(&sk_r, &pk_s, &pk_r, b"", &pkt[..pkt_len], &mut out);
        assert!(
            out.iter().all(|&b| b == 0),
            "output buffer must be zeroized on failure"
        );
    }
}
