/// MLSigcrypt-v2 phase-1 — outsider-verifiable post-quantum signcryption.
///
/// # Purpose
///
/// MLSigcrypt-v2 phase-1 keeps the existing unified ML-KEM-1024 + ML-DSA-87
/// key hierarchy and key encodings, but replaces the v1 packet path with a
/// two-sponge SHAKE-256 construction:
///
/// - `S_E` produces the payload keystream from `κ`, sender/recipient `key_id`,
///   and `kem_ct`
/// - `S_T` absorbs the authenticated public transcript and ciphertext to derive
///   the 64-byte signing transcript `T`
///
/// The v2 signcrypt path is built only from SHAKE-256, ML-KEM-1024, and
/// ML-DSA-87.
///
/// # Packet format
///
/// ```text
/// [13]     alg_id = "MLSigcrypt-v2"
/// [1]      version = 0x02
/// [32]     key_id_S
/// [32]     key_id_R
/// [1568]   kem_ct
/// [8]      ct_len
/// [N]      ct
/// [4627]   sig
/// ```
///
/// Fixed overhead: 6281 bytes.
///
/// # Security invariants
///
/// - Signature verification happens before ML-KEM decapsulation.
/// - `alg_id`, `key_id_S`, and `key_id_R` comparisons on open use constant-time
///   equality.
/// - All transient secret material (`κ`, sponge state, keystream blocks,
///   signing randomness) is explicitly zeroized.
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
        .ok_or_else(|| CryptoError::internal("invalid MLSigcrypt-v2 secret key length"))?;
    let recipient_pk = decode_public_key(pk_user_recipient).ok_or_else(|| {
        CryptoError::invalid_public_key("invalid MLSigcrypt-v2 public key length")
    })?;

    let result = signcrypt::signcrypt(
        &sender_sk,
        &sender_pk,
        &recipient_pk,
        aad,
        message,
        packet_out,
    )
    .map_err(|_| CryptoError::encryption_failed("MLSigcrypt-v2 signcrypt failed"));
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
        .ok_or_else(|| CryptoError::internal("invalid MLSigcrypt-v2 secret key length"))?;
    let sender_pk = decode_public_key(pk_user_sender).ok_or_else(|| {
        CryptoError::invalid_public_key("invalid MLSigcrypt-v2 public key length")
    })?;

    let result = signcrypt::unsigncrypt(
        &recipient_sk,
        &sender_pk,
        &recipient_pk,
        aad,
        packet,
        plaintext_out,
    )
    .map_err(|_| CryptoError::decryption_failed("MLSigcrypt-v2 open failed"));
    if result.is_err() {
        zeroize_slice(plaintext_out);
    }
    result
}

#[cfg(test)]
mod integration_tests {
    use super::keys::{UserPublicKey, UserSecretKey, keygen};
    use super::params::{
        ALG_ID, ALG_ID_LEN, MASTER_SECRET_LEN, PACKET_FIXED_OVERHEAD, PKT_ALG_ID_OFF,
        PKT_VERSION_OFF, VERSION,
    };
    use super::signcrypt::{signcrypt, unsigncrypt};

    fn fresh_keypair(seed: u8) -> (UserSecretKey, UserPublicKey) {
        keygen(&[seed; MASTER_SECRET_LEN])
    }

    #[test]
    fn full_roundtrip_with_aad() {
        let (sk_alice, pk_alice) = fresh_keypair(0x01);
        let (sk_bob, pk_bob) = fresh_keypair(0x02);
        let plaintext = b"Hello, Bob. This is Alice.";
        let aad = b"session-id:v2";
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
    fn packet_alg_id_is_correct() {
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
        assert!(out.iter().all(|&b| b == 0));
    }
}
