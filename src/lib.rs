//! # Bastion — MLSigcrypt public surface
//!
//! Public APIs:
//! - [`mlsigcrypt_keygen`]: MLSigcrypt unified key generation
//! - [`mlsigcrypt_signcrypt`]: MLSigcrypt signcryption
//! - [`mlsigcrypt_unsigncrypt`]: MLSigcrypt signcryption open

#![allow(unsafe_code)]
#![allow(dead_code)]
#![deny(clippy::clone_on_ref_ptr)]
#![warn(clippy::unwrap_used, clippy::panic)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

mod constant_time;
mod error;
mod mlsigcrypt;
mod os_random;
mod zeroize;

use crate::zeroize::{zeroize_array, zeroize_slice};
use std::time::Instant;

/// MLSigcrypt public identity size (bytes).
pub const MLSIGCRYPT_PUBLIC_KEY_SIZE: usize = mlsigcrypt::PUBLIC_KEY_SIZE;
/// MLSigcrypt unified secret key size (bytes).
pub const MLSIGCRYPT_SECRET_KEY_SIZE: usize = mlsigcrypt::SECRET_KEY_SIZE;
/// MLSigcrypt per-packet fixed overhead excluding payload ciphertext (bytes).
pub const MLSIGCRYPT_PACKET_OVERHEAD: usize = mlsigcrypt::PACKET_OVERHEAD;

/// Best-effort timing floors for the public API wrappers (ns).
///
/// Key generation is intentionally left unpadded because it has no
/// adversary-controlled secret-dependent input at the public boundary.
const FLOOR_PUBLIC_MLSIGCRYPT_KEYGEN_NS: u64 = 0;
const FLOOR_PUBLIC_MLSIGCRYPT_SIGNCRYPT_NS: u64 = 7_000_000;
const FLOOR_PUBLIC_MLSIGCRYPT_UNSIGNCRYPT_NS: u64 = 1_500_000;

#[inline]
fn enforce_public_floor(start: Instant, floor_ns: u64) {
    loop {
        let elapsed = core::hint::black_box(start.elapsed().as_nanos() as u64);
        if elapsed >= floor_ns {
            return;
        }
        core::hint::spin_loop();
    }
}

/// MLSigcrypt unified key generation.
pub fn mlsigcrypt_keygen(
    pk_user_out: &mut [u8; MLSIGCRYPT_PUBLIC_KEY_SIZE],
    sk_user_out: &mut [u8; MLSIGCRYPT_SECRET_KEY_SIZE],
) -> std::result::Result<(), &'static str> {
    let start = Instant::now();

    let result = match mlsigcrypt::keygen_into(pk_user_out, sk_user_out) {
        Ok(()) => Ok(()),
        Err(_) => {
            zeroize_array(pk_user_out);
            zeroize_array(sk_user_out);
            Err("mlsigcrypt-v3 key generation failed")
        }
    };

    enforce_public_floor(start, FLOOR_PUBLIC_MLSIGCRYPT_KEYGEN_NS);
    result
}

/// MLSigcrypt signcryption.
pub fn mlsigcrypt_signcrypt(
    sk_user_sender: &[u8],
    pk_user_recipient: &[u8],
    aad: &[u8],
    message: &[u8],
    packet_out: &mut [u8],
) -> std::result::Result<usize, &'static str> {
    let start = Instant::now();

    let result =
        mlsigcrypt::signcrypt_into(sk_user_sender, pk_user_recipient, aad, message, packet_out)
            .map_err(|_| {
                zeroize_slice(packet_out);
                "mlsigcrypt-v3 signcrypt failed"
            });

    enforce_public_floor(start, FLOOR_PUBLIC_MLSIGCRYPT_SIGNCRYPT_NS);
    result
}

/// MLSigcrypt open with unified failure semantics.
pub fn mlsigcrypt_unsigncrypt(
    sk_user_recipient: &[u8],
    pk_user_sender: &[u8],
    aad: &[u8],
    packet: &[u8],
    plaintext_out: &mut [u8],
) -> std::result::Result<usize, &'static str> {
    let start = Instant::now();

    let result = mlsigcrypt::unsigncrypt_into(
        sk_user_recipient,
        pk_user_sender,
        aad,
        packet,
        plaintext_out,
    )
    .map_err(|_| {
        zeroize_slice(plaintext_out);
        "mlsigcrypt-v3 open failed"
    });

    enforce_public_floor(start, FLOOR_PUBLIC_MLSIGCRYPT_UNSIGNCRYPT_NS);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlsigcrypt_public_api_roundtrip() {
        let aad = b"bastion-mlsigcrypt-v3";
        let msg = b"mlsigcrypt-v3 public api roundtrip";
        let mut sender_pk = [0u8; MLSIGCRYPT_PUBLIC_KEY_SIZE];
        let mut sender_sk = [0u8; MLSIGCRYPT_SECRET_KEY_SIZE];
        let mut recipient_pk = [0u8; MLSIGCRYPT_PUBLIC_KEY_SIZE];
        let mut recipient_sk = [0u8; MLSIGCRYPT_SECRET_KEY_SIZE];
        let mut packet = [0u8; MLSIGCRYPT_PACKET_OVERHEAD + 96];
        let mut plaintext = [0u8; 96];

        assert!(mlsigcrypt_keygen(&mut sender_pk, &mut sender_sk).is_ok());
        assert!(mlsigcrypt_keygen(&mut recipient_pk, &mut recipient_sk).is_ok());

        let packet_len = mlsigcrypt_signcrypt(&sender_sk, &recipient_pk, aad, msg, &mut packet)
            .expect("signcrypt succeeds");
        let plain_len = mlsigcrypt_unsigncrypt(
            &recipient_sk,
            &sender_pk,
            aad,
            &packet[..packet_len],
            &mut plaintext,
        )
        .expect("unsigncrypt succeeds");

        assert_eq!(&plaintext[..plain_len], msg);
    }

    #[test]
    fn mlsigcrypt_open_failures_are_unified() {
        let aad = b"bastion-mlsigcrypt-v3";
        let msg = b"fail-open";
        let mut sender_pk = [0u8; MLSIGCRYPT_PUBLIC_KEY_SIZE];
        let mut sender_sk = [0u8; MLSIGCRYPT_SECRET_KEY_SIZE];
        let mut recipient_pk = [0u8; MLSIGCRYPT_PUBLIC_KEY_SIZE];
        let mut recipient_sk = [0u8; MLSIGCRYPT_SECRET_KEY_SIZE];
        let mut packet = [0u8; MLSIGCRYPT_PACKET_OVERHEAD + 64];
        let mut plaintext = [0u8; 64];

        assert!(mlsigcrypt_keygen(&mut sender_pk, &mut sender_sk).is_ok());
        assert!(mlsigcrypt_keygen(&mut recipient_pk, &mut recipient_sk).is_ok());

        let packet_len = mlsigcrypt_signcrypt(&sender_sk, &recipient_pk, aad, msg, &mut packet)
            .expect("signcrypt succeeds");

        let mut tampered = [0u8; MLSIGCRYPT_PACKET_OVERHEAD + 64];
        tampered[..packet_len].copy_from_slice(&packet[..packet_len]);
        tampered[packet_len - 1] ^= 0x01;

        assert_eq!(
            mlsigcrypt_unsigncrypt(
                &recipient_sk,
                &sender_pk,
                aad,
                &tampered[..packet_len],
                &mut plaintext,
            ),
            Err("mlsigcrypt-v3 open failed")
        );
        assert_eq!(
            mlsigcrypt_unsigncrypt(
                &recipient_sk,
                &sender_pk,
                b"wrong-aad",
                &packet[..packet_len],
                &mut plaintext,
            ),
            Err("mlsigcrypt-v3 open failed")
        );
    }
}
