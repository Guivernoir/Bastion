#![allow(missing_docs)]

use crypto_bastion::{
    MLSIGCRYPT_PACKET_OVERHEAD, MLSIGCRYPT_PUBLIC_KEY_SIZE, MLSIGCRYPT_SECRET_KEY_SIZE,
    mlsigcrypt_keygen, mlsigcrypt_signcrypt, mlsigcrypt_unsigncrypt,
};

fn main() -> Result<(), &'static str> {
    let aad = b"demo-mlsigcrypt-v3-aad";
    let msg = b"mlsigcrypt public api demo";

    let mut sender_pk = [0u8; MLSIGCRYPT_PUBLIC_KEY_SIZE];
    let mut sender_sk = [0u8; MLSIGCRYPT_SECRET_KEY_SIZE];
    let mut recipient_pk = [0u8; MLSIGCRYPT_PUBLIC_KEY_SIZE];
    let mut recipient_sk = [0u8; MLSIGCRYPT_SECRET_KEY_SIZE];
    let mut packet = vec![0u8; MLSIGCRYPT_PACKET_OVERHEAD + msg.len()];
    let mut opened = vec![0u8; msg.len()];

    mlsigcrypt_keygen(&mut sender_pk, &mut sender_sk)?;
    mlsigcrypt_keygen(&mut recipient_pk, &mut recipient_sk)?;

    let packet_len = mlsigcrypt_signcrypt(&sender_sk, &recipient_pk, aad, msg, &mut packet)?;
    let opened_len = mlsigcrypt_unsigncrypt(
        &recipient_sk,
        &sender_pk,
        aad,
        &packet[..packet_len],
        &mut opened,
    )?;

    assert_eq!(&opened[..opened_len], msg);
    println!(
        "mlsigcrypt: packet={} bytes opened={}",
        packet_len,
        String::from_utf8_lossy(&opened[..opened_len])
    );

    Ok(())
}
