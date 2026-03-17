#![no_main]

use crypto_bastion::{
    MLSIGCRYPT_V1_PACKET_OVERHEAD, MLSIGCRYPT_V1_PUBLIC_KEY_SIZE, MLSIGCRYPT_V1_SECRET_KEY_SIZE,
    compare, mlsigcrypt_v1_keygen, mlsigcrypt_v1_signcrypt, mlsigcrypt_v1_unsigncrypt,
};
use libfuzzer_sys::fuzz_target;

fn expand_vec(data: &[u8], len: usize, tweak: u8) -> Vec<u8> {
    let mut out = vec![0u8; len];
    if data.is_empty() {
        out.fill(tweak);
        return out;
    }
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = data[idx % data.len()] ^ tweak.wrapping_add(idx as u8);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let aad_len = data.first().copied().unwrap_or(0) as usize % 64;
    let msg_len = data.get(1).copied().unwrap_or(0) as usize % 512;

    let mut aad = vec![0u8; aad_len];
    let mut msg = vec![0u8; msg_len];
    for (idx, byte) in aad.iter_mut().enumerate() {
        *byte = data.get(2 + idx).copied().unwrap_or(0) ^ 0x5A;
    }
    for (idx, byte) in msg.iter_mut().enumerate() {
        *byte = data.get(2 + aad_len + idx).copied().unwrap_or(0) ^ 0xA5;
    }

    let sender_pk = expand_vec(data, MLSIGCRYPT_V1_PUBLIC_KEY_SIZE, 0x11);
    let sender_sk = expand_vec(data, MLSIGCRYPT_V1_SECRET_KEY_SIZE, 0x22);
    let recipient_pk = expand_vec(data, MLSIGCRYPT_V1_PUBLIC_KEY_SIZE, 0x33);
    let recipient_sk = expand_vec(data, MLSIGCRYPT_V1_SECRET_KEY_SIZE, 0x44);
    let mut malformed_packet = expand_vec(
        data,
        MLSIGCRYPT_V1_PACKET_OVERHEAD + msg.len(),
        0x55,
    );
    let mut malformed_out = vec![0u8; msg.len()];

    let _ = mlsigcrypt_v1_signcrypt(&sender_sk, &recipient_pk, &aad, &msg, &mut malformed_packet);
    let _ = mlsigcrypt_v1_unsigncrypt(
        &recipient_sk,
        &sender_pk,
        &aad,
        &malformed_packet,
        &mut malformed_out,
    );

    let mut real_sender_pk = [0u8; MLSIGCRYPT_V1_PUBLIC_KEY_SIZE];
    let mut real_sender_sk = [0u8; MLSIGCRYPT_V1_SECRET_KEY_SIZE];
    let mut real_recipient_pk = [0u8; MLSIGCRYPT_V1_PUBLIC_KEY_SIZE];
    let mut real_recipient_sk = [0u8; MLSIGCRYPT_V1_SECRET_KEY_SIZE];

    if mlsigcrypt_v1_keygen(&mut real_sender_pk, &mut real_sender_sk).is_ok()
        && mlsigcrypt_v1_keygen(&mut real_recipient_pk, &mut real_recipient_sk).is_ok()
    {
        let mut packet = vec![0u8; MLSIGCRYPT_V1_PACKET_OVERHEAD + msg.len()];
        let mut opened = vec![0u8; msg.len()];
        if let Ok(packet_len) = mlsigcrypt_v1_signcrypt(
            &real_sender_sk,
            &real_recipient_pk,
            &aad,
            &msg,
            &mut packet,
        ) {
            if let Ok(opened_len) = mlsigcrypt_v1_unsigncrypt(
                &real_recipient_sk,
                &real_sender_pk,
                &aad,
                &packet[..packet_len],
                &mut opened,
            ) {
                assert!(compare(&opened[..opened_len], &msg));
            }

            let mut wrong_aad = aad.clone();
            if let Some(first) = wrong_aad.first_mut() {
                *first ^= 0x01;
            } else {
                wrong_aad.push(0x01);
            }
            let _ = mlsigcrypt_v1_unsigncrypt(
                &real_recipient_sk,
                &real_sender_pk,
                &wrong_aad,
                &packet[..packet_len],
                &mut opened,
            );

            let mut tampered = packet.clone();
            if !tampered.is_empty() {
                let index = data.get(2).copied().unwrap_or(0) as usize % tampered.len();
                tampered[index] ^= 0x01;
            }
            let _ = mlsigcrypt_v1_unsigncrypt(
                &real_recipient_sk,
                &real_sender_pk,
                &aad,
                &tampered[..packet_len],
                &mut opened,
            );
        }
    }
});
