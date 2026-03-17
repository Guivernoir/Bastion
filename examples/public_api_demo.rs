#![allow(missing_docs)]

use crypto_bastion::{
    DSA_PUBLIC_KEY_SIZE, DSA_SECRET_KEY_SIZE, DSA_SIGNATURE_SIZE, KEM_CIPHERTEXT_SIZE,
    KEM_PUBLIC_KEY_SIZE, KEM_SECRET_KEY_SIZE, LAYER_OVERHEAD, MLSIGCRYPT_V1_PACKET_OVERHEAD,
    MLSIGCRYPT_V1_PUBLIC_KEY_SIZE, MLSIGCRYPT_V1_SECRET_KEY_SIZE, compare, cut, decapsulate,
    decrypt, dsa_keygen, encapsulate, encrypt, hash, kem_keygen, layer_decrypt, layer_encrypt,
    mlsigcrypt_v1_keygen, mlsigcrypt_v1_signcrypt, mlsigcrypt_v1_unsigncrypt, onion, sign, verify,
};

const MSG: &[u8; 23] = b"bastion public api demo";

fn main() -> Result<(), &'static str> {
    let digest = hash(MSG);
    println!("SHA-512(msg)[0..8] = {:02x?}", &digest[..8]);
    println!("compare(msg, msg) = {}", compare(MSG, MSG));

    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let aad = [0x33u8; 16];
    let mut ct = [0u8; MSG.len()];
    let mut tag = [0u8; 16];
    let ct_len = encrypt(&key, &nonce, &aad, MSG, &mut ct, &mut tag)?;
    println!("encrypt: ct={} bytes tag={:02x?}", ct_len, tag);
    let mut pt = [0u8; MSG.len()];
    let pt_len = decrypt(&key, &nonce, &aad, &ct[..ct_len], &tag, &mut pt)?;
    println!("decrypt: {}", String::from_utf8_lossy(&pt[..pt_len]));

    let mut kem_pk = [0u8; KEM_PUBLIC_KEY_SIZE];
    let mut kem_sk = [0u8; KEM_SECRET_KEY_SIZE];
    let mut kem_ct = [0u8; KEM_CIPHERTEXT_SIZE];
    let mut ss = [0u8; 32];
    let mut decapped = [0u8; 32];
    kem_keygen(&mut kem_pk, &mut kem_sk)?;
    encapsulate(&kem_pk, &mut kem_ct, &mut ss)?;
    decapsulate(&kem_sk, &kem_ct, &mut decapped)?;
    assert!(compare(&ss, &decapped));
    println!(
        "kem_keygen + encapsulate + decapsulate: pk={} sk={} ct={} ss[0..8]={:02x?}",
        kem_pk.len(),
        kem_sk.len(),
        kem_ct.len(),
        &ss[..8]
    );

    let mut dsa_pk = [0u8; DSA_PUBLIC_KEY_SIZE];
    let mut dsa_sk = [0u8; DSA_SECRET_KEY_SIZE];
    let mut sig = [0u8; DSA_SIGNATURE_SIZE];
    dsa_keygen(&mut dsa_pk, &mut dsa_sk)?;
    sign(&dsa_sk, MSG, &mut sig)?;
    assert!(verify(&dsa_pk, MSG, &sig));
    println!("verify: {}", verify(&dsa_pk, MSG, &sig));

    let mlsigcrypt_aad = b"demo-mlsigcrypt-aad";
    let mlsigcrypt_msg = b"mlsigcrypt public api demo";
    let mut sender_pk = [0u8; MLSIGCRYPT_V1_PUBLIC_KEY_SIZE];
    let mut sender_sk = [0u8; MLSIGCRYPT_V1_SECRET_KEY_SIZE];
    let mut recipient_pk = [0u8; MLSIGCRYPT_V1_PUBLIC_KEY_SIZE];
    let mut recipient_sk = [0u8; MLSIGCRYPT_V1_SECRET_KEY_SIZE];
    let mut packet = vec![0u8; MLSIGCRYPT_V1_PACKET_OVERHEAD + mlsigcrypt_msg.len()];
    let mut opened = vec![0u8; mlsigcrypt_msg.len()];

    mlsigcrypt_v1_keygen(&mut sender_pk, &mut sender_sk)?;
    mlsigcrypt_v1_keygen(&mut recipient_pk, &mut recipient_sk)?;
    let packet_len = mlsigcrypt_v1_signcrypt(
        &sender_sk,
        &recipient_pk,
        mlsigcrypt_aad,
        mlsigcrypt_msg,
        &mut packet,
    )?;
    let opened_len = mlsigcrypt_v1_unsigncrypt(
        &recipient_sk,
        &sender_pk,
        mlsigcrypt_aad,
        &packet[..packet_len],
        &mut opened,
    )?;
    assert_eq!(&opened[..opened_len], mlsigcrypt_msg);
    println!(
        "mlsigcrypt_v1: packet={} bytes opened={}",
        packet_len,
        String::from_utf8_lossy(&opened[..opened_len])
    );

    let mut kem_pk0 = [0u8; KEM_PUBLIC_KEY_SIZE];
    let mut kem_pk1 = [0u8; KEM_PUBLIC_KEY_SIZE];
    let mut kem_pk2 = [0u8; KEM_PUBLIC_KEY_SIZE];
    let mut kem_sk0 = [0u8; KEM_SECRET_KEY_SIZE];
    let mut kem_sk1 = [0u8; KEM_SECRET_KEY_SIZE];
    let mut kem_sk2 = [0u8; KEM_SECRET_KEY_SIZE];
    let mut dsa_pk0 = [0u8; DSA_PUBLIC_KEY_SIZE];
    let mut dsa_pk1 = [0u8; DSA_PUBLIC_KEY_SIZE];
    let mut dsa_pk2 = [0u8; DSA_PUBLIC_KEY_SIZE];
    let mut dsa_sk0 = [0u8; DSA_SECRET_KEY_SIZE];
    let mut dsa_sk1 = [0u8; DSA_SECRET_KEY_SIZE];
    let mut dsa_sk2 = [0u8; DSA_SECRET_KEY_SIZE];

    kem_keygen(&mut kem_pk0, &mut kem_sk0)?;
    kem_keygen(&mut kem_pk1, &mut kem_sk1)?;
    kem_keygen(&mut kem_pk2, &mut kem_sk2)?;
    dsa_keygen(&mut dsa_pk0, &mut dsa_sk0)?;
    dsa_keygen(&mut dsa_pk1, &mut dsa_sk1)?;
    dsa_keygen(&mut dsa_pk2, &mut dsa_sk2)?;

    let kem_pks = [kem_pk0.as_slice(), kem_pk1.as_slice(), kem_pk2.as_slice()];
    let dsa_sks = [dsa_sk0.as_slice(), dsa_sk1.as_slice(), dsa_sk2.as_slice()];
    let kem_sks = [kem_sk0.as_slice(), kem_sk1.as_slice(), kem_sk2.as_slice()];
    let dsa_pks = [dsa_pk0.as_slice(), dsa_pk1.as_slice(), dsa_pk2.as_slice()];

    let mut layered = vec![0u8; MSG.len() + (3 * LAYER_OVERHEAD)];
    let layered_len = layer_encrypt(MSG, kem_pks, dsa_sks, &mut layered)?;
    println!("layer_encrypt: packet={} bytes", layered_len);
    let mut peeled = vec![0u8; MSG.len() + (3 * LAYER_OVERHEAD)];
    let peeled_len = layer_decrypt(&layered[..layered_len], kem_sks, dsa_pks, &mut peeled)?;
    println!(
        "layer_decrypt: {}",
        String::from_utf8_lossy(&peeled[..peeled_len])
    );

    let onion_kem = [kem_pk0.as_slice(), kem_pk1.as_slice()];
    let onion_dsa = [dsa_sk0.as_slice(), dsa_sk1.as_slice()];
    let onion_kem_sks = [kem_sk0.as_slice(), kem_sk1.as_slice()];
    let onion_dsa_pks = [dsa_pk0.as_slice(), dsa_pk1.as_slice()];

    let mut onion_out = vec![0u8; MSG.len() + (2 * LAYER_OVERHEAD)];
    let onion_len = onion(MSG, &onion_kem, &onion_dsa, &mut onion_out)?;
    println!("onion(2): packet={} bytes", onion_len);
    let mut onion_peeled = vec![0u8; MSG.len() + (2 * LAYER_OVERHEAD)];
    let onion_peeled_len = cut(
        &onion_out[..onion_len],
        &onion_kem_sks,
        &onion_dsa_pks,
        &mut onion_peeled,
    )?;
    println!(
        "cut: {}",
        String::from_utf8_lossy(&onion_peeled[..onion_peeled_len])
    );

    Ok(())
}
