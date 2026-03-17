#![allow(missing_docs)]

use crypto_bastion::{
    DSA_PUBLIC_KEY_SIZE, DSA_SECRET_KEY_SIZE, DSA_SIGNATURE_SIZE, KEM_CIPHERTEXT_SIZE,
    KEM_PUBLIC_KEY_SIZE, KEM_SECRET_KEY_SIZE, LAYER_OVERHEAD, compare, cut, decrypt, dsa_keygen,
    encapsulate, encrypt, hash, kem_keygen, layer_decrypt, layer_encrypt, onion, sign, verify,
};

const MSG: &[u8; 23] = b"bastion public api demo";

fn main() {
    let digest = hash(MSG);
    println!("SHA-512(msg)[0..8] = {:02x?}", &digest[..8]);
    println!("compare(msg, msg) = {}", compare(MSG, MSG));

    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let aad = [0x33u8; 16];
    let mut ct = [0u8; MSG.len()];
    let mut tag = [0u8; 16];
    match encrypt(&key, &nonce, &aad, MSG, &mut ct, &mut tag) {
        Ok(ct_len) => {
            println!("encrypt: ct={} bytes tag={:02x?}", ct_len, tag);
            let mut pt = [0u8; MSG.len()];
            match decrypt(&key, &nonce, &aad, &ct[..ct_len], &tag, &mut pt) {
                Ok(pt_len) => println!("decrypt: {}", String::from_utf8_lossy(&pt[..pt_len])),
                Err(e) => println!("decrypt failed: {e}"),
            }
        }
        Err(e) => println!("encrypt failed: {e}"),
    }

    let mut kem_pk = [0u8; KEM_PUBLIC_KEY_SIZE];
    let mut kem_sk = [0u8; KEM_SECRET_KEY_SIZE];
    let mut kem_ct = [0u8; KEM_CIPHERTEXT_SIZE];
    let mut ss = [0u8; 32];
    match kem_keygen(&mut kem_pk, &mut kem_sk) {
        Ok(()) => match encapsulate(&kem_pk, &mut kem_ct, &mut ss) {
            Ok(()) => println!(
                "kem_keygen + encapsulate: pk={} sk={} ct={} ss[0..8]={:02x?}",
                kem_pk.len(),
                kem_sk.len(),
                kem_ct.len(),
                &ss[..8]
            ),
            Err(e) => println!("encapsulate failed: {e}"),
        },
        Err(e) => println!("kem_keygen failed: {e}"),
    }

    let mut dsa_pk = [0u8; DSA_PUBLIC_KEY_SIZE];
    let mut dsa_sk = [0u8; DSA_SECRET_KEY_SIZE];
    let mut sig = [0u8; DSA_SIGNATURE_SIZE];
    match dsa_keygen(&mut dsa_pk, &mut dsa_sk) {
        Ok(()) => match sign(&dsa_sk, MSG, &mut sig) {
            Ok(()) => println!("verify: {}", verify(&dsa_pk, MSG, &sig)),
            Err(e) => println!("sign failed: {e}"),
        },
        Err(e) => println!("dsa_keygen failed: {e}"),
    }

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

    if kem_keygen(&mut kem_pk0, &mut kem_sk0).is_ok()
        && kem_keygen(&mut kem_pk1, &mut kem_sk1).is_ok()
        && kem_keygen(&mut kem_pk2, &mut kem_sk2).is_ok()
        && dsa_keygen(&mut dsa_pk0, &mut dsa_sk0).is_ok()
        && dsa_keygen(&mut dsa_pk1, &mut dsa_sk1).is_ok()
        && dsa_keygen(&mut dsa_pk2, &mut dsa_sk2).is_ok()
    {
        let kem_pks = [kem_pk0.as_slice(), kem_pk1.as_slice(), kem_pk2.as_slice()];
        let dsa_sks = [dsa_sk0.as_slice(), dsa_sk1.as_slice(), dsa_sk2.as_slice()];
        let kem_sks = [kem_sk0.as_slice(), kem_sk1.as_slice(), kem_sk2.as_slice()];
        let dsa_pks = [dsa_pk0.as_slice(), dsa_pk1.as_slice(), dsa_pk2.as_slice()];

        let mut layered = vec![0u8; MSG.len() + (3 * LAYER_OVERHEAD)];
        match layer_encrypt(MSG, kem_pks, dsa_sks, &mut layered) {
            Ok(packet_len) => {
                println!("layer_encrypt: packet={} bytes", packet_len);
                let mut peeled = vec![0u8; MSG.len() + (3 * LAYER_OVERHEAD)];
                match layer_decrypt(&layered[..packet_len], kem_sks, dsa_pks, &mut peeled) {
                    Ok(pt_len) => {
                        println!(
                            "layer_decrypt: {}",
                            String::from_utf8_lossy(&peeled[..pt_len])
                        )
                    }
                    Err(e) => println!("layer_decrypt failed: {e}"),
                }
            }
            Err(e) => println!("layer_encrypt failed: {e}"),
        }

        let onion_kem = [kem_pk0.as_slice(), kem_pk1.as_slice()];
        let onion_dsa = [dsa_sk0.as_slice(), dsa_sk1.as_slice()];
        let onion_kem_sks = [kem_sk0.as_slice(), kem_sk1.as_slice()];
        let onion_dsa_pks = [dsa_pk0.as_slice(), dsa_pk1.as_slice()];

        let mut onion_out = vec![0u8; MSG.len() + (2 * LAYER_OVERHEAD)];
        match onion(MSG, &onion_kem, &onion_dsa, &mut onion_out) {
            Ok(packet_len) => {
                println!("onion(2): packet={} bytes", packet_len);
                let mut peeled = vec![0u8; MSG.len() + (2 * LAYER_OVERHEAD)];
                match cut(
                    &onion_out[..packet_len],
                    &onion_kem_sks,
                    &onion_dsa_pks,
                    &mut peeled,
                ) {
                    Ok(pt_len) => println!("cut: {}", String::from_utf8_lossy(&peeled[..pt_len])),
                    Err(e) => println!("cut failed: {e}"),
                }
            }
            Err(e) => println!("onion failed: {e}"),
        }
    }
}
