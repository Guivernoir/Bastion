#![allow(missing_docs)]

use crypto_bastion::{
    compare, cut, decapsulate, decrypt, encapsulate, encrypt, hash, layer_decrypt, layer_encrypt,
    onion, sign, verify,
};

fn main() {
    let msg = b"bastion public api demo";
    let digest = hash(msg);
    println!("SHA-512(msg)[0..8] = {:02x?}", &digest[..8]);
    println!("compare(msg, msg) = {}", compare(msg, msg));

    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let aad = [0x33u8; 16];
    let mut ct = vec![0u8; msg.len()];
    let mut tag = [0u8; 16];
    match encrypt(&key, &nonce, &aad, msg, &mut ct, &mut tag) {
        Ok(ct_len) => {
            println!("encrypt: ct={} bytes tag={:02x?}", ct_len, tag);
            let mut pt = vec![0u8; ct_len];
            match decrypt(&key, &nonce, &aad, &ct[..ct_len], &tag, &mut pt) {
                Ok(pt_len) => println!("decrypt: pt={} bytes", pt_len),
                Err(e) => println!("decrypt failed: {e}"),
            }
        }
        Err(e) => println!("encrypt failed: {e}"),
    }

    let kem_pk = vec![0x55u8; 1568];
    let kem_sk = vec![0x77u8; 3168];
    let mut kem_ct = [0u8; 1568];
    let mut ss = [0u8; 32];
    match encapsulate(&kem_pk, &mut kem_ct, &mut ss) {
        Ok(()) => {
            println!(
                "encapsulate: ct={} bytes ss[0..8]={:02x?}",
                kem_ct.len(),
                &ss[..8]
            );
            let mut decap_ss = [0u8; 32];
            match decapsulate(&kem_sk, &kem_ct, &mut decap_ss) {
                Ok(()) => println!("decapsulate: ok"),
                Err(e) => println!("decapsulate failed: {e}"),
            }
        }
        Err(e) => println!("encapsulate failed: {e}"),
    }

    let dsa_pk = vec![0x88u8; 2592];
    let dsa_sk = vec![0x66u8; 4896];
    let mut sig = [0u8; 4627];
    match sign(&dsa_sk, msg, &mut sig) {
        Ok(()) => {
            println!("sign: sig={} bytes", sig.len());
            println!("verify: {}", verify(&dsa_pk, msg, &sig));
        }
        Err(e) => println!("sign failed: {e}"),
    }

    let kem0 = vec![0x01u8; 1568];
    let kem1 = vec![0x02u8; 1568];
    let kem2 = vec![0x03u8; 1568];
    let dsa0 = vec![0x11u8; 4896];
    let dsa1 = vec![0x22u8; 4896];
    let dsa2 = vec![0x33u8; 4896];

    let kem_pks = [kem0.as_slice(), kem1.as_slice(), kem2.as_slice()];
    let dsa_sks = [dsa0.as_slice(), dsa1.as_slice(), dsa2.as_slice()];
    let mut layered = vec![0u8; msg.len() + (3 * 6223)];
    match layer_encrypt(msg, kem_pks, dsa_sks, &mut layered) {
        Ok(packet_len) => {
            println!("layer_encrypt: packet={} bytes", packet_len);
            let kem_sks = [vec![0xA1u8; 3168], vec![0xA2u8; 3168], vec![0xA3u8; 3168]];
            let dsa_pks = [vec![0xB1u8; 2592], vec![0xB2u8; 2592], vec![0xB3u8; 2592]];
            let kem_sks_ref = [
                kem_sks[0].as_slice(),
                kem_sks[1].as_slice(),
                kem_sks[2].as_slice(),
            ];
            let dsa_pks_ref = [
                dsa_pks[0].as_slice(),
                dsa_pks[1].as_slice(),
                dsa_pks[2].as_slice(),
            ];
            let mut peeled = vec![0u8; packet_len];
            match layer_decrypt(
                &layered[..packet_len],
                kem_sks_ref,
                dsa_pks_ref,
                &mut peeled,
            ) {
                Ok(pt_len) => println!("layer_decrypt: pt={} bytes", pt_len),
                Err(e) => println!("layer_decrypt failed: {e}"),
            }
        }
        Err(e) => println!("layer_encrypt failed: {e}"),
    }

    let onion_kem = [kem0.as_slice(), kem1.as_slice()];
    let onion_dsa = [dsa0.as_slice(), dsa1.as_slice()];
    let mut onion_out = vec![0u8; msg.len() + (2 * 6223)];
    match onion(msg, &onion_kem, &onion_dsa, &mut onion_out) {
        Ok(packet_len) => {
            println!("onion(2): packet={} bytes", packet_len);
            let kem_sks = [vec![0xC1u8; 3168], vec![0xC2u8; 3168]];
            let dsa_pks = [vec![0xD1u8; 2592], vec![0xD2u8; 2592]];
            let kem_sks_ref = [kem_sks[0].as_slice(), kem_sks[1].as_slice()];
            let dsa_pks_ref = [dsa_pks[0].as_slice(), dsa_pks[1].as_slice()];
            let mut peeled = vec![0u8; packet_len];
            match cut(
                &onion_out[..packet_len],
                &kem_sks_ref,
                &dsa_pks_ref,
                &mut peeled,
            ) {
                Ok(pt_len) => println!("cut: pt={} bytes", pt_len),
                Err(e) => println!("cut failed: {e}"),
            }
        }
        Err(e) => println!("onion failed: {e}"),
    }
}
