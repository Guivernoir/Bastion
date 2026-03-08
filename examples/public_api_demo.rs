#![allow(missing_docs)]

use crypto_bastion::{compare, encapsulate, encrypt, hash, layer_encrypt, onion, sign};

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
        }
        Err(e) => println!("encrypt failed: {e}"),
    }

    let kem_pk = vec![0x55u8; 1568];
    let mut kem_ct = [0u8; 1568];
    let mut ss = [0u8; 32];
    match encapsulate(&kem_pk, &mut kem_ct, &mut ss) {
        Ok(()) => println!(
            "encapsulate: ct={} bytes ss[0..8]={:02x?}",
            kem_ct.len(),
            &ss[..8]
        ),
        Err(e) => println!("encapsulate failed: {e}"),
    }

    let dsa_sk = vec![0x66u8; 4896];
    let mut sig = [0u8; 4627];
    match sign(&dsa_sk, msg, &mut sig) {
        Ok(()) => println!("sign: sig={} bytes", sig.len()),
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
        Ok(packet_len) => println!("layer_encrypt: packet={} bytes", packet_len),
        Err(e) => println!("layer_encrypt failed: {e}"),
    }

    let onion_kem = [kem0.as_slice(), kem1.as_slice()];
    let onion_dsa = [dsa0.as_slice(), dsa1.as_slice()];
    let mut onion_out = vec![0u8; msg.len() + (2 * 6223)];
    match onion(msg, &onion_kem, &onion_dsa, &mut onion_out) {
        Ok(packet_len) => println!("onion(2): packet={} bytes", packet_len),
        Err(e) => println!("onion failed: {e}"),
    }
}
