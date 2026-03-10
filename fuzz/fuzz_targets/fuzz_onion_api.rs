#![no_main]

use crypto_bastion::{cut, layer_decrypt, layer_encrypt, onion};
use libfuzzer_sys::fuzz_target;

fn expand_vec(data: &[u8], len: usize, tweak: u8) -> Vec<u8> {
    let mut out = vec![0u8; len];
    if data.is_empty() {
        out.fill(tweak);
        return out;
    }
    for i in 0..len {
        out[i] = data[i % data.len()] ^ tweak.wrapping_add(i as u8);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let mut msg = vec![0u8; if data.is_empty() { 0 } else { data[0] as usize % 128 }];
    for i in 0..msg.len() {
        msg[i] = data.get(1 + i).copied().unwrap_or(0);
    }

    let kem0 = expand_vec(data, 1568, 0x01);
    let kem1 = expand_vec(data, 1568, 0x02);
    let kem2 = expand_vec(data, 1568, 0x03);
    let dsa0 = expand_vec(data, 4896, 0x11);
    let dsa1 = expand_vec(data, 4896, 0x22);
    let dsa2 = expand_vec(data, 4896, 0x33);
    let kem_sk0 = expand_vec(data, 3168, 0xA1);
    let kem_sk1 = expand_vec(data, 3168, 0xA2);
    let kem_sk2 = expand_vec(data, 3168, 0xA3);
    let dsa_pk0 = expand_vec(data, 2592, 0xB1);
    let dsa_pk1 = expand_vec(data, 2592, 0xB2);
    let dsa_pk2 = expand_vec(data, 2592, 0xB3);

    let kem_3 = [kem0.as_slice(), kem1.as_slice(), kem2.as_slice()];
    let dsa_3 = [dsa0.as_slice(), dsa1.as_slice(), dsa2.as_slice()];
    let kem_sks_3 = [kem_sk0.as_slice(), kem_sk1.as_slice(), kem_sk2.as_slice()];
    let dsa_pks_3 = [dsa_pk0.as_slice(), dsa_pk1.as_slice(), dsa_pk2.as_slice()];
    let mut layer_out = vec![0u8; msg.len() + (3 * 6223)];
    let mut layer_peel_out = vec![0u8; msg.len() + (3 * 6223)];

    if let Ok(packet_len) = layer_encrypt(&msg, kem_3, dsa_3, &mut layer_out) {
        let _ = layer_decrypt(
            &layer_out[..packet_len],
            kem_sks_3,
            dsa_pks_3,
            &mut layer_peel_out,
        );
    }

    let kem_any = [kem0.as_slice(), kem1.as_slice()];
    let dsa_any = [dsa0.as_slice(), dsa1.as_slice()];
    let kem_sks_any = [kem_sk0.as_slice(), kem_sk1.as_slice()];
    let dsa_pks_any = [dsa_pk0.as_slice(), dsa_pk1.as_slice()];
    let mut onion_out = vec![0u8; msg.len() + (2 * 6223)];
    let mut cut_out = vec![0u8; msg.len() + (2 * 6223)];
    if let Ok(packet_len) = onion(&msg, &kem_any, &dsa_any, &mut onion_out) {
        let _ = cut(&onion_out[..packet_len], &kem_sks_any, &dsa_pks_any, &mut cut_out);
    }
});
