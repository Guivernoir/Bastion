#![no_main]

use crypto_bastion::{layer_encrypt, onion};
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

    let kem_3 = [kem0.as_slice(), kem1.as_slice(), kem2.as_slice()];
    let dsa_3 = [dsa0.as_slice(), dsa1.as_slice(), dsa2.as_slice()];
    let mut layer_out = vec![0u8; msg.len() + (3 * 6223)];

    let _ = layer_encrypt(&msg, kem_3, dsa_3, &mut layer_out);

    let kem_any = [kem0.as_slice(), kem1.as_slice()];
    let dsa_any = [dsa0.as_slice(), dsa1.as_slice()];
    let mut onion_out = vec![0u8; msg.len() + (2 * 6223)];
    let _ = onion(&msg, &kem_any, &dsa_any, &mut onion_out);
});
