#![no_main]

use crypto_bastion::{decapsulate, encapsulate, hash, sign, verify};
use libfuzzer_sys::fuzz_target;

fn expand_vec(data: &[u8], len: usize, seed: u8) -> Vec<u8> {
    let mut out = vec![0u8; len];
    if data.is_empty() {
        out.fill(seed);
        return out;
    }
    for i in 0..len {
        out[i] = data[i % data.len()] ^ seed.wrapping_add(i as u8);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let kem_pk = expand_vec(data, 1568, 0x31);
    let kem_sk = expand_vec(data, 3168, 0x41);
    let dsa_pk = expand_vec(data, 2592, 0x47);
    let dsa_sk = expand_vec(data, 4896, 0x53);

    let msg_len = if data.is_empty() {
        0
    } else {
        data[0] as usize % 512
    };
    let mut msg = vec![0u8; msg_len];
    for i in 0..msg_len {
        msg[i] = data.get(1 + i).copied().unwrap_or(0) ^ 0x7C;
    }

    let mut ct = [0u8; 1568];
    let mut ss = [0u8; 32];
    if encapsulate(&kem_pk, &mut ct, &mut ss).is_ok() {
        let _ = hash(&ct);
        let _ = hash(&ss);
        let _ = decapsulate(&kem_sk, &ct, &mut ss);
    }

    let mut sig = [0u8; 4627];
    if sign(&dsa_sk, &msg, &mut sig).is_ok() {
        let _ = hash(&sig);
        let _ = verify(&dsa_pk, &msg, &sig);
    }
});
