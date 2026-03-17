#![no_main]

use crypto_bastion::{
    DSA_PUBLIC_KEY_SIZE, DSA_SECRET_KEY_SIZE, DSA_SIGNATURE_SIZE, KEM_CIPHERTEXT_SIZE,
    KEM_PUBLIC_KEY_SIZE, KEM_SECRET_KEY_SIZE, decapsulate, dsa_keygen, encapsulate, hash,
    kem_keygen, sign, verify,
};
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
    let kem_pk = expand_vec(data, KEM_PUBLIC_KEY_SIZE, 0x31);
    let kem_sk = expand_vec(data, KEM_SECRET_KEY_SIZE, 0x41);
    let dsa_pk = expand_vec(data, DSA_PUBLIC_KEY_SIZE, 0x47);
    let dsa_sk = expand_vec(data, DSA_SECRET_KEY_SIZE, 0x53);

    let msg_len = if data.is_empty() {
        0
    } else {
        data[0] as usize % 512
    };
    let mut msg = vec![0u8; msg_len];
    for i in 0..msg_len {
        msg[i] = data.get(1 + i).copied().unwrap_or(0) ^ 0x7C;
    }

    let mut ct = [0u8; KEM_CIPHERTEXT_SIZE];
    let mut ss = [0u8; 32];
    if encapsulate(&kem_pk, &mut ct, &mut ss).is_ok() {
        let _ = hash(&ct);
        let _ = hash(&ss);
        let _ = decapsulate(&kem_sk, &ct, &mut ss);
    }

    let mut sig = [0u8; DSA_SIGNATURE_SIZE];
    if sign(&dsa_sk, &msg, &mut sig).is_ok() {
        let _ = hash(&sig);
        let _ = verify(&dsa_pk, &msg, &sig);
    }

    let mut kem_pk_real = [0u8; KEM_PUBLIC_KEY_SIZE];
    let mut kem_sk_real = [0u8; KEM_SECRET_KEY_SIZE];
    let mut kem_ct_real = [0u8; KEM_CIPHERTEXT_SIZE];
    let mut ss_real = [0u8; 32];
    let mut ss_real_decap = [0u8; 32];
    if kem_keygen(&mut kem_pk_real, &mut kem_sk_real).is_ok()
        && encapsulate(&kem_pk_real, &mut kem_ct_real, &mut ss_real).is_ok()
    {
        let _ = decapsulate(&kem_sk_real, &kem_ct_real, &mut ss_real_decap);
        let _ = hash(&kem_pk_real);
        let _ = hash(&kem_ct_real);
        let _ = hash(&ss_real);
        let _ = hash(&ss_real_decap);
    }

    let mut dsa_pk_real = [0u8; DSA_PUBLIC_KEY_SIZE];
    let mut dsa_sk_real = [0u8; DSA_SECRET_KEY_SIZE];
    let mut dsa_sig_real = [0u8; DSA_SIGNATURE_SIZE];
    if dsa_keygen(&mut dsa_pk_real, &mut dsa_sk_real).is_ok()
        && sign(&dsa_sk_real, &msg, &mut dsa_sig_real).is_ok()
    {
        let _ = verify(&dsa_pk_real, &msg, &dsa_sig_real);
        let _ = hash(&dsa_pk_real);
        let _ = hash(&dsa_sig_real);
    }
});
