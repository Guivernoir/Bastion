#![no_main]

use crypto_bastion::{compare, encrypt};
use libfuzzer_sys::fuzz_target;

fn expand<const N: usize>(data: &[u8], seed: u8) -> [u8; N] {
    let mut out = [0u8; N];
    if data.is_empty() {
        out.fill(seed);
        return out;
    }
    for i in 0..N {
        out[i] = data[i % data.len()] ^ seed.wrapping_add(i as u8);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let key = expand::<32>(data, 0x11);
    let nonce = expand::<12>(data, 0x22);

    let aad_len = if data.is_empty() { 0 } else { data[0] as usize % 64 };
    let pt_len = if data.len() < 2 { 0 } else { data[1] as usize % 256 };

    let mut aad = vec![0u8; aad_len];
    let mut pt = vec![0u8; pt_len];
    for i in 0..aad_len {
        aad[i] = data.get(2 + i).copied().unwrap_or(0) ^ 0xA5;
    }
    for i in 0..pt_len {
        pt[i] = data.get(2 + aad_len + i).copied().unwrap_or(0) ^ 0x5A;
    }

    let mut ct1 = vec![0u8; pt.len()];
    let mut ct2 = vec![0u8; pt.len()];
    let mut tag1 = [0u8; 16];
    let mut tag2 = [0u8; 16];

    let r1 = encrypt(&key, &nonce, &aad, &pt, &mut ct1, &mut tag1);
    let r2 = encrypt(&key, &nonce, &aad, &pt, &mut ct2, &mut tag2);

    if let (Ok(len1), Ok(len2)) = (r1, r2) {
        assert_eq!(len1, len2);
        assert!(compare(&ct1[..len1], &ct2[..len2]));
        assert!(compare(&tag1, &tag2));
    }
});
