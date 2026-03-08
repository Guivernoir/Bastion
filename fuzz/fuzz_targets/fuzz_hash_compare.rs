#![no_main]

use crypto_bastion::{compare, hash};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let d1 = hash(data);
    let d2 = hash(data);
    assert!(compare(&d1, &d2));

    assert!(compare(data, data));

    let mid = data.len() / 2;
    let (a, b) = data.split_at(mid);
    assert_eq!(compare(a, b), compare(b, a));

    if !a.is_empty() {
        let mut flipped = a.to_vec();
        flipped[0] ^= 0x01;
        let _ = compare(a, &flipped);
    }
});
