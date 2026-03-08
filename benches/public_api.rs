#![allow(missing_docs)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use crypto_bastion::{compare, encapsulate, encrypt, hash, layer_encrypt, onion, sign};

fn bench_hash_compare(c: &mut Criterion) {
    let data = vec![0xA5u8; 4096];
    let other = vec![0x5Au8; 4096];

    c.bench_function("api/hash/4k", |b| {
        b.iter(|| {
            let d = hash(black_box(&data));
            black_box(d);
        })
    });

    c.bench_function("api/compare/equal-4k", |b| {
        b.iter(|| {
            let eq = compare(black_box(&data), black_box(&data));
            black_box(eq);
        })
    });

    c.bench_function("api/compare/diff-4k", |b| {
        b.iter(|| {
            let eq = compare(black_box(&data), black_box(&other));
            black_box(eq);
        })
    });
}

fn bench_encrypt(c: &mut Criterion) {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let aad = [0x33u8; 32];
    let plaintext = vec![0x44u8; 1024];
    let mut ct_out = [0u8; 1024];
    let mut tag_out = [0u8; 16];

    c.bench_function("api/encrypt/1k", |b| {
        b.iter(|| {
            let out_len = encrypt(
                black_box(&key),
                black_box(&nonce),
                black_box(&aad),
                black_box(&plaintext),
                black_box(&mut ct_out),
                black_box(&mut tag_out),
            );
            let _ = black_box(out_len);
        })
    });
}

fn bench_pqc(c: &mut Criterion) {
    let kem_pk = vec![0x55u8; 1568];
    let dsa_sk = vec![0x66u8; 4896];
    let msg = vec![0x77u8; 256];
    let mut ct_out = [0u8; 1568];
    let mut ss_out = [0u8; 32];
    let mut sig_out = [0u8; 4627];

    c.bench_function("api/encapsulate", |b| {
        b.iter(|| {
            let r = encapsulate(
                black_box(&kem_pk),
                black_box(&mut ct_out),
                black_box(&mut ss_out),
            );
            let _ = black_box(r);
        })
    });

    c.bench_function("api/sign/256b", |b| {
        b.iter(|| {
            let r = sign(black_box(&dsa_sk), black_box(&msg), black_box(&mut sig_out));
            let _ = black_box(r);
        })
    });
}

fn bench_layered(c: &mut Criterion) {
    let plaintext = vec![0x99u8; 128];

    let kem0 = vec![0x01u8; 1568];
    let kem1 = vec![0x02u8; 1568];
    let kem2 = vec![0x03u8; 1568];
    let dsa0 = vec![0x11u8; 4896];
    let dsa1 = vec![0x22u8; 4896];
    let dsa2 = vec![0x33u8; 4896];

    let kem_pks = [kem0.as_slice(), kem1.as_slice(), kem2.as_slice()];
    let dsa_sks = [dsa0.as_slice(), dsa1.as_slice(), dsa2.as_slice()];
    let onion_kem = [kem0.as_slice(), kem1.as_slice()];
    let onion_dsa = [dsa0.as_slice(), dsa1.as_slice()];
    let mut layered_out = [0u8; 128 + 3 * 6223];
    let mut onion_out = [0u8; 128 + 2 * 6223];

    c.bench_function("api/layer_encrypt/3-layers", |b| {
        b.iter(|| {
            let out_len = layer_encrypt(
                black_box(&plaintext),
                black_box(kem_pks),
                black_box(dsa_sks),
                black_box(&mut layered_out),
            );
            let _ = black_box(out_len);
        })
    });

    c.bench_function("api/onion/2-layers", |b| {
        b.iter(|| {
            let out_len = onion(
                black_box(&plaintext),
                black_box(&onion_kem),
                black_box(&onion_dsa),
                black_box(&mut onion_out),
            );
            let _ = black_box(out_len);
        })
    });
}

fn all_benches(c: &mut Criterion) {
    bench_hash_compare(c);
    bench_encrypt(c);
    bench_pqc(c);
    bench_layered(c);
}

criterion_group!(benches, all_benches);
criterion_main!(benches);
