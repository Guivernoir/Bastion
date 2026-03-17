#![allow(missing_docs)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use crypto_bastion::{
    DSA_PUBLIC_KEY_SIZE, DSA_SECRET_KEY_SIZE, DSA_SIGNATURE_SIZE, KEM_CIPHERTEXT_SIZE,
    KEM_PUBLIC_KEY_SIZE, KEM_SECRET_KEY_SIZE, LAYER_OVERHEAD, compare, cut, decapsulate, decrypt,
    dsa_keygen, encapsulate, encrypt, hash, kem_keygen, layer_decrypt, layer_encrypt, onion, sign,
    verify,
};

const PLAINTEXT_1K: usize = 1024;
const SIGN_MSG_256: usize = 256;
const LAYER_PT_128: usize = 128;

fn bench_hash_compare(c: &mut Criterion) {
    let data = [0xA5u8; 4096];
    let other = [0x5Au8; 4096];

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

fn bench_symmetric(c: &mut Criterion) {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let aad = [0x33u8; 32];
    let plaintext = [0x44u8; PLAINTEXT_1K];
    let mut ct_out = [0u8; PLAINTEXT_1K];
    let mut tag_out = [0u8; 16];

    let ct_len =
        encrypt(&key, &nonce, &aad, &plaintext, &mut ct_out, &mut tag_out).unwrap_or_default();
    let mut pt_out = [0u8; PLAINTEXT_1K];

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

    c.bench_function("api/decrypt/1k", |b| {
        b.iter(|| {
            let out_len = decrypt(
                black_box(&key),
                black_box(&nonce),
                black_box(&aad),
                black_box(&ct_out[..ct_len]),
                black_box(&tag_out),
                black_box(&mut pt_out),
            );
            let _ = black_box(out_len);
        })
    });
}

fn bench_pqc(c: &mut Criterion) {
    let mut kem_pk = [0u8; KEM_PUBLIC_KEY_SIZE];
    let mut kem_sk = [0u8; KEM_SECRET_KEY_SIZE];
    let mut kem_ct = [0u8; KEM_CIPHERTEXT_SIZE];
    let mut kem_ss = [0u8; 32];

    let mut dsa_pk = [0u8; DSA_PUBLIC_KEY_SIZE];
    let mut dsa_sk = [0u8; DSA_SECRET_KEY_SIZE];
    let mut sig_out = [0u8; DSA_SIGNATURE_SIZE];
    let msg = [0x77u8; SIGN_MSG_256];

    let _ = kem_keygen(&mut kem_pk, &mut kem_sk);
    let _ = dsa_keygen(&mut dsa_pk, &mut dsa_sk);
    let _ = sign(&dsa_sk, &msg, &mut sig_out);

    c.bench_function("api/kem_keygen", |b| {
        b.iter(|| {
            let r = kem_keygen(black_box(&mut kem_pk), black_box(&mut kem_sk));
            let _ = black_box(r);
        })
    });

    c.bench_function("api/encapsulate", |b| {
        b.iter(|| {
            let r = encapsulate(
                black_box(&kem_pk),
                black_box(&mut kem_ct),
                black_box(&mut kem_ss),
            );
            let _ = black_box(r);
        })
    });

    c.bench_function("api/decapsulate", |b| {
        b.iter(|| {
            let r = decapsulate(
                black_box(&kem_sk),
                black_box(&kem_ct),
                black_box(&mut kem_ss),
            );
            let _ = black_box(r);
        })
    });

    c.bench_function("api/dsa_keygen", |b| {
        b.iter(|| {
            let r = dsa_keygen(black_box(&mut dsa_pk), black_box(&mut dsa_sk));
            let _ = black_box(r);
        })
    });

    c.bench_function("api/sign/256b", |b| {
        b.iter(|| {
            let r = sign(black_box(&dsa_sk), black_box(&msg), black_box(&mut sig_out));
            let _ = black_box(r);
        })
    });

    c.bench_function("api/verify/256b", |b| {
        b.iter(|| {
            let r = verify(black_box(&dsa_pk), black_box(&msg), black_box(&sig_out));
            let _ = black_box(r);
        })
    });
}

fn bench_layered(c: &mut Criterion) {
    let plaintext = [0x99u8; LAYER_PT_128];

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

    let _ = kem_keygen(&mut kem_pk0, &mut kem_sk0);
    let _ = kem_keygen(&mut kem_pk1, &mut kem_sk1);
    let _ = kem_keygen(&mut kem_pk2, &mut kem_sk2);
    let _ = dsa_keygen(&mut dsa_pk0, &mut dsa_sk0);
    let _ = dsa_keygen(&mut dsa_pk1, &mut dsa_sk1);
    let _ = dsa_keygen(&mut dsa_pk2, &mut dsa_sk2);

    let kem_pks = [kem_pk0.as_slice(), kem_pk1.as_slice(), kem_pk2.as_slice()];
    let dsa_sks = [dsa_sk0.as_slice(), dsa_sk1.as_slice(), dsa_sk2.as_slice()];
    let onion_kem = [kem_pk0.as_slice(), kem_pk1.as_slice()];
    let onion_dsa = [dsa_sk0.as_slice(), dsa_sk1.as_slice()];

    let kem_sks_3 = [kem_sk0.as_slice(), kem_sk1.as_slice(), kem_sk2.as_slice()];
    let dsa_pks_3 = [dsa_pk0.as_slice(), dsa_pk1.as_slice(), dsa_pk2.as_slice()];
    let kem_sks_2 = [kem_sk0.as_slice(), kem_sk1.as_slice()];
    let dsa_pks_2 = [dsa_pk0.as_slice(), dsa_pk1.as_slice()];

    let mut layered_out = vec![0u8; LAYER_PT_128 + 3 * LAYER_OVERHEAD];
    let mut layered_peel_out = vec![0u8; LAYER_PT_128 + 3 * LAYER_OVERHEAD];
    let mut onion_out = vec![0u8; LAYER_PT_128 + 2 * LAYER_OVERHEAD];
    let mut cut_out = vec![0u8; LAYER_PT_128 + 2 * LAYER_OVERHEAD];

    let layered_len =
        layer_encrypt(&plaintext, kem_pks, dsa_sks, &mut layered_out).unwrap_or_default();
    let onion_len = onion(&plaintext, &onion_kem, &onion_dsa, &mut onion_out).unwrap_or_default();

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

    c.bench_function("api/layer_decrypt/3-layers", |b| {
        b.iter(|| {
            let out_len = layer_decrypt(
                black_box(&layered_out[..layered_len]),
                black_box(kem_sks_3),
                black_box(dsa_pks_3),
                black_box(&mut layered_peel_out),
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

    c.bench_function("api/cut/2-layers", |b| {
        b.iter(|| {
            let out_len = cut(
                black_box(&onion_out[..onion_len]),
                black_box(&kem_sks_2),
                black_box(&dsa_pks_2),
                black_box(&mut cut_out),
            );
            let _ = black_box(out_len);
        })
    });
}

fn all_benches(c: &mut Criterion) {
    bench_hash_compare(c);
    bench_symmetric(c);
    bench_pqc(c);
    bench_layered(c);
}

criterion_group!(benches, all_benches);
criterion_main!(benches);
