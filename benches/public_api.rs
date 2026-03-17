#![allow(missing_docs)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use crypto_bastion::{
    MLSIGCRYPT_PACKET_OVERHEAD, MLSIGCRYPT_PUBLIC_KEY_SIZE, MLSIGCRYPT_SECRET_KEY_SIZE,
    mlsigcrypt_keygen, mlsigcrypt_signcrypt, mlsigcrypt_unsigncrypt,
};

const MLSIGCRYPT_MSG_256: usize = 256;

fn bench_mlsigcrypt(c: &mut Criterion) {
    let aad = [0xA6u8; 32];
    let msg = [0xD4u8; MLSIGCRYPT_MSG_256];

    let mut sender_pk = [0u8; MLSIGCRYPT_PUBLIC_KEY_SIZE];
    let mut sender_sk = [0u8; MLSIGCRYPT_SECRET_KEY_SIZE];
    let mut recipient_pk = [0u8; MLSIGCRYPT_PUBLIC_KEY_SIZE];
    let mut recipient_sk = [0u8; MLSIGCRYPT_SECRET_KEY_SIZE];
    let mut keygen_pk = [0u8; MLSIGCRYPT_PUBLIC_KEY_SIZE];
    let mut keygen_sk = [0u8; MLSIGCRYPT_SECRET_KEY_SIZE];
    let mut packet = vec![0u8; MLSIGCRYPT_PACKET_OVERHEAD + msg.len()];
    let mut opened = vec![0u8; msg.len()];

    let _ = mlsigcrypt_keygen(&mut sender_pk, &mut sender_sk);
    let _ = mlsigcrypt_keygen(&mut recipient_pk, &mut recipient_sk);
    let packet_len =
        mlsigcrypt_signcrypt(&sender_sk, &recipient_pk, &aad, &msg, &mut packet).unwrap_or(0);

    c.bench_function("api/mlsigcrypt_keygen", |b| {
        b.iter(|| {
            let out = mlsigcrypt_keygen(black_box(&mut keygen_pk), black_box(&mut keygen_sk));
            let _ = black_box(out);
        })
    });

    c.bench_function("api/mlsigcrypt_signcrypt/256b", |b| {
        b.iter(|| {
            let out = mlsigcrypt_signcrypt(
                black_box(&sender_sk),
                black_box(&recipient_pk),
                black_box(&aad),
                black_box(&msg),
                black_box(&mut packet),
            );
            let _ = black_box(out);
        })
    });

    c.bench_function("api/mlsigcrypt_unsigncrypt/256b", |b| {
        b.iter(|| {
            let out = mlsigcrypt_unsigncrypt(
                black_box(&recipient_sk),
                black_box(&sender_pk),
                black_box(&aad),
                black_box(&packet[..packet_len]),
                black_box(&mut opened),
            );
            let _ = black_box(out);
        })
    });
}

criterion_group!(benches, bench_mlsigcrypt);
criterion_main!(benches);
