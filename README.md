# Bastion

Bastion is a hardened cryptographic crate focused on strict operational constraints:

- post-quantum primitives: ML-KEM-1024 and ML-DSA-87
- authenticated encryption: AES-256-GCM
- SHA-512 hashing
- zeroization of sensitive material
- bounded public API with timing-floor normalization
- runtime dependency-free (`[dependencies]` is empty)
- allocation-aware measurement workflow

## Public API

Only these crate-level functions are public:

- `mlsigcrypt_v1_keygen`
- `mlsigcrypt_v1_signcrypt`
- `mlsigcrypt_v1_unsigncrypt`
- legacy primitive surface:
- `encrypt`
- `decrypt`
- `kem_keygen`
- `encapsulate`
- `decapsulate`
- `dsa_keygen`
- `sign`
- `verify`
- `hash`
- `compare`
- `layer_encrypt`
- `layer_decrypt`
- `onion`
- `cut`

The crate also exposes public size constants for buffer sizing:

- `KEM_PUBLIC_KEY_SIZE`
- `KEM_SECRET_KEY_SIZE`
- `KEM_CIPHERTEXT_SIZE`
- `DSA_PUBLIC_KEY_SIZE`
- `DSA_SECRET_KEY_SIZE`
- `DSA_SIGNATURE_SIZE`
- `MLSIGCRYPT_V1_PUBLIC_KEY_SIZE`
- `MLSIGCRYPT_V1_SECRET_KEY_SIZE`
- `MLSIGCRYPT_V1_PACKET_OVERHEAD`
- `NONCE_SIZE`
- `TAG_SIZE`
- `LAYER_OVERHEAD`

Current signatures are buffer-oriented (caller provides output memory):

```rust
pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
    tag_out: &mut [u8; 16],
) -> Result<usize, &'static str>;

pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    plaintext_out: &mut [u8],
) -> Result<usize, &'static str>;

pub fn kem_keygen(
    pk_out: &mut [u8; KEM_PUBLIC_KEY_SIZE],
    sk_out: &mut [u8; KEM_SECRET_KEY_SIZE],
) -> Result<(), &'static str>;

pub fn encapsulate(
    pk: &[u8],
    ct_out: &mut [u8; KEM_CIPHERTEXT_SIZE],
    ss_out: &mut [u8; 32],
) -> Result<(), &'static str>;

pub fn decapsulate(
    sk: &[u8],
    ct: &[u8],
    ss_out: &mut [u8; 32],
) -> Result<(), &'static str>;

pub fn dsa_keygen(
    pk_out: &mut [u8; DSA_PUBLIC_KEY_SIZE],
    sk_out: &mut [u8; DSA_SECRET_KEY_SIZE],
) -> Result<(), &'static str>;

pub fn sign(
    sk: &[u8],
    msg: &[u8],
    sig_out: &mut [u8; DSA_SIGNATURE_SIZE],
) -> Result<(), &'static str>;

pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool;

pub fn mlsigcrypt_v1_keygen(
    pk_user_out: &mut [u8; MLSIGCRYPT_V1_PUBLIC_KEY_SIZE],
    sk_user_out: &mut [u8; MLSIGCRYPT_V1_SECRET_KEY_SIZE],
) -> Result<(), &'static str>;

pub fn mlsigcrypt_v1_signcrypt(
    sk_user_sender: &[u8],
    pk_user_recipient: &[u8],
    aad: &[u8],
    message: &[u8],
    packet_out: &mut [u8],
) -> Result<usize, &'static str>;

pub fn mlsigcrypt_v1_unsigncrypt(
    sk_user_recipient: &[u8],
    pk_user_sender: &[u8],
    aad: &[u8],
    packet: &[u8],
    plaintext_out: &mut [u8],
) -> Result<usize, &'static str>;

pub fn hash(data: &[u8]) -> [u8; 64];
pub fn compare(a: &[u8], b: &[u8]) -> bool;

pub fn layer_encrypt(
    plaintext: &[u8],
    kem_pks: [&[u8]; 3],
    dsa_sks: [&[u8]; 3],
    out: &mut [u8],
) -> Result<usize, &'static str>;

pub fn layer_decrypt(
    packet: &[u8],
    kem_sks: [&[u8]; 3],
    dsa_pks: [&[u8]; 3],
    out: &mut [u8],
) -> Result<usize, &'static str>;

pub fn onion(
    plaintext: &[u8],
    kem_pks: &[&[u8]],
    dsa_sks: &[&[u8]],
    out: &mut [u8],
) -> Result<usize, &'static str>;

pub fn cut(
    packet: &[u8],
    kem_sks: &[&[u8]],
    dsa_pks: &[&[u8]],
    out: &mut [u8],
) -> Result<usize, &'static str>;
```

## Install

```toml
[dependencies]
crypto_bastion = "0.4"
```

## Quick Start

### Hash and Compare

```rust
use crypto_bastion::{compare, hash};

let a = hash(b"alpha");
let b = hash(b"alpha");
assert!(compare(&a, &b));
```

### AES-256-GCM Encrypt

```rust
use crypto_bastion::encrypt;

let key = [0x11u8; 32];
let nonce = [0x22u8; 12];
let aad = b"context";
let pt = b"payload";

let mut ct = vec![0u8; pt.len()];
let mut tag = [0u8; 16];
let n = encrypt(&key, &nonce, aad, pt, &mut ct, &mut tag)?;
assert_eq!(n, pt.len());
# Ok::<(), &'static str>(())
```

### ML-KEM Key Management + Encapsulation

```rust
use crypto_bastion::{
    KEM_CIPHERTEXT_SIZE, KEM_PUBLIC_KEY_SIZE, KEM_SECRET_KEY_SIZE, encapsulate, kem_keygen,
};

let mut pk = [0u8; KEM_PUBLIC_KEY_SIZE];
let mut sk = [0u8; KEM_SECRET_KEY_SIZE];
let mut ct = [0u8; KEM_CIPHERTEXT_SIZE];
let mut ss = [0u8; 32];
kem_keygen(&mut pk, &mut sk)?;
encapsulate(&pk, &mut ct, &mut ss)?;
assert!(ct.iter().any(|&b| b != 0));
assert!(ss.iter().any(|&b| b != 0));
# Ok::<(), &'static str>(())
```

### ML-DSA Key Management + Signature

```rust
use crypto_bastion::{
    DSA_PUBLIC_KEY_SIZE, DSA_SECRET_KEY_SIZE, DSA_SIGNATURE_SIZE, dsa_keygen, sign, verify,
};

let msg = b"signed-message";
let mut pk = [0u8; DSA_PUBLIC_KEY_SIZE];
let mut sk = [0u8; DSA_SECRET_KEY_SIZE];
let mut sig = [0u8; DSA_SIGNATURE_SIZE];
dsa_keygen(&mut pk, &mut sk)?;
sign(&sk, msg, &mut sig)?;
assert!(verify(&pk, msg, &sig));
# Ok::<(), &'static str>(())
```

### MLSigcrypt-v1 Unified Signcryption

`MLSIGCRYPT_V1_PACKET_OVERHEAD` is the fixed packet cost excluding the payload ciphertext.

```rust
use crypto_bastion::{
    MLSIGCRYPT_V1_PACKET_OVERHEAD, MLSIGCRYPT_V1_PUBLIC_KEY_SIZE, MLSIGCRYPT_V1_SECRET_KEY_SIZE,
    mlsigcrypt_v1_keygen, mlsigcrypt_v1_signcrypt, mlsigcrypt_v1_unsigncrypt,
};

let aad = b"context";
let msg = b"signcrypted";

let mut sender_pk = [0u8; MLSIGCRYPT_V1_PUBLIC_KEY_SIZE];
let mut sender_sk = [0u8; MLSIGCRYPT_V1_SECRET_KEY_SIZE];
let mut recipient_pk = [0u8; MLSIGCRYPT_V1_PUBLIC_KEY_SIZE];
let mut recipient_sk = [0u8; MLSIGCRYPT_V1_SECRET_KEY_SIZE];
let mut packet = vec![0u8; MLSIGCRYPT_V1_PACKET_OVERHEAD + msg.len()];
let mut plaintext = vec![0u8; msg.len()];

mlsigcrypt_v1_keygen(&mut sender_pk, &mut sender_sk)?;
mlsigcrypt_v1_keygen(&mut recipient_pk, &mut recipient_sk)?;
let packet_len =
    mlsigcrypt_v1_signcrypt(&sender_sk, &recipient_pk, aad, msg, &mut packet)?;
let plain_len = mlsigcrypt_v1_unsigncrypt(
    &recipient_sk,
    &sender_pk,
    aad,
    &packet[..packet_len],
    &mut plaintext,
)?;

assert_eq!(&plaintext[..plain_len], msg);
# Ok::<(), &'static str>(())
```

### Layered Onion Encryption

Per-layer overhead is `LAYER_OVERHEAD` bytes. Required output size is:

- `plaintext.len() + (layers * LAYER_OVERHEAD)`

```rust
use crypto_bastion::{
    DSA_PUBLIC_KEY_SIZE, DSA_SECRET_KEY_SIZE, KEM_PUBLIC_KEY_SIZE, KEM_SECRET_KEY_SIZE,
    LAYER_OVERHEAD, dsa_keygen, kem_keygen, onion,
};

let msg = b"onion-data";
let mut kem0 = [0u8; KEM_PUBLIC_KEY_SIZE];
let mut kem1 = [0u8; KEM_PUBLIC_KEY_SIZE];
let mut kem0_sk = [0u8; KEM_SECRET_KEY_SIZE];
let mut kem1_sk = [0u8; KEM_SECRET_KEY_SIZE];
let mut dsa0 = [0u8; DSA_SECRET_KEY_SIZE];
let mut dsa1 = [0u8; DSA_SECRET_KEY_SIZE];
let mut dsa0_pk = [0u8; DSA_PUBLIC_KEY_SIZE];
let mut dsa1_pk = [0u8; DSA_PUBLIC_KEY_SIZE];

kem_keygen(&mut kem0, &mut kem0_sk)?;
kem_keygen(&mut kem1, &mut kem1_sk)?;
dsa_keygen(&mut dsa0_pk, &mut dsa0)?;
dsa_keygen(&mut dsa1_pk, &mut dsa1)?;

let kem = [kem0.as_slice(), kem1.as_slice()];
let dsa = [dsa0.as_slice(), dsa1.as_slice()];

let mut out = vec![0u8; msg.len() + (2 * LAYER_OVERHEAD)];
let packet_len = onion(msg, &kem, &dsa, &mut out)?;
assert_eq!(packet_len, msg.len() + (2 * LAYER_OVERHEAD));
# Ok::<(), &'static str>(())
```

## Security and Engineering Constraints

- Secret material is zeroized in internal key/signing paths.
- Public key-generation paths are buffer-oriented and zeroize transient seeds/intermediates.
- Public API wrappers enforce timing floors.
- `compare` is constant-time over equal-length slices.
- Public API paths are allocation-aware; measurements are generated by `write_results`.
- Key material stays as raw caller-owned byte buffers; no public heap-backed containers are exposed.

See [SECURITY.md](SECURITY.md) for the detailed model and verification process.

## Verification Workflow

```bash
# Formatting and checks
cargo fmt
cargo check --all-targets
cargo test --all-targets

# Benchmarks
cargo bench --bench public_api

# Allocation + memory + timing-spread report
cargo run --example write_results

# Fuzzing targets (cargo-fuzz + nightly)
cd fuzz
cargo +nightly fuzz run fuzz_hash_compare -- -max_total_time=30
cargo +nightly fuzz run fuzz_encrypt_api -- -max_total_time=30
cargo +nightly fuzz run fuzz_encaps_sign_api -- -max_total_time=30
cargo +nightly fuzz run fuzz_onion_api -- -max_total_time=30
```

## Repository Layout

- `src/lib.rs` public API and hybrid orchestration
- `src/mlsigcrypt/` MLSigcrypt-v1 protocol orchestration and internal packet logic
- `src/mlsigcrypt/specs/` primitive implementations: SHA3-512, HKDF, SHA-512, AES-GCM, ML-KEM, ML-DSA
- `src/constant_time.rs` constant-time helpers and timing guard
- `src/zeroize.rs` zeroization primitives
- `examples/` usage and reporting tools
- `benches/` criterion benchmark suites
- `fuzz/` libFuzzer targets

## License

Licensed under MIT OR Apache-2.0.
