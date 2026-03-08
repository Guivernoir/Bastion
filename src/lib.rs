//! # Bastion — hybrid onion encryption (no-alloc public surface)
//!
//! Public APIs:
//! - [`encrypt`]: AES-256-GCM encrypt
//! - [`encapsulate`]: ML-KEM-1024 encapsulate
//! - [`sign`]: ML-DSA-87 detached signature
//! - [`hash`]: SHA-512 digest
//! - [`compare`]: constant-time byte-slice equality
//! - [`layer_encrypt`]: fixed 3-layer hybrid onion
//! - [`onion`]: variable-layer hybrid onion

#![allow(unsafe_code)]
#![allow(dead_code)]
#![deny(clippy::clone_on_ref_ptr)]
#![warn(clippy::unwrap_used, clippy::panic)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

mod algos;
mod audit;
mod constant_time;
mod error;
mod os_random;
mod pqc;
mod zeroize;

use error::{CryptoError, Result};

use crate::algos::aes256gcm::aes::Key256;
use crate::algos::aes256gcm::{Aes256Gcm, Nonce};
use crate::constant_time::{
    ct_copy_if, ct_eq, ct_hamming_weight, ct_in_range, ct_mod_reduce, ct_xor,
};
use crate::os_random::fill_os_random_array;
use crate::zeroize::zeroize_array;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// ML-KEM-1024 public key size (bytes).
pub(crate) const KEM_PK_SIZE: usize = pqc::KEM_PK_SIZE;
/// ML-KEM-1024 ciphertext size (bytes).
pub(crate) const KEM_CT_SIZE: usize = pqc::KEM_CT_SIZE;
/// ML-DSA-87 detached signature size (bytes).
pub(crate) const DSA_SIG_SIZE: usize = pqc::DSA_SIG_SIZE;

const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

/// Per-layer fixed overhead in bytes.
pub(crate) const LAYER_OVERHEAD: usize = KEM_CT_SIZE + NONCE_SIZE + TAG_SIZE + DSA_SIG_SIZE;

/// Best-effort timing floors for the public API wrappers (ns).
const FLOOR_PUBLIC_ENCRYPT_NS: u64 = 50_000;
const FLOOR_PUBLIC_ENCAPSULATE_NS: u64 = 120_000;
const FLOOR_PUBLIC_SIGN_NS: u64 = 300_000;
const FLOOR_PUBLIC_HASH_NS: u64 = 40_000;
const FLOOR_PUBLIC_COMPARE_NS: u64 = 40_000;
const FLOOR_PUBLIC_LAYER_NS: u64 = 800_000;
const FLOOR_PUBLIC_ONION_NS: u64 = 800_000;

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

const KEY_MIN_HAMMING_WEIGHT: u32 = 64;
const KEY_MAX_HAMMING_WEIGHT: u32 = 192;

#[inline]
fn validate_key_entropy(key: &[u8; 32]) -> Result<()> {
    let weight: u32 = key
        .chunks_exact(4)
        .map(|chunk| {
            ct_hamming_weight(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        })
        .sum();

    if !ct_in_range(weight, KEY_MIN_HAMMING_WEIGHT, KEY_MAX_HAMMING_WEIGHT) {
        return Err(CryptoError::key_exchange_failed(
            "derived key entropy outside accepted range",
        ));
    }
    Ok(())
}

#[inline]
fn fill_layer_nonce(out: &mut [u8; NONCE_SIZE]) -> Result<()> {
    let mut os_nonce = [0u8; NONCE_SIZE];
    fill_os_random_array(&mut os_nonce)?;

    let raw_counter = NONCE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let reduced = ct_mod_reduce(raw_counter as u32, 0x00FF_FFFFu32);
    let mut counter_frame = [0u8; NONCE_SIZE];
    counter_frame[NONCE_SIZE - 3] = (reduced >> 16) as u8;
    counter_frame[NONCE_SIZE - 2] = (reduced >> 8) as u8;
    counter_frame[NONCE_SIZE - 1] = reduced as u8;

    ct_xor(&os_nonce, &counter_frame, out);
    zeroize_array(&mut os_nonce);
    zeroize_array(&mut counter_frame);
    Ok(())
}

#[inline]
fn enforce_public_floor(start: Instant, floor_ns: u64) {
    loop {
        let elapsed = core::hint::black_box(start.elapsed().as_nanos() as u64);
        if elapsed >= floor_ns {
            return;
        }
        core::hint::spin_loop();
    }
}

#[inline]
fn required_onion_len(plaintext_len: usize, layers: usize) -> Result<usize> {
    let layer_bytes = layers
        .checked_mul(LAYER_OVERHEAD)
        .ok_or_else(|| CryptoError::internal("layer size overflow"))?;
    plaintext_len
        .checked_add(layer_bytes)
        .ok_or_else(|| CryptoError::internal("packet size overflow"))
}

#[inline]
fn wrap_layer_in_place(
    buf: &mut [u8],
    cur_offset: usize,
    cur_len: usize,
    kem_pk: &[u8],
    dsa_sk: &[u8],
) -> Result<()> {
    if cur_offset < LAYER_OVERHEAD {
        return Err(CryptoError::internal("invalid layer offset"));
    }

    let new_offset = cur_offset - LAYER_OVERHEAD;
    let nonce_start = new_offset + KEM_CT_SIZE;
    let ct_start = nonce_start + NONCE_SIZE;
    let ct_end = ct_start + cur_len;
    let signed_end = ct_end + TAG_SIZE;
    let sig_end = signed_end + DSA_SIG_SIZE;

    if sig_end > buf.len() {
        return Err(CryptoError::invalid_packet("output buffer too small"));
    }

    let mut kem_ct = [0u8; KEM_CT_SIZE];
    let mut aes_key = [0u8; 32];
    let mut sig = [0u8; DSA_SIG_SIZE];

    let result = (|| {
        buf.copy_within(cur_offset..cur_offset + cur_len, ct_start);

        pqc::kem_encapsulate_into(kem_pk, &mut kem_ct, &mut aes_key)?;
        validate_key_entropy(&aes_key)?;
        buf[new_offset..new_offset + KEM_CT_SIZE].copy_from_slice(&kem_ct);

        let mut nonce_arr = [0u8; NONCE_SIZE];
        fill_layer_nonce(&mut nonce_arr)?;
        ct_copy_if(
            true,
            &nonce_arr,
            &mut buf[nonce_start..nonce_start + NONCE_SIZE],
        );

        let cipher = Aes256Gcm::new(Key256::from_mut_bytes(&mut aes_key));
        let tag = cipher
            .seal_in_place(&Nonce(nonce_arr), b"", &mut buf[ct_start..ct_end])
            .map_err(|_| CryptoError::encryption_failed("AES-GCM encrypt_in_place failed"))?;
        buf[ct_end..signed_end].copy_from_slice(&tag);

        pqc::dsa_sign_into(dsa_sk, &buf[new_offset..signed_end], &mut sig)?;
        buf[signed_end..sig_end].copy_from_slice(&sig);
        Ok(())
    })();

    zeroize_array(&mut kem_ct);
    zeroize_array(&mut aes_key);
    zeroize_array(&mut sig);
    result
}

fn onion_internal_into(
    plaintext: &[u8],
    kem_pks: &[&[u8]],
    dsa_sks: &[&[u8]],
    out: &mut [u8],
) -> Result<usize> {
    if kem_pks.is_empty() {
        return Err(CryptoError::internal("at least one layer is required"));
    }
    if kem_pks.len() != dsa_sks.len() {
        return Err(CryptoError::internal("kem_pks and dsa_sks length mismatch"));
    }

    let layer_bytes = kem_pks
        .len()
        .checked_mul(LAYER_OVERHEAD)
        .ok_or_else(|| CryptoError::internal("layer size overflow"))?;
    let total_len = required_onion_len(plaintext.len(), kem_pks.len())?;
    if out.len() < total_len {
        return Err(CryptoError::invalid_packet("output buffer too small"));
    }

    let out = &mut out[..total_len];
    let mut cur_offset = layer_bytes;
    let mut cur_len = plaintext.len();
    out[cur_offset..cur_offset + cur_len].copy_from_slice(plaintext);

    for i in (0..kem_pks.len()).rev() {
        wrap_layer_in_place(out, cur_offset, cur_len, kem_pks[i], dsa_sks[i])?;
        cur_offset -= LAYER_OVERHEAD;
        cur_len += LAYER_OVERHEAD;
    }

    Ok(total_len)
}

/// AES-256-GCM encrypt with caller-supplied key/nonce/AAD.
pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
    tag_out: &mut [u8; 16],
) -> std::result::Result<usize, &'static str> {
    let start = Instant::now();

    let mut key_buf = [0u8; 32];
    ct_copy_if(true, key, &mut key_buf);

    let out_ok = ciphertext_out.len() >= plaintext.len();
    let result = if out_ok {
        let out = &mut ciphertext_out[..plaintext.len()];
        out.copy_from_slice(plaintext);

        let gcm = Aes256Gcm::new(Key256::from_mut_bytes(&mut key_buf));
        gcm.seal_in_place(&Nonce(*nonce), aad, out)
            .map(|tag| {
                tag_out.copy_from_slice(&tag);
                plaintext.len()
            })
            .map_err(|_| "encryption failed")
    } else {
        tag_out.fill(0);
        Err("ciphertext output buffer too small")
    };

    zeroize_array(&mut key_buf);
    enforce_public_floor(start, FLOOR_PUBLIC_ENCRYPT_NS);
    result
}

/// ML-KEM-1024 encapsulation.
pub fn encapsulate(
    pk: &[u8],
    ct_out: &mut [u8; 1568],
    ss_out: &mut [u8; 32],
) -> std::result::Result<(), &'static str> {
    let start = Instant::now();

    let len_ok = pk.len() == KEM_PK_SIZE;
    let mut pk_buf = [0u8; KEM_PK_SIZE];
    ct_copy_if(len_ok, pk, &mut pk_buf);

    let op = pqc::kem_encapsulate_into(&pk_buf, ct_out, ss_out).map_err(|_| "encapsulation failed");
    let result = if len_ok {
        op
    } else {
        ct_out.fill(0);
        zeroize_array(ss_out);
        Err("encapsulation failed")
    };

    zeroize_array(&mut pk_buf);
    enforce_public_floor(start, FLOOR_PUBLIC_ENCAPSULATE_NS);
    result
}

/// ML-DSA-87 detached signature.
pub fn sign(
    sk: &[u8],
    msg: &[u8],
    sig_out: &mut [u8; 4627],
) -> std::result::Result<(), &'static str> {
    let start = Instant::now();

    let len_ok = sk.len() == pqc::DSA_SK_SIZE;
    let mut sk_buf = [0u8; pqc::DSA_SK_SIZE];
    ct_copy_if(len_ok, sk, &mut sk_buf);

    let op = pqc::dsa_sign_into(&sk_buf, msg, sig_out).map_err(|_| "sign failed");
    let result = if len_ok {
        op
    } else {
        zeroize_array(sig_out);
        Err("sign failed")
    };

    zeroize_array(&mut sk_buf);
    enforce_public_floor(start, FLOOR_PUBLIC_SIGN_NS);
    result
}

/// SHA-512 digest.
pub fn hash(data: &[u8]) -> [u8; 64] {
    let start = Instant::now();
    let digest = crate::algos::sha512::hash(data);
    enforce_public_floor(start, FLOOR_PUBLIC_HASH_NS);
    digest
}

/// Constant-time byte-slice equality comparison.
pub fn compare(a: &[u8], b: &[u8]) -> bool {
    let start = Instant::now();
    let eq = ct_eq(a, b);
    enforce_public_floor(start, FLOOR_PUBLIC_COMPARE_NS);
    eq
}

/// Apply exactly 3 hybrid layers (ML-KEM + AES-GCM + ML-DSA).
pub fn layer_encrypt(
    plaintext: &[u8],
    kem_pks: [&[u8]; 3],
    dsa_sks: [&[u8]; 3],
    out: &mut [u8],
) -> std::result::Result<usize, &'static str> {
    let start = Instant::now();
    let result = onion_internal_into(plaintext, &kem_pks, &dsa_sks, out)
        .map_err(|_| "layer encryption failed");
    enforce_public_floor(start, FLOOR_PUBLIC_LAYER_NS);
    result
}

/// Apply N hybrid onion layers (N is user-defined).
pub fn onion(
    plaintext: &[u8],
    kem_pks: &[&[u8]],
    dsa_sks: &[&[u8]],
    out: &mut [u8],
) -> std::result::Result<usize, &'static str> {
    let start = Instant::now();
    let result = onion_internal_into(plaintext, kem_pks, dsa_sks, out)
        .map_err(|_| "onion encryption failed");
    enforce_public_floor(start, FLOOR_PUBLIC_ONION_NS);
    result
}
