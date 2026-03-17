//! Post-quantum primitive wrappers — internal only.
//!
//! All functions zeroize intermediate key material before returning.
//! Rate limiting lives at the call site (per-layer context).
//!
//! [`TimingGuard::enforce`] is called after each PQC primitive completes,
//! ensuring the timing floor is checked on every code path (success *and*
//! failure) and keeping `TimingGuard`, `TIMING_VIOLATIONS`, and
//! `record_timing_viol` in the live call graph.

use crate::algos::mldsa87;
use crate::algos::mlkem1024;
use crate::algos::mlkem1024::hash::sha3_512_x2;
use crate::audit::METRICS;
use crate::constant_time::{TimingGuard, ct_zeroize_verify};
use crate::error::{CryptoError, Result};
use crate::os_random::fill_os_random_array;
use crate::zeroize::zeroize_array;
use std::time::Instant;

// ── Size constants (re-exported for packet layout arithmetic) ─────────────────

pub(crate) const KEM_PK_SIZE: usize = mlkem1024::EK_BYTES; // 1568
pub(crate) const KEM_SK_SIZE: usize = mlkem1024::DK_BYTES; // 3168
pub(crate) const KEM_CT_SIZE: usize = mlkem1024::CT_BYTES; // 1568
pub(crate) const DSA_PK_SIZE: usize = mldsa87::PK_BYTES; // 2592
pub(crate) const DSA_SK_SIZE: usize = mldsa87::SK_BYTES; // 4896
pub(crate) const DSA_SIG_SIZE: usize = mldsa87::SIG_BYTES; // 4627
pub(crate) const AES_KEY_SIZE: usize = 32;

/// Conservative timing floors (ns) for PQC operations.
const FLOOR_KEM_KEYGEN_NS: u64 = 2_000_000;
const FLOOR_ENCAP_NS: u64 = 1_500_000;
const FLOOR_DECAP_NS: u64 = 700_000;
const FLOOR_DSA_KEYGEN_NS: u64 = 15_000_000;
const FLOOR_SIGN_NS: u64 = 12_000_000;
const FLOOR_VERIFY_NS: u64 = 2_000_000;

#[inline]
fn fill_entropy<const N: usize>(buf: &mut [u8; N]) -> Result<()> {
    fill_os_random_array(buf).inspect_err(|e| {
        METRICS.record_fail();
        METRICS.record_error_ctx(e);
    })
}

#[inline]
fn enforce_floor_only(start: Instant, floor_ns: u64) {
    loop {
        let elapsed = core::hint::black_box(start.elapsed().as_nanos() as u64);
        if elapsed >= floor_ns {
            return;
        }
        core::hint::spin_loop();
    }
}

// ── Key derivation ────────────────────────────────────────────────────────────

/// Derive a 32-byte AES key from a KEM shared secret via SHA3-512
/// with domain separation.
#[inline]
pub(crate) fn derive_aes_key_into(raw_ss: &[u8], key_out: &mut [u8; AES_KEY_SIZE]) {
    let mut digest = [0u8; 64];
    sha3_512_x2(b"bastion-aes-key-v1\x00", raw_ss, &mut digest);
    key_out.copy_from_slice(&digest[..AES_KEY_SIZE]);
    zeroize_array(&mut digest);
}

// ── ML-KEM-1024 ───────────────────────────────────────────────────────────────

/// Generate an ML-KEM-1024 key pair with OS-backed entropy.
pub(crate) fn kem_keygen_into(
    pk_out: &mut [u8; KEM_PK_SIZE],
    sk_out: &mut [u8; KEM_SK_SIZE],
) -> Result<()> {
    let mut seed = [0u8; mlkem1024::KEYGEN_SEED_BYTES];
    fill_entropy(&mut seed)?;

    let mut ek = mlkem1024::EncapKey([0u8; mlkem1024::EK_BYTES]);
    let mut dk = mlkem1024::DecapKey([0u8; mlkem1024::DK_BYTES]);

    let start = Instant::now();
    mlkem1024::keygen(&seed, &mut ek, &mut dk);
    enforce_floor_only(start, FLOOR_KEM_KEYGEN_NS);
    let seed_res = ct_zeroize_verify(&mut seed).inspect_err(|e| METRICS.record_error_ctx(e));
    if let Err(e) = seed_res {
        zeroize_array(pk_out);
        zeroize_array(sk_out);
        zeroize_array(&mut ek.0);
        let _ = ct_zeroize_verify(&mut dk.0).inspect_err(|err| METRICS.record_error_ctx(err));
        return Err(e);
    }

    pk_out.copy_from_slice(ek.as_bytes());
    sk_out.copy_from_slice(dk.as_bytes());

    zeroize_array(&mut ek.0);
    ct_zeroize_verify(&mut dk.0).inspect_err(|e| METRICS.record_error_ctx(e))?;

    METRICS.record_ok();
    Ok(())
}

/// Encapsulate to `pk`, returning `(kem_ct_bytes, aes_key)`.
///
/// The raw shared secret is zeroized and verified before returning.
/// The caller is responsible for zeroizing `aes_key` after use.
///
/// The timing guard is enforced *after* the PQC primitive completes and
/// *before* the result is propagated — covering both success and failure paths.
pub(crate) fn kem_encapsulate_into(
    pk: &[u8],
    ct_out: &mut [u8; KEM_CT_SIZE],
    aes_key_out: &mut [u8; AES_KEY_SIZE],
) -> Result<()> {
    if pk.len() != KEM_PK_SIZE {
        return Err(CryptoError::invalid_public_key(
            "invalid KEM public key length",
        ));
    }

    let mut ek = mlkem1024::EncapKey([0u8; mlkem1024::EK_BYTES]);
    ek.0.copy_from_slice(pk);

    let mut entropy = [0u8; 32];
    fill_entropy(&mut entropy)?;

    let guard = TimingGuard::new("ml_kem_encap", FLOOR_ENCAP_NS);
    let mut ct = mlkem1024::Ciphertext([0u8; mlkem1024::CT_BYTES]);
    let mut ss = mlkem1024::SharedSecret([0u8; mlkem1024::SS_BYTES]);
    mlkem1024::encaps(&ek, &entropy, &mut ct, &mut ss);
    guard
        .enforce()
        .inspect_err(|e| METRICS.record_error_ctx(e))?;

    let mut raw_ss = *ss.as_bytes();
    derive_aes_key_into(&raw_ss, aes_key_out);
    ct_zeroize_verify(&mut raw_ss).inspect_err(|e| METRICS.record_error_ctx(e))?;

    ct_out.copy_from_slice(ct.as_bytes());
    zeroize_array(&mut ct.0);
    ct_zeroize_verify(&mut entropy).inspect_err(|e| METRICS.record_error_ctx(e))?;
    METRICS.record_ok();
    Ok(())
}

/// Decapsulate `kem_ct` with `sk`, returning the derived `aes_key`.
///
/// The raw shared secret is zeroized internally. The caller must zeroize
/// `aes_key` after use.
pub(crate) fn kem_decapsulate_into(
    kem_ct: &[u8],
    sk: &[u8],
    aes_key_out: &mut [u8; AES_KEY_SIZE],
) -> Result<()> {
    if kem_ct.len() != KEM_CT_SIZE {
        return Err(CryptoError::invalid_packet("invalid KEM ciphertext length"));
    }
    if sk.len() != KEM_SK_SIZE {
        return Err(CryptoError::internal("invalid KEM secret key length"));
    }

    let mut ct_t = mlkem1024::Ciphertext([0u8; mlkem1024::CT_BYTES]);
    ct_t.0.copy_from_slice(kem_ct);
    let mut dk_t = mlkem1024::DecapKey([0u8; mlkem1024::DK_BYTES]);
    dk_t.0.copy_from_slice(sk);

    let guard = TimingGuard::new("ml_kem_decap", FLOOR_DECAP_NS);
    let mut ss = mlkem1024::SharedSecret([0u8; mlkem1024::SS_BYTES]);
    mlkem1024::decaps(&dk_t, &ct_t, &mut ss);
    guard
        .enforce()
        .inspect_err(|e| METRICS.record_error_ctx(e))?;

    let mut raw_ss = *ss.as_bytes();
    derive_aes_key_into(&raw_ss, aes_key_out);
    ct_zeroize_verify(&mut raw_ss).inspect_err(|e| METRICS.record_error_ctx(e))?;
    zeroize_array(&mut ct_t.0);
    ct_zeroize_verify(&mut dk_t.0).inspect_err(|e| METRICS.record_error_ctx(e))?;

    METRICS.record_ok();
    Ok(())
}

// ── ML-DSA-87 ─────────────────────────────────────────────────────────────────

/// Generate an ML-DSA-87 key pair with OS-backed entropy.
pub(crate) fn dsa_keygen_into(
    pk_out: &mut [u8; DSA_PK_SIZE],
    sk_out: &mut [u8; DSA_SK_SIZE],
) -> Result<()> {
    let mut seed = [0u8; 32];
    fill_entropy(&mut seed)?;

    let mut pk = [0u8; mldsa87::PK_BYTES];
    let mut sk = [0u8; mldsa87::SK_BYTES];

    let start = Instant::now();
    mldsa87::keypair(&mut pk, &mut sk, &seed);
    enforce_floor_only(start, FLOOR_DSA_KEYGEN_NS);
    let seed_res = ct_zeroize_verify(&mut seed).inspect_err(|e| METRICS.record_error_ctx(e));
    if let Err(e) = seed_res {
        zeroize_array(pk_out);
        zeroize_array(sk_out);
        zeroize_array(&mut pk);
        let _ = ct_zeroize_verify(&mut sk).inspect_err(|err| METRICS.record_error_ctx(err));
        return Err(e);
    }

    pk_out.copy_from_slice(&pk);
    sk_out.copy_from_slice(&sk);

    zeroize_array(&mut pk);
    ct_zeroize_verify(&mut sk).inspect_err(|e| METRICS.record_error_ctx(e))?;

    METRICS.record_ok();
    Ok(())
}

/// Sign `msg` with ML-DSA-87 secret key bytes. Returns detached signature bytes.
pub(crate) fn dsa_sign_into(sk: &[u8], msg: &[u8], sig_out: &mut [u8; DSA_SIG_SIZE]) -> Result<()> {
    if sk.len() != DSA_SK_SIZE {
        return Err(CryptoError::internal("invalid DSA secret key length"));
    }

    let sk_arr: &[u8; mldsa87::SK_BYTES] = sk
        .try_into()
        .map_err(|_| CryptoError::internal("invalid ML-DSA secret key length"))?;

    let mut rnd = [0u8; 32];
    fill_entropy(&mut rnd)?;

    let guard = TimingGuard::new("ml_dsa_sign", FLOOR_SIGN_NS);
    mldsa87::sign(sig_out, msg, sk_arr, &rnd);
    guard
        .enforce()
        .inspect_err(|e| METRICS.record_error_ctx(e))?;
    ct_zeroize_verify(&mut rnd).inspect_err(|e| METRICS.record_error_ctx(e))?;

    METRICS.record_ok();
    Ok(())
}

/// Verify detached `sig` over `msg` with ML-DSA-87 public key bytes.
pub(crate) fn dsa_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    if pk.len() != DSA_PK_SIZE {
        return Err(CryptoError::invalid_public_key(
            "invalid DSA public key length",
        ));
    }
    if sig.len() != DSA_SIG_SIZE {
        return Err(CryptoError::signature_failed(
            "invalid DSA signature length",
        ));
    }

    let pk_arr: &[u8; mldsa87::PK_BYTES] = pk
        .try_into()
        .map_err(|_| CryptoError::invalid_public_key("invalid ML-DSA public key length"))?;
    let sig_arr: &[u8; mldsa87::SIG_BYTES] = sig
        .try_into()
        .map_err(|_| CryptoError::signature_failed("invalid ML-DSA signature length"))?;

    let guard = TimingGuard::new("ml_dsa_verify", FLOOR_VERIFY_NS);
    let valid = mldsa87::verify(sig_arr, msg, pk_arr);
    guard
        .enforce()
        .inspect_err(|e| METRICS.record_error_ctx(e))?;

    if !valid {
        METRICS.record_tampering();
        METRICS.record_fail();
        return Err(CryptoError::signature_failed("ML-DSA verification failed"));
    }

    METRICS.record_ok();
    Ok(())
}
