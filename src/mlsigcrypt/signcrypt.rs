/// MLSigcrypt-v1 signcrypt and unsigncrypt algorithms.
///
/// ## Signcrypt
///
///   1.  Validate recipient public object.
///   2.  KEM encapsulation → (kem_ct, κ).
///   3.  KDF(κ, "K_aead") → K_aead;  KDF(κ, "K_nonce") → K_nonce.
///   4.  SHA3-512("aad" ∥ aad) → aad_digest.
///   5.  DeriveNonce(K_nonce, ...) → nonce  (NOT transmitted).
///   6.  AES-256-GCM.Enc(K_aead, nonce, aad, m) → (ct, tag).
///   7.  SHA3-512(transcript_fields...) → T.
///   8.  ML-DSA-87.Sign(sk_sig_S, T) → sig.
///   9.  Encode packet; zeroize all sensitive intermediates.
///
/// ## Unsigncrypt
///
///   1.  Parse packet (constant-shape).
///   2.  Verify header consistency (alg_id, version, key_id_S, key_id_R).
///   3.  Compute aad_digest.
///   4.  Build transcript T.
///   5.  ML-DSA-87.Verify(pk_sig_S, T, sig)   ← BEFORE decapsulation.
///   6.  ML-KEM-1024.Decaps(sk_enc_R, kem_ct) → κ.
///   7.  KDF(κ, "K_aead") → K_aead;  KDF(κ, "K_nonce") → K_nonce.
///   8.  RecomputeNonce(K_nonce, ...) → nonce.
///   9.  AES-256-GCM.Dec(K_aead, nonce, aad, ct, tag) → m.
///   10. Zeroize all sensitive intermediates.
///
/// All externally observable failures collapse to `SigncryptOpenFailed`.
use super::keys::{UserPublicKey, UserSecretKey};
use super::params::*;
use crate::constant_time::ct_eq;
use crate::mlsigcrypt::specs::aes256gcm::aes::Key256;
use crate::mlsigcrypt::specs::aes256gcm::{Aes256Gcm, Nonce};
use crate::mlsigcrypt::specs::hkdf::kdf;
use crate::mlsigcrypt::specs::mldsa87;
use crate::mlsigcrypt::specs::mlkem1024::{self, Ciphertext, DecapKey, EncapKey, SharedSecret};
use crate::mlsigcrypt::specs::sha3_512::hash as sha3_512;
use crate::os_random::fill_os_random_array;
use crate::zeroize::zeroize_mem;
use core::sync::atomic::{Ordering, compiler_fence};

// ── Error type ────────────────────────────────────────────────────────────────

/// Opaque failure result from `unsigncrypt`.
///
/// All failure causes — parse error, version mismatch, key-id mismatch,
/// signature failure, decapsulation failure, AEAD tag failure — collapse into
/// this single type. No external caller can determine which check failed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SigncryptOpenFailed;

impl core::fmt::Display for SigncryptOpenFailed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "signcrypt open failed")
    }
}

// ── RAII secret buffer ────────────────────────────────────────────────────────

/// A fixed-size byte array that is zeroized automatically on `Drop`.
///
/// Used for transient sensitive material (session keys, entropy, etc.) so that
/// early returns and `?` operators do not skip zeroization.
struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    fn new() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid writable array of N bytes.
        unsafe { zeroize_mem(self.0.as_mut_ptr(), N) };
        compiler_fence(Ordering::SeqCst);
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Compute the canonical transcript hash T.
///
/// Absorbs all packet fields and public key material into SHA3-512.
/// The `ct` field is length-prefixed with `u64be(ct.len())` per §12.2.
fn compute_transcript(
    key_id_s: &[u8; KEY_ID_LEN],
    key_id_r: &[u8; KEY_ID_LEN],
    pk_enc_s: &[u8],
    pk_sig_s: &[u8],
    pk_enc_r: &[u8],
    pk_sig_r: &[u8],
    kem_ct: &[u8],
    aad_digest: &[u8; AAD_DIGEST_LEN],
    ct: &[u8],
    tag: &[u8; TAG_LEN],
    out: &mut [u8; TRANSCRIPT_LEN],
) {
    let version_byte = [VERSION];
    let ct_len_be = (ct.len() as u64).to_be_bytes();
    sha3_512(
        &[
            b"MLSigcrypt-v1/transcript",
            ALG_ID,
            &version_byte,
            key_id_s,
            key_id_r,
            pk_enc_s,
            pk_sig_s,
            pk_enc_r,
            pk_sig_r,
            kem_ct,
            aad_digest,
            &ct_len_be,
            ct,
            tag,
        ],
        out,
    );
}

/// Derive the AEAD nonce deterministically from session context.
///
/// The nonce is NOT transmitted. Both sender and receiver derive it from κ
/// (via K_nonce), key identifiers, kem_ct, and aad_digest. Fresh encapsulation
/// → fresh κ → fresh K_nonce → fresh nonce, preventing reuse under K_aead.
fn derive_nonce(
    k_nonce: &[u8; K_NONCE_LEN],
    key_id_s: &[u8; KEY_ID_LEN],
    key_id_r: &[u8; KEY_ID_LEN],
    kem_ct: &[u8],
    aad_digest: &[u8; AAD_DIGEST_LEN],
    nonce_out: &mut [u8; NONCE_LEN],
) {
    let mut full = [0u8; SHA3_512_OUT];
    sha3_512(
        &[
            b"MLSigcrypt-v1/nonce",
            k_nonce,
            key_id_s,
            key_id_r,
            kem_ct,
            aad_digest,
        ],
        &mut full,
    );
    nonce_out.copy_from_slice(&full[..NONCE_LEN]);
    unsafe { zeroize_mem(full.as_mut_ptr(), SHA3_512_OUT) };
}

// ── Signcrypt ─────────────────────────────────────────────────────────────────

/// Signcrypt `plaintext` from sender S to recipient R.
///
/// # Arguments
///
/// - `sk_user_s` — sender's unified secret key (uses `sk_sig` only)
/// - `pk_user_s` — sender's public identity object
/// - `pk_user_r` — recipient's public identity object (authenticated by caller)
/// - `aad`       — associated data (may be empty; authenticated but not encrypted)
/// - `plaintext` — message to encrypt and authenticate
/// - `out`       — output buffer; must be `>= plaintext.len() + PACKET_FIXED_OVERHEAD`
///
/// # Returns
///
/// Number of bytes written to `out` on success, or `SigncryptOpenFailed`
/// if a precondition is violated (buffer too small, key inconsistency, etc.).
///
/// # Security
///
/// All sensitive intermediates are zeroized on both success and failure paths
/// via RAII `Secret<N>` wrappers and explicit cleanup.
pub(crate) fn signcrypt(
    sk_user_s: &UserSecretKey,
    pk_user_s: &UserPublicKey,
    pk_user_r: &UserPublicKey,
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, SigncryptOpenFailed> {
    let pt_len = plaintext.len();
    let packet_len = pt_len
        .checked_add(PACKET_FIXED_OVERHEAD)
        .ok_or(SigncryptOpenFailed)?;

    if out.len() < packet_len {
        return Err(SigncryptOpenFailed);
    }

    // ── Validate caller-supplied identities ──────────────────────────────────
    if !pk_user_s.verify_consistency() || !pk_user_r.verify_consistency() {
        return Err(SigncryptOpenFailed);
    }

    // ── Step 1: Write fixed packet header fields ──────────────────────────────
    // Written first so kem_ct is in the output buffer for transcript building.
    out[PKT_ALG_ID_OFF..PKT_VERSION_OFF].copy_from_slice(ALG_ID);
    out[PKT_VERSION_OFF] = VERSION;
    out[PKT_KEY_ID_S_OFF..PKT_KEY_ID_S_OFF + KEY_ID_LEN].copy_from_slice(&pk_user_s.key_id);
    out[PKT_KEY_ID_R_OFF..PKT_KEY_ID_R_OFF + KEY_ID_LEN].copy_from_slice(&pk_user_r.key_id);

    // ── Step 2: KEM encapsulation ─────────────────────────────────────────────
    let mut entropy = Secret::<32>::new();
    fill_os_random_array(&mut entropy.0).map_err(|_| SigncryptOpenFailed)?;

    let mut ek = EncapKey([0u8; KEM_EK_LEN]);
    ek.0.copy_from_slice(&pk_user_r.pk_enc);

    let mut kem_ct = Ciphertext([0u8; mlkem1024::CT_BYTES]);
    let mut ss = SharedSecret([0u8; mlkem1024::SS_BYTES]);
    mlkem1024::encaps(&ek, &entropy.0, &mut kem_ct, &mut ss);
    // entropy: auto-zeroized by Secret::drop when this scope ends.

    // Copy kem_ct into the packet before ss and entropy drop.
    out[PKT_KEM_CT_OFF..PKT_KEM_CT_OFF + KEM_CT_LEN].copy_from_slice(&kem_ct.0);

    // Extract κ before SharedSecret drops.
    let mut kappa = Secret::<{ KEM_SS_LEN }>::new();
    kappa.0.copy_from_slice(ss.as_bytes());
    // ss drops here → zeroized by SharedSecret::drop.

    // ── Step 3: Derive session keys from κ ───────────────────────────────────
    let mut k_aead = Secret::<{ K_AEAD_LEN }>::new();
    let mut k_nonce = Secret::<{ K_NONCE_LEN }>::new();
    kdf(&kappa.0, b"MLSigcrypt-v1/K_aead", &mut k_aead.0);
    kdf(&kappa.0, b"MLSigcrypt-v1/K_nonce", &mut k_nonce.0);
    // kappa is no longer needed.
    drop(kappa); // explicit zeroize via Secret::drop

    // ── Step 4: AAD digest ────────────────────────────────────────────────────
    let mut aad_digest = Secret::<{ AAD_DIGEST_LEN }>::new();
    sha3_512(&[b"MLSigcrypt-v1/aad", aad], &mut aad_digest.0);

    // ── Step 5: Derive deterministic nonce ───────────────────────────────────
    let mut nonce_arr = Secret::<{ NONCE_LEN }>::new();
    derive_nonce(
        &k_nonce.0,
        &pk_user_s.key_id,
        &pk_user_r.key_id,
        &out[PKT_KEM_CT_OFF..PKT_KEM_CT_OFF + KEM_CT_LEN],
        &aad_digest.0,
        &mut nonce_arr.0,
    );
    drop(k_nonce); // no longer needed

    // ── Step 6: Write ct_len, copy plaintext, encrypt in-place ───────────────
    let ct_len_be = (pt_len as u64).to_be_bytes();
    out[PKT_CT_LEN_OFF..PKT_CT_OFF].copy_from_slice(&ct_len_be);
    out[PKT_CT_OFF..PKT_CT_OFF + pt_len].copy_from_slice(plaintext);

    let tag = {
        // from_mut_bytes copies k_aead.0 into Key256 and wipes k_aead.0.
        // k_aead.0 is now zero, but Secret::drop will re-zeroize harmlessly.
        let cipher = Aes256Gcm::new(Key256::from_mut_bytes(&mut k_aead.0));
        cipher
            .seal_in_place(
                &Nonce(nonce_arr.0),
                aad,
                &mut out[PKT_CT_OFF..PKT_CT_OFF + pt_len],
            )
            .map_err(|_| SigncryptOpenFailed)?
        // cipher drops here → KeySchedule zeroized by KeySchedule::drop.
    };

    let tag_off = PKT_CT_OFF + pt_len;
    out[tag_off..tag_off + TAG_LEN].copy_from_slice(&tag);

    // ── Step 7: Build transcript T ────────────────────────────────────────────
    let mut transcript = Secret::<{ TRANSCRIPT_LEN }>::new();
    {
        let tag_ref: &[u8; TAG_LEN] = out[tag_off..tag_off + TAG_LEN]
            .try_into()
            .map_err(|_| SigncryptOpenFailed)?;
        compute_transcript(
            &pk_user_s.key_id,
            &pk_user_r.key_id,
            &pk_user_s.pk_enc,
            &pk_user_s.pk_sig,
            &pk_user_r.pk_enc,
            &pk_user_r.pk_sig,
            &out[PKT_KEM_CT_OFF..PKT_KEM_CT_OFF + KEM_CT_LEN],
            &aad_digest.0,
            &out[PKT_CT_OFF..PKT_CT_OFF + pt_len],
            tag_ref,
            &mut transcript.0,
        );
    }
    drop(aad_digest); // no longer needed

    // ── Step 8: Sign transcript ───────────────────────────────────────────────
    let mut rnd = Secret::<32>::new();
    fill_os_random_array(&mut rnd.0).map_err(|_| SigncryptOpenFailed)?;

    let mut sig = [0u8; SIG_LEN];
    mldsa87::sign(&mut sig, &transcript.0, &sk_user_s.sk_sig, &rnd.0);
    drop(rnd);
    drop(transcript);

    // ── Step 9: Write signature and finish ────────────────────────────────────
    let sig_off = tag_off + TAG_LEN;
    out[sig_off..sig_off + SIG_LEN].copy_from_slice(&sig);

    // Zeroize local sig copy; kem_ct.0 is public but wipe for hygiene.
    unsafe {
        zeroize_mem(sig.as_mut_ptr(), SIG_LEN);
        zeroize_mem(kem_ct.0.as_mut_ptr(), KEM_CT_LEN);
    }

    Ok(packet_len)
}

// ── Unsigncrypt ───────────────────────────────────────────────────────────────

/// Unsigncrypt a packet from sender S to recipient R.
///
/// # Arguments
///
/// - `sk_user_r`  — recipient's unified secret key (uses `sk_enc` only)
/// - `pk_user_s`  — sender's public identity object (authenticated by caller)
/// - `pk_user_r`  — recipient's public identity object
/// - `aad`        — associated data (must match what was passed to `signcrypt`)
/// - `packet`     — the packet bytes produced by `signcrypt`
/// - `out`        — output buffer; must be `>= packet.len() - PACKET_FIXED_OVERHEAD`
///
/// # Returns
///
/// Length of the recovered plaintext in `out` on success, or
/// `SigncryptOpenFailed` on any failure. No information about which check
/// failed is exposed externally.
///
/// # Ordering
///
/// Signature verification runs **before** decapsulation. This:
/// 1. Prevents use of the decapsulator as a chosen-ciphertext oracle.
/// 2. Rejects unauthenticated packets before expensive KEM work.
/// 3. Prevents secret-dependent computation on unauthenticated input.
pub(crate) fn unsigncrypt(
    sk_user_r: &UserSecretKey,
    pk_user_s: &UserPublicKey,
    pk_user_r: &UserPublicKey,
    aad: &[u8],
    packet: &[u8],
    out: &mut [u8],
) -> Result<usize, SigncryptOpenFailed> {
    // Wrap inner logic so we can guarantee output buffer zeroization on failure.
    let result = unsigncrypt_inner(sk_user_r, pk_user_s, pk_user_r, aad, packet, out);
    if result.is_err() {
        // Zero out any partial plaintext that may have been written.
        // Constant-size: zero the portion that could have been touched.
        if packet.len() > PACKET_FIXED_OVERHEAD {
            let ct_len = packet.len() - PACKET_FIXED_OVERHEAD;
            if out.len() >= ct_len {
                unsafe { zeroize_mem(out.as_mut_ptr(), ct_len) };
            } else {
                unsafe { zeroize_mem(out.as_mut_ptr(), out.len()) };
            }
        }
    }
    result
}

fn unsigncrypt_inner(
    sk_user_r: &UserSecretKey,
    pk_user_s: &UserPublicKey,
    pk_user_r: &UserPublicKey,
    aad: &[u8],
    packet: &[u8],
    out: &mut [u8],
) -> Result<usize, SigncryptOpenFailed> {
    // ── Step 1: Structural size validation ───────────────────────────────────
    if packet.len() < PACKET_FIXED_OVERHEAD {
        return Err(SigncryptOpenFailed);
    }

    // Parse ct_len from the fixed field (u64 big-endian).
    let ct_len = {
        let bytes: [u8; 8] = packet[PKT_CT_LEN_OFF..PKT_CT_OFF]
            .try_into()
            .map_err(|_| SigncryptOpenFailed)?;
        let n = u64::from_be_bytes(bytes) as usize;
        n
    };

    // The packet must be exactly PACKET_FIXED_OVERHEAD + ct_len bytes.
    if packet.len() != PACKET_FIXED_OVERHEAD + ct_len {
        return Err(SigncryptOpenFailed);
    }

    if out.len() < ct_len {
        return Err(SigncryptOpenFailed);
    }

    if !pk_user_s.verify_consistency() || !pk_user_r.verify_consistency() {
        return Err(SigncryptOpenFailed);
    }

    // ── Step 2: Header field validation ──────────────────────────────────────

    // alg_id — constant-time comparison (public, but consistent with policy)
    if !ct_eq(&packet[PKT_ALG_ID_OFF..PKT_VERSION_OFF], ALG_ID) {
        return Err(SigncryptOpenFailed);
    }

    // version
    if packet[PKT_VERSION_OFF] != VERSION {
        return Err(SigncryptOpenFailed);
    }

    // key_id_S: verify packet field matches pk_user_s
    {
        let mut expected = [0u8; SHA3_512_OUT];
        sha3_512(
            &[
                b"MLSigcrypt-v1/key_id",
                &pk_user_s.pk_enc,
                &pk_user_s.pk_sig,
            ],
            &mut expected,
        );
        if !ct_eq(
            &packet[PKT_KEY_ID_S_OFF..PKT_KEY_ID_S_OFF + KEY_ID_LEN],
            &expected[..KEY_ID_LEN],
        ) {
            return Err(SigncryptOpenFailed);
        }
    }

    // key_id_R: verify packet field matches pk_user_r
    {
        let mut expected = [0u8; SHA3_512_OUT];
        sha3_512(
            &[
                b"MLSigcrypt-v1/key_id",
                &pk_user_r.pk_enc,
                &pk_user_r.pk_sig,
            ],
            &mut expected,
        );
        if !ct_eq(
            &packet[PKT_KEY_ID_R_OFF..PKT_KEY_ID_R_OFF + KEY_ID_LEN],
            &expected[..KEY_ID_LEN],
        ) {
            return Err(SigncryptOpenFailed);
        }
    }

    // ── Slice references into the validated packet ────────────────────────────
    let kem_ct = &packet[PKT_KEM_CT_OFF..PKT_KEM_CT_OFF + KEM_CT_LEN];
    let ct = &packet[PKT_CT_OFF..PKT_CT_OFF + ct_len];
    let tag_off = PKT_CT_OFF + ct_len;
    let tag: &[u8; TAG_LEN] = packet[tag_off..tag_off + TAG_LEN]
        .try_into()
        .map_err(|_| SigncryptOpenFailed)?;
    let sig_off = tag_off + TAG_LEN;
    let sig: &[u8; SIG_LEN] = packet[sig_off..sig_off + SIG_LEN]
        .try_into()
        .map_err(|_| SigncryptOpenFailed)?;

    // ── Step 3: AAD digest ────────────────────────────────────────────────────
    let mut aad_digest = Secret::<{ AAD_DIGEST_LEN }>::new();
    sha3_512(&[b"MLSigcrypt-v1/aad", aad], &mut aad_digest.0);

    // ── Step 4: Build transcript T ────────────────────────────────────────────
    let mut transcript = Secret::<{ TRANSCRIPT_LEN }>::new();
    compute_transcript(
        packet[PKT_KEY_ID_S_OFF..PKT_KEY_ID_S_OFF + KEY_ID_LEN]
            .try_into()
            .map_err(|_| SigncryptOpenFailed)?,
        packet[PKT_KEY_ID_R_OFF..PKT_KEY_ID_R_OFF + KEY_ID_LEN]
            .try_into()
            .map_err(|_| SigncryptOpenFailed)?,
        &pk_user_s.pk_enc,
        &pk_user_s.pk_sig,
        &pk_user_r.pk_enc,
        &pk_user_r.pk_sig,
        kem_ct,
        &aad_digest.0,
        ct,
        tag,
        &mut transcript.0,
    );

    // ── Step 5: Verify signature (BEFORE decapsulation) ──────────────────────
    //
    // This ordering:
    //   (a) rejects unauthenticated packets before expensive KEM work,
    //   (b) prevents using the decapsulator as a CCA oracle.
    let sig_valid = mldsa87::verify(sig, &transcript.0, &pk_user_s.pk_sig);
    drop(transcript); // zeroize transcript immediately after use

    if !sig_valid {
        return Err(SigncryptOpenFailed);
    }

    // ── Step 6: KEM decapsulation ─────────────────────────────────────────────
    let mut dk = DecapKey([0u8; KEM_DK_LEN]);
    dk.0.copy_from_slice(&sk_user_r.sk_enc);

    let mut kem_ct_typed = Ciphertext([0u8; mlkem1024::CT_BYTES]);
    kem_ct_typed.0.copy_from_slice(kem_ct);

    let mut ss = SharedSecret([0u8; mlkem1024::SS_BYTES]);
    mlkem1024::decaps(&dk, &kem_ct_typed, &mut ss);
    // dk drops here → zeroized by DecapKey::drop.
    unsafe { zeroize_mem(kem_ct_typed.0.as_mut_ptr(), KEM_CT_LEN) };

    let mut kappa = Secret::<{ KEM_SS_LEN }>::new();
    kappa.0.copy_from_slice(ss.as_bytes());
    // ss drops here → zeroized by SharedSecret::drop.

    // ── Step 7: Derive session keys ───────────────────────────────────────────
    let mut k_aead = Secret::<{ K_AEAD_LEN }>::new();
    let mut k_nonce = Secret::<{ K_NONCE_LEN }>::new();
    kdf(&kappa.0, b"MLSigcrypt-v1/K_aead", &mut k_aead.0);
    kdf(&kappa.0, b"MLSigcrypt-v1/K_nonce", &mut k_nonce.0);
    drop(kappa);

    // ── Step 8: Recompute nonce deterministically ─────────────────────────────
    let mut nonce_arr = Secret::<{ NONCE_LEN }>::new();
    derive_nonce(
        &k_nonce.0,
        packet[PKT_KEY_ID_S_OFF..PKT_KEY_ID_S_OFF + KEY_ID_LEN]
            .try_into()
            .map_err(|_| SigncryptOpenFailed)?,
        packet[PKT_KEY_ID_R_OFF..PKT_KEY_ID_R_OFF + KEY_ID_LEN]
            .try_into()
            .map_err(|_| SigncryptOpenFailed)?,
        kem_ct,
        &aad_digest.0,
        &mut nonce_arr.0,
    );
    drop(k_nonce);
    drop(aad_digest);

    // ── Step 9: AEAD decrypt ──────────────────────────────────────────────────
    // Copy ciphertext to output buffer before decrypting in-place.
    out[..ct_len].copy_from_slice(ct);

    let cipher = Aes256Gcm::new(Key256::from_mut_bytes(&mut k_aead.0));
    cipher
        .open_in_place(&Nonce(nonce_arr.0), aad, &mut out[..ct_len], tag)
        .map_err(|_| SigncryptOpenFailed)?;
    // cipher drops here → KeySchedule zeroized.

    Ok(ct_len)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlsigcrypt::keys::keygen;

    fn make_keypair(seed: u8) -> (UserSecretKey, UserPublicKey) {
        keygen(&[seed; MASTER_SECRET_LEN])
    }

    // ── Packet-size arithmetic ────────────────────────────────────────────────

    #[test]
    fn packet_overhead_matches_constant() {
        // An empty plaintext signcrypt produces exactly PACKET_FIXED_OVERHEAD bytes.
        let (sk_s, pk_s) = make_keypair(0x01);
        let (_, pk_r) = make_keypair(0x02);
        let mut pkt = vec![0u8; PACKET_FIXED_OVERHEAD];
        let written = signcrypt(&sk_s, &pk_s, &pk_r, b"", b"", &mut pkt).unwrap();
        assert_eq!(written, PACKET_FIXED_OVERHEAD);
        assert_eq!(written, pkt.len());
    }

    #[test]
    fn packet_size_includes_plaintext() {
        let (sk_s, pk_s) = make_keypair(0x10);
        let (_, pk_r) = make_keypair(0x11);
        let msg = b"hello, world";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let written = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();
        assert_eq!(written, msg.len() + PACKET_FIXED_OVERHEAD);
    }

    // ── Round-trip ────────────────────────────────────────────────────────────

    #[test]
    fn roundtrip_short_message() {
        let (sk_s, pk_s) = make_keypair(0x20);
        let (sk_r, pk_r) = make_keypair(0x21);
        let msg = b"secure message";
        let aad = b"metadata";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, aad, msg, &mut pkt).unwrap();

        let mut recovered = vec![0u8; msg.len()];
        let recovered_len =
            unsigncrypt(&sk_r, &pk_s, &pk_r, aad, &pkt[..pkt_len], &mut recovered).unwrap();

        assert_eq!(recovered_len, msg.len());
        assert_eq!(&recovered[..recovered_len], msg);
    }

    #[test]
    fn roundtrip_empty_message_empty_aad() {
        let (sk_s, pk_s) = make_keypair(0x30);
        let (sk_r, pk_r) = make_keypair(0x31);
        let mut pkt = vec![0u8; PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", b"", &mut pkt).unwrap();
        let mut recovered = vec![];
        let n = unsigncrypt(&sk_r, &pk_s, &pk_r, b"", &pkt[..pkt_len], &mut recovered).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn roundtrip_large_message() {
        let (sk_s, pk_s) = make_keypair(0x40);
        let (sk_r, pk_r) = make_keypair(0x41);
        let msg = vec![0xBBu8; 4096];
        let aad = b"large";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, aad, &msg, &mut pkt).unwrap();
        let mut recovered = vec![0u8; msg.len()];
        let n = unsigncrypt(&sk_r, &pk_s, &pk_r, aad, &pkt[..pkt_len], &mut recovered).unwrap();
        assert_eq!(&recovered[..n], msg.as_slice());
    }

    // ── Tamper resistance ─────────────────────────────────────────────────────

    #[test]
    fn tampered_ciphertext_rejected() {
        let (sk_s, pk_s) = make_keypair(0x50);
        let (sk_r, pk_r) = make_keypair(0x51);
        let msg = b"tamper test";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();

        pkt[PKT_CT_OFF] ^= 0xFF; // flip a byte in the ciphertext

        let mut out = vec![0u8; msg.len()];
        assert_eq!(
            unsigncrypt(&sk_r, &pk_s, &pk_r, b"", &pkt[..pkt_len], &mut out),
            Err(SigncryptOpenFailed)
        );
    }

    #[test]
    fn tampered_signature_rejected() {
        let (sk_s, pk_s) = make_keypair(0x60);
        let (sk_r, pk_r) = make_keypair(0x61);
        let msg = b"sig tamper";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();

        // Flip a byte deep in the signature.
        let sig_start = PKT_CT_OFF + msg.len() + TAG_LEN;
        pkt[sig_start + 100] ^= 0x01;

        let mut out = vec![0u8; msg.len()];
        assert_eq!(
            unsigncrypt(&sk_r, &pk_s, &pk_r, b"", &pkt[..pkt_len], &mut out),
            Err(SigncryptOpenFailed)
        );
    }

    #[test]
    fn tampered_aad_rejected() {
        let (sk_s, pk_s) = make_keypair(0x70);
        let (sk_r, pk_r) = make_keypair(0x71);
        let msg = b"aad test";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"correct", msg, &mut pkt).unwrap();
        let mut out = vec![0u8; msg.len()];
        assert_eq!(
            unsigncrypt(&sk_r, &pk_s, &pk_r, b"wrong", &pkt[..pkt_len], &mut out),
            Err(SigncryptOpenFailed)
        );
    }

    #[test]
    fn wrong_recipient_key_rejected() {
        let (sk_s, pk_s) = make_keypair(0x80);
        let (_, pk_r) = make_keypair(0x81);
        let (sk_r2, pk_r2) = make_keypair(0x82); // different recipient
        let msg = b"wrong recipient";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();
        let mut out = vec![0u8; msg.len()];
        assert_eq!(
            unsigncrypt(&sk_r2, &pk_s, &pk_r2, b"", &pkt[..pkt_len], &mut out),
            Err(SigncryptOpenFailed)
        );
    }

    #[test]
    fn wrong_sender_key_rejected() {
        let (sk_s, pk_s) = make_keypair(0x90);
        let (_, pk_s2) = make_keypair(0x91); // different claimed sender
        let (sk_r, pk_r) = make_keypair(0x92);
        let msg = b"wrong sender";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();
        let mut out = vec![0u8; msg.len()];
        // Verify with a different sender public key — should fail sig check.
        assert_eq!(
            unsigncrypt(&sk_r, &pk_s2, &pk_r, b"", &pkt[..pkt_len], &mut out),
            Err(SigncryptOpenFailed)
        );
    }

    #[test]
    fn truncated_packet_rejected() {
        let (sk_s, pk_s) = make_keypair(0xA0);
        let (sk_r, pk_r) = make_keypair(0xA1);
        let msg = b"truncation";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();
        let mut out = vec![0u8; msg.len()];
        // Remove the last byte.
        assert_eq!(
            unsigncrypt(&sk_r, &pk_s, &pk_r, b"", &pkt[..pkt_len - 1], &mut out),
            Err(SigncryptOpenFailed)
        );
    }

    #[test]
    fn output_buffer_too_small_returns_err() {
        let (sk_s, pk_s) = make_keypair(0xB0);
        let (_, pk_r) = make_keypair(0xB1);
        let msg = b"buf check";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD - 1]; // one byte short
        assert_eq!(
            signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt),
            Err(SigncryptOpenFailed)
        );
    }

    // ── Determinism / non-determinism ─────────────────────────────────────────

    #[test]
    fn two_signcrypts_same_message_different_kem_ct() {
        // Each signcrypt call uses fresh entropy → different kem_ct and ciphertext.
        let (sk_s, pk_s) = make_keypair(0xC0);
        let (_, pk_r) = make_keypair(0xC1);
        let msg = b"non-det test";
        let mut pkt1 = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let mut pkt2 = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt1).unwrap();
        signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt2).unwrap();
        // With overwhelming probability, fresh KEM entropy produces different packets.
        assert_ne!(
            &pkt1[PKT_KEM_CT_OFF..PKT_KEM_CT_OFF + KEM_CT_LEN],
            &pkt2[PKT_KEM_CT_OFF..PKT_KEM_CT_OFF + KEM_CT_LEN],
            "two independent encapsulations must produce different kem_ct (with overwhelming probability)"
        );
    }

    // ── Packet-field binding ──────────────────────────────────────────────────

    #[test]
    fn tampered_kem_ct_rejected() {
        let (sk_s, pk_s) = make_keypair(0xD0);
        let (sk_r, pk_r) = make_keypair(0xD1);
        let msg = b"kem tamper";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();

        // Corrupt a byte inside the kem_ct field.
        pkt[PKT_KEM_CT_OFF + 42] ^= 0x80;

        let mut out = vec![0u8; msg.len()];
        assert_eq!(
            unsigncrypt(&sk_r, &pk_s, &pk_r, b"", &pkt[..pkt_len], &mut out),
            Err(SigncryptOpenFailed),
            "tampered kem_ct must cause signature failure (it's in the transcript)"
        );
    }

    #[test]
    fn tampered_tag_rejected() {
        let (sk_s, pk_s) = make_keypair(0xE0);
        let (sk_r, pk_r) = make_keypair(0xE1);
        let msg = b"tag tamper";
        let mut pkt = vec![0u8; msg.len() + PACKET_FIXED_OVERHEAD];
        let pkt_len = signcrypt(&sk_s, &pk_s, &pk_r, b"", msg, &mut pkt).unwrap();

        let tag_off = PKT_CT_OFF + msg.len();
        pkt[tag_off] ^= 0x01; // flip a bit in the tag

        let mut out = vec![0u8; msg.len()];
        assert_eq!(
            unsigncrypt(&sk_r, &pk_s, &pk_r, b"", &pkt[..pkt_len], &mut out),
            Err(SigncryptOpenFailed)
        );
    }
}
