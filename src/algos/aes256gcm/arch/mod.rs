/// Architecture dispatch.
///
/// Three-tier selection strategy:
///
///   1. Compile-time guaranteed AES-NI (`target_feature = "aes"`):
///      Emit only the hardware path — zero overhead, no dead code.
///      Active when building with `-C target-feature=+aes` or `target-cpu=native`.
///
///   2. x86/x86_64 without compile-time AES-NI guarantee:
///      Detect at runtime via `std::is_x86_feature_detected!`.
///      Result cached in an `AtomicU8` with `Acquire`/`AcqRel` ordering and
///      `compare_exchange` to handle concurrent first-detection races safely.
///      One `Acquire` load on every subsequent call (~1–2 cycles).
///
///   3. Non-x86 architectures:
///      Pure software path; no SIMD, no runtime check.
pub(crate) mod soft;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) mod x86;

// ─────────────────────────────────────────────────────────────────────────────
// Public dispatch surface
// ─────────────────────────────────────────────────────────────────────────────

/// Expand a 256-bit key into 15 × 128-bit round keys.
#[inline]
pub(crate) fn expand_key_256(key: &[u8; 32], round_keys: &mut [[u8; 16]; 15]) {
    dispatch_expand(key, round_keys);
}

/// Encrypt a single 128-bit block in-place.
#[inline]
pub(crate) fn aes256_encrypt(block: &mut [u8; 16], round_keys: &[[u8; 16]; 15]) {
    dispatch_encrypt(block, round_keys);
}

// ─────────────────────────────────────────────────────────────────────────────
// Path A: compile-time guaranteed AES-NI
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "aes"
))]
#[inline(always)]
fn dispatch_expand(key: &[u8; 32], round_keys: &mut [[u8; 16]; 15]) {
    // SAFETY: target_feature = "aes" is statically guaranteed by the cfg gate.
    unsafe { x86::expand_key_256(key, round_keys) }
}

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "aes"
))]
#[inline(always)]
fn dispatch_encrypt(block: &mut [u8; 16], round_keys: &[[u8; 16]; 15]) {
    // SAFETY: target_feature = "aes" is statically guaranteed by the cfg gate.
    unsafe { x86::aes256_encrypt(block, round_keys) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Path B: x86/x86_64 without compile-time AES-NI → runtime detection
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    not(target_feature = "aes")
))]
#[inline]
fn dispatch_expand(key: &[u8; 32], round_keys: &mut [[u8; 16]; 15]) {
    if aesni_available() {
        // SAFETY: aesni_available() confirmed hardware support.
        unsafe { x86::expand_key_256(key, round_keys) }
    } else {
        soft::expand_key_256(key, round_keys)
    }
}

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    not(target_feature = "aes")
))]
#[inline]
fn dispatch_encrypt(block: &mut [u8; 16], round_keys: &[[u8; 16]; 15]) {
    if aesni_available() {
        // SAFETY: aesni_available() confirmed hardware support.
        unsafe { x86::aes256_encrypt(block, round_keys) }
    } else {
        soft::aes256_encrypt(block, round_keys)
    }
}

/// Cache AES-NI detection result to avoid repeated CPUID overhead.
///
/// State machine encoded in an `AtomicU8`:
///   0 = not yet detected
///   1 = detected, not available
///   2 = detected, available
///
/// `Acquire`/`AcqRel` ordering ensures that any thread which reads `2` (or
/// `1`) from the cache also sees all stores made by the detecting thread
/// before it wrote the result. `compare_exchange` prevents redundant writes
/// in a concurrent first-detection race — the hardware result is deterministic
/// so the racing threads agree, but we avoid torn state and unnecessary stores.
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    not(target_feature = "aes")
))]
fn aesni_available() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    static CACHE: AtomicU8 = AtomicU8::new(0);

    // Fast path: already resolved.
    match CACHE.load(Ordering::Acquire) {
        2 => return true,
        1 => return false,
        _ => {}
    }

    // Slow path: run CPUID and attempt to be the first writer.
    let available = std::is_x86_feature_detected!("aes");
    let new_val = if available { 2u8 } else { 1u8 };

    // compare_exchange: write only if the state is still 0 (unresolved).
    // If another thread raced and already wrote, their value wins — which is
    // fine because the result is deterministic (same CPU, same feature).
    // On failure we don't care about the current value — re-read below.
    let _ = CACHE.compare_exchange(0, new_val, Ordering::AcqRel, Ordering::Acquire);

    // Re-read so we return whatever the winning thread stored.
    CACHE.load(Ordering::Acquire) == 2
}

// ─────────────────────────────────────────────────────────────────────────────
// Path C: non-x86 — software only
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
#[inline(always)]
fn dispatch_expand(key: &[u8; 32], round_keys: &mut [[u8; 16]; 15]) {
    soft::expand_key_256(key, round_keys)
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
#[inline(always)]
fn dispatch_encrypt(block: &mut [u8; 16], round_keys: &[[u8; 16]; 15]) {
    soft::aes256_encrypt(block, round_keys)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Dispatch produces the NIST FIPS 197 Appendix B cipher vector.
    /// This tests whichever path (AES-NI or soft) is selected for this build.
    #[test]
    fn dispatch_encrypt_nist_fips197() {
        let key = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let mut rk = [[0u8; 16]; 15];
        expand_key_256(&key, &mut rk);
        let mut block = [
            0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        aes256_encrypt(&mut block, &rk);
        assert_eq!(
            block,
            [
                0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
                0x60, 0x89
            ]
        );
    }

    /// AES-256(0^32, 0^128) — GHASH subkey H when K = 0.
    /// Verified against OpenSSL and NIST AES ECB Known Answer Tests.
    #[test]
    fn dispatch_encrypt_zero_block() {
        let mut rk = [[0u8; 16]; 15];
        expand_key_256(&[0u8; 32], &mut rk);
        let mut block = [0u8; 16];
        aes256_encrypt(&mut block, &rk);
        assert_eq!(
            block,
            [
                0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84,
                0x20, 0x87
            ]
        );
    }

    /// Verify that the soft and dispatch paths agree.
    #[test]
    fn dispatch_matches_soft_path() {
        let key = [0xDEu8; 32];
        let mut rk_dispatch = [[0u8; 16]; 15];
        let mut rk_soft = [[0u8; 16]; 15];
        expand_key_256(&key, &mut rk_dispatch);
        soft::expand_key_256(&key, &mut rk_soft);
        assert_eq!(rk_dispatch, rk_soft, "Key schedule dispatch/soft mismatch");

        let pt = [0xBEu8; 16];
        let mut ct_dispatch = pt;
        let mut ct_soft = pt;
        aes256_encrypt(&mut ct_dispatch, &rk_dispatch);
        soft::aes256_encrypt(&mut ct_soft, &rk_soft);
        assert_eq!(ct_dispatch, ct_soft, "Encrypt dispatch/soft mismatch");
    }

    #[test]
    fn key_schedule_rk0_is_first_half() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let mut rk = [[0u8; 16]; 15];
        expand_key_256(&key, &mut rk);
        assert_eq!(rk[0], key[0..16]);
        assert_eq!(rk[1], key[16..32]);
    }
}
