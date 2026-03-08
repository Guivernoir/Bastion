//! Constant-time primitives.
//!
//! ## Threat model and limitations
//!
//! These functions attempt to prevent *compiler-level* timing channels by:
//!
//! - Accumulating results with XOR/OR folds instead of early-return branches.
//! - Using `ptr::read_volatile` to prevent the compiler from eliminating reads
//!   or short-circuiting loops based on intermediate values.
//! - Inserting `compiler_fence(SeqCst)` barriers before returning boolean
//!   results to prevent instruction reordering.
//!
//! Hardware-level timing guarantees (branch-predictor training, cache
//! side-channels, speculative execution) are *not* provided by this module.
//! Production deployments should validate timing properties with dedicated
//! analysis tools (e.g., `ctgrind`, `dudect`).
//!
//! [`TimingGuard`] enforces a minimum execution floor via spin-wait and
//! detects ceiling violations. It is a best-effort defence against observable
//! timing at the network layer, not a substitute for hardware CT assurance.

#![allow(unsafe_code)]

use crate::audit::METRICS;
use crate::error::{CryptoError, Result};
use crate::zeroize::zeroize_mem;
use core::hint::black_box;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering, compiler_fence};
use std::time::Instant;

/// Global timing-violation counter, distinct from the audit-layer counter.
static TIMING_VIOLATIONS: AtomicU64 = AtomicU64::new(0);

/// Maximum allowed overshoot above the timing floor (5 ms).
const MAX_TIMING_WINDOW_NS: u64 = 5_000_000;

// ── Internal branchless helpers ───────────────────────────────────────────────

/// Returns `0xFF` if `a < b`, `0x00` otherwise. No branches.
///
/// Uses the borrow bit of a widened subtraction.
#[inline]
fn ct_byte_lt(a: u8, b: u8) -> u8 {
    // SAFETY: arithmetic on u16 — no memory access, no UB.
    let borrow = (a as u16).wrapping_sub(b as u16) >> 8;
    // borrow is 0 or 1; wrapping_neg maps 1 → 0xFF, 0 → 0x00.
    (borrow as u8).wrapping_neg()
}

/// Returns `0xFF` if `a == b`, `0x00` otherwise. No branches.
#[inline]
fn ct_byte_eq(a: u8, b: u8) -> u8 {
    let diff = a ^ b;
    // If diff == 0: (0 | 0) >> 7 == 0 → nonzero == 0 → 0u8.wrapping_sub(0) == 0xFF? No.
    // Actually: nonzero == 0 → 0u8.wrapping_neg() == 0 ... wait, need:
    //   nonzero = 0 if equal, 1 if not equal.
    // (diff | diff.wrapping_neg()) has MSB set iff diff != 0.
    let nonzero = (diff | diff.wrapping_neg()) >> 7; // 0 if equal, 1 if not equal
    nonzero.wrapping_sub(1) // 0xFF if equal (0-1 wraps), 0x00 if not equal (1-1 = 0)
}

/// Returns `0xFFFF_FFFF` if `a < b`, `0x0000_0000` otherwise.
///
/// Uses the borrow bit of a 64-bit widened subtraction.
#[inline]
fn ct_u32_lt(a: u32, b: u32) -> u32 {
    // The upper 32 bits of the 64-bit result hold the borrow.
    let borrow = (a as u64).wrapping_sub(b as u64) >> 32;
    borrow as u32 // 0 or 0xFFFF_FFFF
}

// ── Public CT primitives ──────────────────────────────────────────────────────

/// Constant-time equality check for byte slices.
///
/// Length mismatch is not secret and returns immediately.
/// All bytes are read via `read_volatile` to prevent loop elimination.
#[inline]
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for i in 0..a.len() {
        // SAFETY: `i` is within bounds for both slices; bounds checked above.
        // `read_volatile` prevents the compiler from proving `acc` can never
        // be set and eliding the loop.
        let x = unsafe { ptr::read_volatile(a.as_ptr().add(i)) };
        let y = unsafe { ptr::read_volatile(b.as_ptr().add(i)) };
        acc |= x ^ y;
    }
    compiler_fence(Ordering::SeqCst);
    black_box(acc) == 0
}

/// Constant-time equality check returning a 0/1 mask.
///
/// Returns `1` when slices are equal, `0` otherwise.
#[inline]
pub(crate) fn ct_eq_mask(a: &[u8], b: &[u8]) -> u8 {
    ct_eq(a, b) as u8
}

/// Constant-time equality check for fixed 16-byte values.
#[inline]
pub(crate) fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    ct_eq(a, b)
}

/// Constant-time lexicographic less-than for byte slices.
///
/// Runs all byte comparisons without early exit regardless of intermediate
/// results. Length difference is used only after comparing all shared bytes.
#[inline]
pub(crate) fn ct_less_than(a: &[u8], b: &[u8]) -> bool {
    let len = a.len().min(b.len());
    // `less`:  0xFF while a is determined to be less, 0x00 otherwise.
    // `equal`: 0xFF while all bytes seen so far are equal, 0x00 once a diff is found.
    let mut less: u8 = 0x00;
    let mut equal: u8 = 0xFF;

    for i in 0..len {
        // SAFETY: `i` is within bounds for both slices.
        let ai = unsafe { ptr::read_volatile(a.as_ptr().add(i)) };
        let bi = unsafe { ptr::read_volatile(b.as_ptr().add(i)) };

        let byte_lt = ct_byte_lt(ai, bi); // 0xFF if ai < bi
        let byte_eq = ct_byte_eq(ai, bi); // 0xFF if ai == bi

        // We update `less` only if we haven't diverged yet (equal & byte_lt).
        // Once a difference is found, `equal` becomes 0x00 and further bytes
        // cannot change `less`.
        less |= equal & byte_lt;
        equal &= byte_eq;
    }

    // If all shared bytes are equal, a shorter slice is less.
    let shorter_less = ((a.len() < b.len()) as u8).wrapping_neg();
    less |= equal & shorter_less;

    compiler_fence(Ordering::SeqCst);
    black_box(less) != 0
}

/// Constant-time conditional copy. Copies `src` into `dst` iff `condition`.
///
/// Uses a bitmask select on each byte — no branch on `condition` after
/// the mask is computed.
#[inline]
pub(crate) fn ct_copy_if(condition: bool, src: &[u8], dst: &mut [u8]) {
    ct_cmov_bytes(dst, src, condition as u8);
}

/// Constant-time conditional move.
///
/// Copies `src` into `dst` iff `choice == 1`; leaves `dst` unchanged otherwise.
/// Any non-`{0,1}` value is reduced to its low bit.
#[inline]
pub(crate) fn ct_cmov_bytes(dst: &mut [u8], src: &[u8], choice: u8) {
    let len = src.len().min(dst.len());
    let src_mask = (choice & 1).wrapping_neg(); // 0xFF if choice==1, else 0x00
    let dst_mask = !src_mask;
    for i in 0..len {
        dst[i] = (src[i] & src_mask) | (dst[i] & dst_mask);
    }
}

/// Constant-time XOR: `dst[i] = a[i] ^ b[i]`.
#[inline]
pub(crate) fn ct_xor(a: &[u8], b: &[u8], dst: &mut [u8]) {
    let len = a.len().min(b.len()).min(dst.len());
    for i in 0..len {
        dst[i] = a[i] ^ b[i];
    }
}

/// Zeroize `buffer` then verify all bytes read back as zero.
///
/// Verification uses `read_volatile` to prevent the compiler from treating the
/// post-zeroize state as a compile-time constant and eliding the check.
pub(crate) fn ct_zeroize_verify(buffer: &mut [u8]) -> Result<()> {
    // SAFETY: `buffer` is a valid writable byte slice.
    unsafe { zeroize_mem(buffer.as_mut_ptr(), buffer.len()) };

    let mut nonzero = 0u8;
    for i in 0..buffer.len() {
        // SAFETY: `i` is within bounds.
        // `read_volatile` prevents the compiler from constant-folding the
        // post-zeroize state and skipping the loop.
        let byte = unsafe { ptr::read_volatile(buffer.as_ptr().add(i)) };
        nonzero |= byte;
    }

    compiler_fence(Ordering::SeqCst);

    if black_box(nonzero) == 0 {
        Ok(())
    } else {
        Err(CryptoError::sanitization_failed(
            "zeroization verification failed",
        ))
    }
}

// ── Scalar CT operations ──────────────────────────────────────────────────────

/// Constant-time `value % modulus` using a 32-step binary long-division.
///
/// Each step is a branchless conditional subtraction via bitmask select.
#[inline]
pub(crate) fn ct_mod_reduce(value: u32, modulus: u32) -> u32 {
    let mut result = value;
    for bit in (0..32u32).rev() {
        let shifted = modulus.wrapping_shl(bit);
        // mask = 0xFFFF_FFFF if result >= shifted (i.e., *not* less-than).
        let lt_mask = ct_u32_lt(result, shifted);
        let ge_mask = !lt_mask;
        let sub_result = result.wrapping_sub(shifted);
        // Select sub_result if result >= shifted, else keep result.
        result = (sub_result & ge_mask) | (result & lt_mask);
    }
    result
}

/// Constant-time minimum of two `u32` values.
#[inline]
pub(crate) fn ct_min_u32(a: u32, b: u32) -> u32 {
    // mask = 0xFFFF_FFFF if a < b, select a; else select b.
    let mask = ct_u32_lt(a, b);
    (a & mask) | (b & !mask)
}

/// Constant-time maximum of two `u32` values.
#[inline]
pub(crate) fn ct_max_u32(a: u32, b: u32) -> u32 {
    // mask = 0xFFFF_FFFF if b < a (a is the larger), select a; else select b.
    let mask = ct_u32_lt(b, a);
    (a & mask) | (b & !mask)
}

/// Constant-time inclusive range check: `min <= value <= max`.
#[inline]
pub(crate) fn ct_in_range(value: u32, min: u32, max: u32) -> bool {
    let ge_min = ct_u32_lt(value, min) == 0; // value >= min iff NOT (value < min)
    let le_max = ct_u32_lt(max, value) == 0; // value <= max iff NOT (max < value)
    compiler_fence(Ordering::SeqCst);
    ge_min & le_max
}

/// Constant-time population count (Hamming weight) for `u32`.
///
/// Uses the parallel bit-sum algorithm. No branches, no data-dependent
/// memory accesses. The algorithm is from Hacker's Delight §5-1.
#[inline]
pub(crate) fn ct_hamming_weight(value: u32) -> u32 {
    let v = value;
    let v = v - ((v >> 1) & 0x5555_5555);
    let v = (v & 0x3333_3333) + ((v >> 2) & 0x3333_3333);
    let v = (v + (v >> 4)) & 0x0F0F_0F0F;
    v.wrapping_mul(0x0101_0101) >> 24
}

// ── Timing guard ──────────────────────────────────────────────────────────────

/// Best-effort timing floor and ceiling enforcer.
///
/// Create one at the start of a guarded block, then call [`TimingGuard::enforce`]
/// at the end. The guard spin-waits if the operation completed faster than
/// `floor_ns`, ensuring the *observed* duration is at least as long as the
/// floor regardless of the operation's actual duration.
///
/// ## Limitations
///
/// - Spin-wait precision is limited by the OS scheduler. On a heavily loaded
///   system, preemption between loop iterations may cause the final measured
///   duration to overshoot the ceiling.
/// - This provides network-layer timing normalisation, not hardware-level
///   constant-time guarantees.
pub(crate) struct TimingGuard {
    start: Instant,
    floor_ns: u64,
    ceil_ns: u64,
    name: &'static str,
}

impl TimingGuard {
    #[inline]
    pub(crate) fn new(name: &'static str, floor_ns: u64) -> Self {
        Self {
            start: Instant::now(),
            floor_ns,
            ceil_ns: floor_ns + MAX_TIMING_WINDOW_NS,
            name,
        }
    }

    /// Spin-wait until the floor is met, then verify the ceiling.
    ///
    /// Returns `Err` if the elapsed time exceeds the ceiling after the floor
    /// has been satisfied. A ceiling overshoot is recorded as a timing
    /// violation in both the module counter and the audit-layer metrics.
    pub(crate) fn enforce(self) -> Result<()> {
        loop {
            // `black_box` prevents the compiler from treating the elapsed
            // value as a compile-time constant and collapsing the loop.
            let elapsed = black_box(self.start.elapsed().as_nanos() as u64);

            if elapsed >= self.floor_ns {
                if elapsed > self.ceil_ns {
                    TIMING_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
                    METRICS.record_timing_viol();
                    return Err(CryptoError::timing_violation("timing ceiling exceeded"));
                }
                return Ok(());
            }

            core::hint::spin_loop();
        }
    }

    /// Passive check without enforcement (test-only).
    ///
    /// Returns `Err` if the elapsed time is outside `[floor_ns, ceil_ns]`
    /// at the moment of the call, without spin-waiting.
    #[cfg(test)]
    pub(crate) fn verify(self) -> Result<()> {
        let elapsed = self.start.elapsed().as_nanos() as u64;

        if elapsed < self.floor_ns {
            TIMING_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
            METRICS.record_timing_viol();
            return Err(CryptoError::timing_violation("timing floor violated"));
        }
        if elapsed > self.ceil_ns {
            TIMING_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
            METRICS.record_timing_viol();
            return Err(CryptoError::timing_violation("timing ceiling exceeded"));
        }
        Ok(())
    }

    /// Returns the number of timing violations recorded by this module.
    pub(crate) fn violation_count() -> u64 {
        TIMING_VIOLATIONS.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_16_identical() {
        assert!(ct_eq_16(&[0x42; 16], &[0x42; 16]));
    }

    #[test]
    fn ct_eq_16_mismatch() {
        let a = [0xAA; 16];
        let mut b = [0xAA; 16];
        b[7] ^= 1;
        assert!(!ct_eq_16(&a, &b));
    }

    #[test]
    fn ct_eq_mask_handles_len_mismatch() {
        assert_eq!(ct_eq_mask(&[1, 2, 3], &[1, 2]), 0);
    }

    #[test]
    fn ct_cmov_bytes_choice_zero_keeps_dst() {
        let mut dst = [1u8, 2, 3];
        let src = [9u8, 9, 9];
        ct_cmov_bytes(&mut dst, &src, 0);
        assert_eq!(dst, [1, 2, 3]);
    }

    #[test]
    fn ct_cmov_bytes_choice_one_copies_src() {
        let mut dst = [1u8, 2, 3];
        let src = [9u8, 9, 9];
        ct_cmov_bytes(&mut dst, &src, 1);
        assert_eq!(dst, [9, 9, 9]);
    }
}
