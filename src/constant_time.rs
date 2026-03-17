//! Constant-time comparison helpers used by the MLSigcrypt packet path.
//!
//! These helpers aim to avoid compiler-level timing shortcuts by reading each
//! compared byte and accumulating differences without early exits.

#![allow(unsafe_code)]

use core::hint::black_box;
use core::ptr;
use core::sync::atomic::{Ordering, compiler_fence};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_identical() {
        assert!(ct_eq(&[0x42; 16], &[0x42; 16]));
    }

    #[test]
    fn ct_eq_mismatch() {
        let a = [0xAA; 16];
        let mut b = [0xAA; 16];
        b[7] ^= 1;
        assert!(!ct_eq(&a, &b));
    }

    #[test]
    fn ct_eq_handles_len_mismatch() {
        assert!(!ct_eq(&[1, 2, 3], &[1, 2]));
    }
}
