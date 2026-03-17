/// Zeroization primitives.
///
/// Two lines of defence against dead-store elimination:
///   1. `core::ptr::write_volatile`  — compiler must emit the store
///   2. `compiler_fence(SeqCst)`     — prevents reordering past the wipe
///
/// `#[inline(never)]` on `zeroize_mem` is non-negotiable: inlining
/// re-exposes the volatile writes to the surrounding optimisation context.
use core::sync::atomic::{Ordering, compiler_fence};

// ─────────────────────────────────────────────────────────────────────────────
// Trait
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) trait Zeroize {
    fn zeroize(&mut self);
}

// ─────────────────────────────────────────────────────────────────────────────
// Core primitive
// ─────────────────────────────────────────────────────────────────────────────

/// Wipe `len` bytes starting at `ptr` to zero.
///
/// # Safety
/// `ptr` must be valid for writes of `len` bytes with no aliasing violations.
///
/// `#[inline(never)]`: mandatory — inlining allows the optimiser to re-examine
/// whether the stores are observable and eliminate them as dead.
#[inline(never)]
pub(crate) unsafe fn zeroize_mem(ptr: *mut u8, len: usize) {
    for i in 0..len {
        // SAFETY: caller guarantees `ptr` is valid for `len` writable bytes.
        unsafe { core::ptr::write_volatile(ptr.add(i), 0u8) };
    }
    // SeqCst fence: no loads or stores may be reordered past this point
    // in either direction by the compiler.
    compiler_fence(Ordering::SeqCst);
}

// ─────────────────────────────────────────────────────────────────────────────
// Typed helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Zeroize a fixed-size byte array in place.
#[inline(always)]
pub(crate) fn zeroize_array<const N: usize>(arr: &mut [u8; N]) {
    // SAFETY: `arr` is a valid aligned stack allocation of exactly N bytes.
    unsafe { zeroize_mem(arr.as_mut_ptr(), N) };
}

/// Zeroize an arbitrary mutable byte slice in place.
#[inline(always)]
pub(crate) fn zeroize_slice(buf: &mut [u8]) {
    // SAFETY: `buf` is a valid writable slice of exactly `buf.len()` bytes.
    unsafe { zeroize_mem(buf.as_mut_ptr(), buf.len()) };
}

/// Zeroize a 2D array of byte arrays (e.g. round key schedules).
/// The array is contiguous in memory; total size is ROWS × COLS bytes.
#[inline(always)]
pub(crate) fn zeroize_array2d<const ROWS: usize, const COLS: usize>(arr: &mut [[u8; COLS]; ROWS]) {
    // SAFETY: 2D arrays are row-major contiguous; total size = ROWS * COLS bytes.
    unsafe { zeroize_mem(arr.as_mut_ptr() as *mut u8, ROWS * COLS) };
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── zeroize_array ────────────────────────────────────────────────────────

    #[test]
    fn zeroize_array_clears_all_bytes() {
        let mut buf = [0xABu8; 32];
        zeroize_array(&mut buf);
        assert_eq!(buf, [0u8; 32]);
    }

    #[test]
    fn zeroize_array_single_byte() {
        let mut buf = [0xFFu8; 1];
        zeroize_array(&mut buf);
        assert_eq!(buf, [0u8; 1]);
    }

    #[test]
    fn zeroize_slice_clears_all_bytes() {
        let mut buf = [0xABu8; 24];
        zeroize_slice(&mut buf);
        assert_eq!(buf, [0u8; 24]);
    }

    #[test]
    fn zeroize_array_idempotent() {
        let mut buf = [0xAAu8; 16];
        zeroize_array(&mut buf);
        zeroize_array(&mut buf);
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn zeroize_array_sparse_values() {
        let mut buf = [0u8; 16];
        buf[0] = 0xFF;
        buf[7] = 0xAB;
        buf[15] = 0x01;
        zeroize_array(&mut buf);
        assert_eq!(buf, [0u8; 16]);
    }

    // ── zeroize_array2d ──────────────────────────────────────────────────────

    #[test]
    fn zeroize_array2d_clears_all() {
        let mut buf = [[0xCDu8; 16]; 15];
        zeroize_array2d(&mut buf);
        assert_eq!(buf, [[0u8; 16]; 15]);
    }

    #[test]
    fn zeroize_array2d_mixed_values() {
        let mut buf = [[0u8; 16]; 4];
        buf[0] = [0xFFu8; 16];
        buf[2][7] = 0x42;
        buf[3] = [0xAAu8; 16];
        zeroize_array2d(&mut buf);
        assert_eq!(buf, [[0u8; 16]; 4]);
    }

    // ── zeroize_mem ──────────────────────────────────────────────────────────

    #[test]
    fn zeroize_mem_full_buffer() {
        let mut buf = [0xFFu8; 64];
        // SAFETY: buf is valid for 64-byte write, no aliasing
        unsafe { zeroize_mem(buf.as_mut_ptr(), 64) };
        assert_eq!(buf, [0u8; 64]);
    }

    #[test]
    fn zeroize_mem_zero_length_is_noop() {
        let mut buf = [0xAAu8; 4];
        // SAFETY: zero-length write is a no-op, pointer value doesn't matter
        unsafe { zeroize_mem(buf.as_mut_ptr(), 0) };
        assert_eq!(buf, [0xAAu8; 4]);
    }

    #[test]
    fn zeroize_mem_partial_range() {
        let mut buf = [0xFFu8; 16];
        // SAFETY: offset 4, 8 bytes — fully within the 16-byte allocation
        unsafe { zeroize_mem(buf.as_mut_ptr().add(4), 8) };
        assert_eq!(&buf[..4], &[0xFFu8; 4]);
        assert_eq!(&buf[4..12], &[0u8; 8]);
        assert_eq!(&buf[12..], &[0xFFu8; 4]);
    }
}
