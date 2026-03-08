//! OS-backed entropy helpers with no external crate dependencies.
//!
//! Runtime code uses this module instead of `rand`/`getrandom` crates to keep
//! the dependency surface minimal.

use crate::error::{CryptoError, Result};

/// Fill `out` with cryptographically secure random bytes from the OS.
#[cfg(unix)]
pub(crate) fn fill_os_random(out: &mut [u8]) -> Result<()> {
    use std::fs::File;
    use std::io::Read;

    let mut urandom = File::open("/dev/urandom")
        .map_err(|_| CryptoError::internal("failed to open /dev/urandom"))?;
    urandom
        .read_exact(out)
        .map_err(|_| CryptoError::internal("failed to read /dev/urandom"))
}

/// Fill `out` with cryptographically secure random bytes from the OS.
#[cfg(windows)]
pub(crate) fn fill_os_random(out: &mut [u8]) -> Result<()> {
    use core::ffi::c_void;
    use core::ptr::null_mut;

    type BcryptAlgHandle = *mut c_void;

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            hAlgorithm: BcryptAlgHandle,
            pbBuffer: *mut u8,
            cbBuffer: u32,
            dwFlags: u32,
        ) -> i32;
    }

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    if out.len() > u32::MAX as usize {
        return Err(CryptoError::internal("random buffer too large"));
    }

    // SAFETY: `out` points to writable memory of size `out.len()`.
    // Passing null algorithm handle with SYSTEM_PREFERRED_RNG is the
    // documented CNG API contract.
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            out.as_mut_ptr(),
            out.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };

    if status >= 0 {
        Ok(())
    } else {
        Err(CryptoError::internal("BCryptGenRandom failed"))
    }
}

/// Fill `out` with cryptographically secure random bytes from the OS.
#[cfg(not(any(unix, windows)))]
pub(crate) fn fill_os_random(_out: &mut [u8]) -> Result<()> {
    Err(CryptoError::internal(
        "OS random source is unsupported on this platform",
    ))
}

/// Const-generic convenience wrapper for fixed-size arrays.
#[inline]
pub(crate) fn fill_os_random_array<const N: usize>(out: &mut [u8; N]) -> Result<()> {
    fill_os_random(out.as_mut_slice())
}
