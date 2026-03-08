pub(crate) mod aes;
/// AES-256-GCM authenticated encryption module.
///
/// Implements NIST SP 800-38D §7 (GCM) over AES-256 (FIPS 197).
/// All types are `pub(crate)` — this module is internal to the parent project.
///
/// # Module layout
///
/// ```text
/// aes256gcm/
///  ├── mod.rs               ← this file; sub-module declarations
///  ├── arch/
///  │    ├── mod.rs          ← hardware dispatch (AES-NI / runtime / soft)
///  │    ├── soft.rs         ← portable AES-256 (lookup tables, const fn)
///  │    └── x86.rs          ← AES-NI + PCLMULQDQ intrinsics
///  ├── aes/
///  │    ├── mod.rs          ← re-exports
///  │    ├── cipher.rs       ← single-block AES-256 encrypt
///  │    └── key_schedule.rs ← Key256, KeySchedule (expand + zeroize-on-drop)
///  └── gcm/
///       ├── mod.rs          ← Aes256Gcm, Nonce, AuthError; NIST test vectors
///       ├── ctr.rs          ← CTR keystream state (J1 onwards, 16-byte buffered)
///       └── ghash.rs        ← GHASH over GF(2¹²⁸); software bit-by-bit multiply
/// ```
///
/// # Consumption within the project
///
/// ```rust
/// use crate::algos::aes256gcm::{Aes256Gcm, Nonce, AuthError};
/// ```
///
/// See `gcm/mod.rs` for the full `seal_in_place` / `open_in_place` API.
///
/// # Safety
///
/// `unsafe` is confined to `arch/x86.rs` (SIMD intrinsics) and `zeroize.rs`
/// (`write_volatile` on raw pointers). All other code is safe Rust. Every
/// `unsafe` block carries an explicit safety contract in its doc comment.
pub(crate) mod arch;
pub(crate) mod gcm;

pub(crate) use gcm::Aes256Gcm;
pub(crate) use gcm::Nonce;
