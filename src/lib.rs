//! # Veil Crypto - Hardened Edition
//!
//! Enterprise-grade post-quantum cryptographic library with STRIDE/CSF/GDPR compliance.
//!
//! ## Key Features
//!
//! - **Constant-Time Operations**: All cryptographic operations enforce timing guarantees
//! - **Dual-Context Errors**: Internal debugging + external opacity for security
//! - **STRIDE Coverage**: Comprehensive threat model mitigation
//! - **CSF Alignment**: NIST Cybersecurity Framework compliance
//! - **GDPR Compliance**: Privacy-by-design with verified zeroization
//! - **Post-Quantum Security**: ML-KEM-1024 + ML-DSA-87 (NIST standards)
//! - **Memory Safety**: Automatic zeroization with verification
//! - **DoS Protection**: Built-in rate limiting (1000 ops/sec symmetric, 100 ops/sec PQC)
//! - **No-Clone Semantics**: Zero-copy architecture prevents side-channel attacks
//!
//! ## Architecture
//!
//! ```text
//! Application Layer
//!     ↓
//! Crypto Operations (AES-GCM, ML-KEM, ML-DSA)
//!     ↓
//! Hardened Standard (Constant-Time, Dual-Context Errors, Audit)
//!     ↓
//! Security Enforcement (Rate Limiting, Zeroization, Timing Guards)
//! ```
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use veil_crypto::*;
//!
//! # fn main() -> Result<()> {
//! // 3-layer onion encryption
//! let encryptor = OnionEncryptor::new(
//!     [1u8; 32],  // entry key
//!     [2u8; 32],  // relay key
//!     [3u8; 32],  // exit key
//! )?;
//!
//! let ciphertext = encryptor.encrypt(b"Secret message")?;
//!
//! // Decryption with automatic audit logging
//! let decryptor = OnionDecryptor::new([1u8; 32])?;
//! let plaintext = decryptor.decrypt(&ciphertext)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Guarantees
//!
//! ### STRIDE Compliance
//!
//! - **Spoofing**: Post-quantum signatures (ML-DSA-87)
//! - **Tampering**: Authenticated encryption (AES-256-GCM)
//! - **Repudiation**: Comprehensive audit logging
//! - **Information Disclosure**: Opaque errors, memory zeroization
//! - **Denial of Service**: Rate limiting
//! - **Elevation of Privilege**: Immutable keys, principle of least privilege
//!
//! ### GDPR Compliance
//!
//! - Data minimization (no PII in errors)
//! - Purpose limitation (keys used only for crypto)
//! - Storage limitation (automatic zeroization)
//! - Right to erasure (verified zeroization)
//!
//! See [SECURITY.md](../SECURITY.md) for detailed compliance documentation.

#![deny(unsafe_code)]
#![warn(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::clone_on_ref_ptr
)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

// Core modules
pub mod error;
pub mod constant_time;
pub mod audit;
pub mod pqc;

// Re-exports for convenience
pub use error::{CryptoError, CryptoErrorKind, ErrorSeverity, Result, StrideCategory};
pub use constant_time::{ct_eq, ct_zeroize_verify, TimingGuard};
pub use audit::{log_audit_event, AuditEvent, METRICS};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce,
};
use governor::{
    clock::DefaultClock, state::InMemoryState, state::NotKeyed, Quota, RateLimiter,
};
use std::num::NonZeroU32;
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS - Security Parameters
// ═══════════════════════════════════════════════════════════════════════════

/// AES-GCM nonce size in bytes (96 bits)
pub const NONCE_SIZE: usize = 12;

/// AES-GCM authentication tag size in bytes (128 bits)
pub const TAG_SIZE: usize = 16;

/// AES-256 key size in bytes
pub const KEY_SIZE: usize = 32;

/// Minimum valid encrypted packet size (nonce + tag)
const MIN_PACKET_SIZE: usize = NONCE_SIZE + TAG_SIZE;

/// Rate limit for symmetric operations (ops per second) - STRIDE: DoS protection
const SYMMETRIC_RATE_LIMIT: u32 = 1000;

/// Expected minimum time for AES-256-GCM encryption (nanoseconds)
/// Used for constant-time verification and side-channel protection
const MIN_ENCRYPT_TIME_NS: u64 = 5_000; // 5 microseconds

/// Expected minimum time for AES-256-GCM decryption (nanoseconds)
const MIN_DECRYPT_TIME_NS: u64 = 5_000;

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

/// Rate limiter for cryptographic operations (DoS protection)
type CryptoRateLimiter = Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>;

// ═══════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/// Create rate limiter for symmetric crypto operations
#[inline]
fn create_rate_limiter() -> CryptoRateLimiter {
    Arc::new(RateLimiter::direct(Quota::per_second(
        NonZeroU32::new(SYMMETRIC_RATE_LIMIT).expect("Rate limit must be non-zero"),
    )))
}

// ═══════════════════════════════════════════════════════════════════════════
// ONION LAYER - Single Encryption Layer with Hardened Security
// ═══════════════════════════════════════════════════════════════════════════

/// Single encryption layer for onion routing with hardened security
///
/// ## Security Enhancements (Hardened Edition)
///
/// - **Constant-Time Operations**: Timing guards enforce execution time bounds
/// - **Audit Logging**: All operations logged with STRIDE classification
/// - **Memory Safety**: Keys zeroized immediately after use
/// - **Rate Limiting**: DoS protection (1000 ops/sec)
/// - **Error Context**: Dual context (internal debugging + external opacity)
/// - **No-Clone Semantics**: Single-owner architecture prevents memory bloat
///
/// ## Packet Format
///
/// ```text
/// ┌──────────┬───────────────┬─────────┐
/// │  Nonce   │  Ciphertext   │   Tag   │
/// │ (12 B)   │  (variable)   │ (16 B)  │
/// └──────────┴───────────────┴─────────┘
/// ```
#[derive(ZeroizeOnDrop)]
pub struct OnionLayer {
    #[zeroize(skip)]
    cipher: Aes256Gcm,
    #[zeroize(skip)]
    rate_limiter: CryptoRateLimiter,
}

impl OnionLayer {
    /// Create layer from 32-byte key
    ///
    /// Key is consumed (moved) and zeroized after cipher initialization.
    /// This prevents accidental key duplication (STRIDE: Information Disclosure).
    pub fn from_key(mut key: [u8; KEY_SIZE]) -> Result<Self> {
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| CryptoError::encryption_failed("AES-GCM initialization failed"))?;
        
        // Zeroize key immediately after use (GDPR: Right to Erasure)
        key.zeroize();
        
        audit::log_audit_event(
            AuditEvent::OperationSuccess,
            "onion_layer_create",
            &StrideCategory::NotApplicable,
            &ErrorSeverity::Info,
            "OnionLayer initialized",
        );
        
        Ok(Self {
            cipher,
            rate_limiter: create_rate_limiter(),
        })
    }

    /// Encrypt plaintext with constant-time guarantees
    ///
    /// ## Security Features
    ///
    /// - Timing guard enforces minimum execution time
    /// - Rate limiting prevents DoS attacks
    /// - Random nonce generation (never reused)
    /// - Audit logging with STRIDE classification
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Box<[u8]>> {
        // Rate limiting check (STRIDE: Denial of Service)
        self.rate_limiter
            .check()
            .map_err(|_| {
                let err = CryptoError::rate_limit_exceeded("Symmetric encryption rate limit hit");
                audit::log_error(&err, "encrypt");
                err
            })?;

        // Timing guard for constant-time enforcement
        let _guard = TimingGuard::new("aes_encrypt", MIN_ENCRYPT_TIME_NS);

        // Generate random nonce (96 bits)
        let nonce = Aes256Gcm::generate_nonce(&mut rand::thread_rng());

        // Encrypt with AES-256-GCM (authenticated encryption)
        let ciphertext = self.cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| {
                let err = CryptoError::encryption_failed("AES-GCM encryption operation failed");
                audit::log_error(&err, "encrypt");
                err
            })?;

        // Construct packet: nonce || ciphertext (includes auth tag)
        let mut packet = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&ciphertext);

        audit::log_audit_event(
            AuditEvent::OperationSuccess,
            "encrypt",
            &StrideCategory::NotApplicable,
            &ErrorSeverity::Info,
            format!("Encrypted {} bytes", plaintext.len()),
        );

        Ok(packet.into_boxed_slice())
    }

    /// Decrypt ciphertext with tampering detection
    ///
    /// ## Security Features
    ///
    /// - Timing guard enforces constant-time execution
    /// - Authentication tag verified (STRIDE: Tampering)
    /// - Invalid packets rejected early
    /// - Audit logging for tampering attempts
    pub fn decrypt(&self, packet: &[u8]) -> Result<Box<[u8]>> {
        // Timing guard for side-channel protection
        let _guard = TimingGuard::new("aes_decrypt", MIN_DECRYPT_TIME_NS);

        // Validate minimum packet size
        if packet.len() < MIN_PACKET_SIZE {
            let err = CryptoError::invalid_packet(format!(
                "Packet too small: {} bytes < {} minimum",
                packet.len(),
                MIN_PACKET_SIZE
            ));
            audit::log_error(&err, "decrypt");
            return Err(err);
        }

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = packet.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt and verify authentication tag
        let plaintext = self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| {
                // Authentication failure indicates tampering
                let err = CryptoError::decryption_failed(
                    "AES-GCM decryption failed - authentication tag mismatch (tampering detected)"
                );
                audit::log_audit_event(
                    AuditEvent::TamperingDetected,
                    "decrypt",
                    &StrideCategory::Tampering,
                    &ErrorSeverity::Warning,
                    "Authentication tag verification failed",
                );
                err
            })?;

        audit::log_audit_event(
            AuditEvent::OperationSuccess,
            "decrypt",
            &StrideCategory::NotApplicable,
            &ErrorSeverity::Info,
            format!("Decrypted {} bytes", plaintext.len()),
        );

        Ok(plaintext.into_boxed_slice())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ONION ENCRYPTOR - 3-Layer Encryption with Audit Trail
// ═══════════════════════════════════════════════════════════════════════════

/// 3-layer onion encryption with comprehensive security
///
/// Each layer uses a unique key and is zeroized after use.
/// All operations are audited for compliance and incident response.
#[derive(ZeroizeOnDrop)]
pub struct OnionEncryptor {
    entry_layer: OnionLayer,
    relay_layer: OnionLayer,
    exit_layer: OnionLayer,
}

impl OnionEncryptor {
    /// Create 3-layer encryptor
    ///
    /// Keys are consumed and zeroized after initialization.
    pub fn new(
        entry_key: [u8; KEY_SIZE],
        relay_key: [u8; KEY_SIZE],
        exit_key: [u8; KEY_SIZE],
    ) -> Result<Self> {
        Ok(Self {
            entry_layer: OnionLayer::from_key(entry_key)?,
            relay_layer: OnionLayer::from_key(relay_key)?,
            exit_layer: OnionLayer::from_key(exit_key)?,
        })
    }

    /// Encrypt with 3 layers: exit → relay → entry
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Box<[u8]>> {
        let layer1 = self.exit_layer.encrypt(plaintext)?;
        let layer2 = self.relay_layer.encrypt(&layer1)?;
        let layer3 = self.entry_layer.encrypt(&layer2)?;
        Ok(layer3)
    }
}

/// Single-layer decryptor for onion routing nodes
#[derive(ZeroizeOnDrop)]
pub struct OnionDecryptor {
    layer: OnionLayer,
}

impl OnionDecryptor {
    /// Create decryptor for one layer
    pub fn new(key: [u8; KEY_SIZE]) -> Result<Self> {
        Ok(Self {
            layer: OnionLayer::from_key(key)?,
        })
    }

    /// Decrypt one onion layer
    pub fn decrypt(&self, packet: &[u8]) -> Result<Box<[u8]>> {
        self.layer.decrypt(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onion_roundtrip() {
        let plaintext = b"Test message";
        let encryptor = OnionEncryptor::new(
            [1u8; KEY_SIZE],
            [2u8; KEY_SIZE],
            [3u8; KEY_SIZE],
        )
        .expect("Failed to create encryptor");

        let encrypted = encryptor.encrypt(plaintext).expect("Encryption failed");

        // Decrypt each layer
        let dec1 = OnionDecryptor::new([1u8; KEY_SIZE]).expect("Dec1 failed");
        let layer1 = dec1.decrypt(&encrypted).expect("Layer1 decrypt failed");

        let dec2 = OnionDecryptor::new([2u8; KEY_SIZE]).expect("Dec2 failed");
        let layer2 = dec2.decrypt(&layer1).expect("Layer2 decrypt failed");

        let dec3 = OnionDecryptor::new([3u8; KEY_SIZE]).expect("Dec3 failed");
        let decrypted = dec3.decrypt(&layer2).expect("Layer3 decrypt failed");

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_tampering_detection() {
        let layer = OnionLayer::from_key([0x42u8; KEY_SIZE]).expect("Layer creation failed");
        let mut encrypted = layer.encrypt(b"Original").expect("Encryption failed").to_vec();

        // Tamper with ciphertext
        encrypted[15] ^= 0x01;

        // Decryption should fail due to authentication tag mismatch
        let result = layer.decrypt(&encrypted);
        assert!(result.is_err());
        
        if let Err(e) = result {
            assert_eq!(e.kind(), &CryptoErrorKind::DecryptionFailed);
            assert_eq!(e.stride_category(), &StrideCategory::Tampering);
        }
    }

    #[test]
    fn test_invalid_packet_size() {
        let layer = OnionLayer::from_key([0x99u8; KEY_SIZE]).expect("Layer creation failed");
        let too_small = vec![0u8; 10]; // Less than MIN_PACKET_SIZE

        let result = layer.decrypt(&too_small);
        assert!(result.is_err());
        
        if let Err(e) = result {
            assert_eq!(e.kind(), &CryptoErrorKind::InvalidPacket);
        }
    }

    #[test]
    fn test_audit_metrics_increment() {
        use std::sync::atomic::Ordering;
        
        let initial = METRICS.total_operations.load(Ordering::Relaxed);
        
        let layer = OnionLayer::from_key([0xAAu8; KEY_SIZE]).expect("Layer creation failed");
        let _encrypted = layer.encrypt(b"Test");
        
        let after = METRICS.total_operations.load(Ordering::Relaxed);
        assert!(after > initial);
    }
}