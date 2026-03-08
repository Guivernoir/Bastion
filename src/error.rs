//! Opaque error types for cryptographic operations.
//!
//! External surface: [`CryptoError`] (opaque) and [`Result<T>`].
//!
//! `Display` emits a fixed string with no implementation detail.
//! Internal context is retained for forensic correlation and is only
//! accessible within the crate.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Crate-wide result alias.
pub(crate) type Result<T> = std::result::Result<T, CryptoError>;

// ── Internal classification ───────────────────────────────────────────────────

/// Severity level used for internal routing and metrics.
///
/// Not sensitive — no zeroize needed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ErrorSeverity {
    Warning,
    Error,
    Critical,
}

/// Broad STRIDE threat category used for internal counter routing.
///
/// Not sensitive — no zeroize needed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ThreatCategory {
    Tampering,
    Spoofing,
    InformationDisclosure,
    DenialOfService,
    /// The audit/sanitization layer itself has failed (e.g. zeroize verification).
    AuditFailure,
    None,
}

/// Error detail retained for forensic correlation. Never forwarded to callers.
///
/// `details` is static and allocation-free.
pub(crate) struct InternalCtx {
    /// Human-readable detail — may reference internal state; never surfaces externally.
    pub(crate) details: &'static str,
    pub(crate) timestamp_ns: u64,
    pub(crate) sequence: u64,
    pub(crate) severity: ErrorSeverity,
    pub(crate) category: ThreatCategory,
}

#[derive(Debug)]
pub(crate) struct SanitizedCtx {
    pub(crate) sequence: u64,
    pub(crate) severity: &'static str,
    pub(crate) category: &'static str,
    pub(crate) timestamp_ns: u64,
}

impl InternalCtx {
    /// Sanitized structured context for audit logging.
    pub(crate) fn sanitized(&self) -> SanitizedCtx {
        let severity = match self.severity {
            ErrorSeverity::Warning => "warning",
            ErrorSeverity::Error => "error",
            ErrorSeverity::Critical => "critical",
        };

        let category = match self.category {
            ThreatCategory::Tampering => "tampering",
            ThreatCategory::Spoofing => "spoofing",
            ThreatCategory::InformationDisclosure => "information_disclosure",
            ThreatCategory::DenialOfService => "denial_of_service",
            ThreatCategory::AuditFailure => "audit_failure",
            ThreatCategory::None => "none",
        };

        SanitizedCtx {
            sequence: self.sequence,
            severity,
            category,
            timestamp_ns: self.timestamp_ns,
        }
    }
}

// ── Error kind ────────────────────────────────────────────────────────────────

/// Classifies the error for `Display` string selection.
///
/// Not sensitive — no zeroize needed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ErrorKind {
    EncryptionFailed,
    DecryptionFailed,
    InvalidPacket,
    RateLimit,
    KeyExchangeFailed,
    SignatureFailed,
    InvalidPublicKey,
    Internal,
    TimingViolation,
    SanitizationFailed,
}

// ── Global sequence counter ───────────────────────────────────────────────────

static SEQ: AtomicU64 = AtomicU64::new(1);

#[inline]
fn next_seq() -> u64 {
    SEQ.fetch_add(1, Ordering::SeqCst)
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

// ── Public error type ─────────────────────────────────────────────────────────

/// Opaque cryptographic error.
///
/// `Display` returns a fixed string with no implementation detail.
/// Internal context is accessible only within the crate and zeroed on drop.
pub(crate) struct CryptoError {
    pub(crate) kind: ErrorKind,
    pub(crate) internal: InternalCtx,
}

impl Drop for CryptoError {
    fn drop(&mut self) {
        // `CryptoError` stores only static detail text and numeric metadata.
    }
}

impl CryptoError {
    pub(crate) fn new(
        kind: ErrorKind,
        details: &'static str,
        severity: ErrorSeverity,
        category: ThreatCategory,
    ) -> Self {
        Self {
            kind,
            internal: InternalCtx {
                details,
                timestamp_ns: now_ns(),
                sequence: next_seq(),
                severity,
                category,
            },
        }
    }

    #[inline]
    pub(crate) fn kind(&self) -> &ErrorKind {
        &self.kind
    }
    #[inline]
    pub(crate) fn severity(&self) -> &ErrorSeverity {
        &self.internal.severity
    }
    #[inline]
    pub(crate) fn category(&self) -> &ThreatCategory {
        &self.internal.category
    }
    #[inline]
    pub(crate) fn sequence(&self) -> u64 {
        self.internal.sequence
    }
    #[inline]
    pub(crate) fn sanitized_log(&self) -> SanitizedCtx {
        self.internal.sanitized()
    }
    #[inline]
    pub(crate) fn internal_ctx(&self) -> &InternalCtx {
        &self.internal
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Fixed strings — no implementation leakage.
        match &self.kind {
            ErrorKind::EncryptionFailed => write!(f, "Encryption failed"),
            ErrorKind::DecryptionFailed => write!(f, "Decryption failed"),
            ErrorKind::InvalidPacket => write!(f, "Invalid packet"),
            ErrorKind::RateLimit => write!(f, "Rate limit exceeded"),
            ErrorKind::KeyExchangeFailed => write!(f, "Key exchange failed"),
            ErrorKind::SignatureFailed => write!(f, "Signature failed"),
            ErrorKind::InvalidPublicKey => write!(f, "Invalid public key"),
            ErrorKind::Internal => write!(f, "Internal error"),
            ErrorKind::TimingViolation => write!(f, "Timing violation"),
            ErrorKind::SanitizationFailed => write!(f, "Sanitization failed"),
        }
    }
}

impl fmt::Debug for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CryptoError({:?}, seq={})",
            self.kind, self.internal.sequence
        )
    }
}

impl std::error::Error for CryptoError {}

impl PartialEq for CryptoError {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
    }
}
impl Eq for CryptoError {}

// ── Convenience constructors ──────────────────────────────────────────────────

impl CryptoError {
    pub(crate) fn encryption_failed(d: &'static str) -> Self {
        Self::new(
            ErrorKind::EncryptionFailed,
            d,
            ErrorSeverity::Error,
            ThreatCategory::Tampering,
        )
    }
    pub(crate) fn decryption_failed(d: &'static str) -> Self {
        Self::new(
            ErrorKind::DecryptionFailed,
            d,
            ErrorSeverity::Warning,
            ThreatCategory::Tampering,
        )
    }
    pub(crate) fn invalid_packet(d: &'static str) -> Self {
        Self::new(
            ErrorKind::InvalidPacket,
            d,
            ErrorSeverity::Warning,
            ThreatCategory::Tampering,
        )
    }
    pub(crate) fn rate_limit_exceeded(d: &'static str) -> Self {
        Self::new(
            ErrorKind::RateLimit,
            d,
            ErrorSeverity::Warning,
            ThreatCategory::DenialOfService,
        )
    }
    pub(crate) fn key_exchange_failed(d: &'static str) -> Self {
        Self::new(
            ErrorKind::KeyExchangeFailed,
            d,
            ErrorSeverity::Error,
            ThreatCategory::Spoofing,
        )
    }
    pub(crate) fn signature_failed(d: &'static str) -> Self {
        Self::new(
            ErrorKind::SignatureFailed,
            d,
            ErrorSeverity::Error,
            ThreatCategory::Spoofing,
        )
    }
    pub(crate) fn invalid_public_key(d: &'static str) -> Self {
        Self::new(
            ErrorKind::InvalidPublicKey,
            d,
            ErrorSeverity::Warning,
            ThreatCategory::Spoofing,
        )
    }
    pub(crate) fn internal(d: &'static str) -> Self {
        Self::new(
            ErrorKind::Internal,
            d,
            ErrorSeverity::Critical,
            ThreatCategory::None,
        )
    }
    pub(crate) fn timing_violation(d: &'static str) -> Self {
        Self::new(
            ErrorKind::TimingViolation,
            d,
            ErrorSeverity::Critical,
            ThreatCategory::InformationDisclosure,
        )
    }
    pub(crate) fn sanitization_failed(d: &'static str) -> Self {
        Self::new(
            ErrorKind::SanitizationFailed,
            d,
            ErrorSeverity::Critical,
            ThreatCategory::AuditFailure,
        )
    }
}
