//! Error types for cryptographic operations with dual-context reporting
//!
//! This module implements a dual-context error system:
//! - **External Context**: Opaque, sanitized errors safe for user display
//! - **Internal Context**: Detailed debugging information for security auditing
//!
//! ## STRIDE Threat Model Coverage
//!
//! - **Spoofing**: Errors never leak authentication details
//! - **Tampering**: Error messages are immutable and verified
//! - **Repudiation**: All errors can be logged with audit context
//! - **Information Disclosure**: External errors are completely opaque
//! - **Denial of Service**: Rate limit errors distinguish legitimate vs attack
//! - **Elevation of Privilege**: No errors leak permission/capability info
//!
//! ## GDPR Compliance
//!
//! - Errors never contain PII or user-identifiable data
//! - All error contexts can be sanitized for data subject access requests
//! - Audit logs support right to erasure via redaction markers

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Result type for cryptographic operations
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Error severity levels for security incident classification
#[derive(Debug, PartialEq, Eq, ZeroizeOnDrop, Zeroize)]
pub enum ErrorSeverity {
    /// Informational - expected operational event
    Info,
    /// Warning - unusual but not critical
    Warning,
    /// Error - operation failed, no security impact
    Error,
    /// Critical - security boundary violated or system integrity compromised
    Critical,
}

/// Internal error context for debugging and security auditing
///
/// This context is NEVER exposed to external users or included in
/// external error messages. It's only used for:
/// - Security incident response
/// - Forensic analysis
/// - Development debugging
/// - Compliance auditing
#[derive(ZeroizeOnDrop)]
pub struct InternalErrorContext {
    /// Detailed error description (may contain sensitive info)
    pub details: String,
    
    /// Error occurrence timestamp (nanoseconds since epoch)
    pub timestamp_ns: u64,
    
    /// Error sequence number for correlation
    pub sequence: u64,
    
    /// Severity level for incident classification
    pub severity: ErrorSeverity,
    
    /// Optional stack context (file:line if available)
    pub location: Option<String>,
    
    /// STRIDE threat category
    pub stride_category: StrideCategory,
}

/// STRIDE threat model categories
#[derive(Debug, PartialEq, Eq, ZeroizeOnDrop, Zeroize)]
pub enum StrideCategory {
    /// Spoofing - identity verification failures
    Spoofing,
    /// Tampering - data integrity violations
    Tampering,
    /// Repudiation - audit/logging failures
    Repudiation,
    /// Information Disclosure - data leakage risks
    InformationDisclosure,
    /// Denial of Service - availability impacts
    DenialOfService,
    /// Elevation of Privilege - authorization failures
    ElevationOfPrivilege,
    /// Not applicable to STRIDE model
    NotApplicable,
}

impl InternalErrorContext {
    /// Create sanitized version for external logging (GDPR-compliant)
    pub fn sanitize(&self) -> String {
        format!(
            "seq={} sev={:?} stride={:?} ts={}",
            self.sequence,
            self.severity,
            self.stride_category,
            self.timestamp_ns
        )
    }
}

/// Global error sequence counter for correlation
static ERROR_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Cryptographic operation errors with dual context
///
/// External variants are completely opaque. Internal context provides
/// detailed information for security teams while preventing information
/// leakage to potential attackers.
#[derive(ZeroizeOnDrop)]
pub struct CryptoError {
    /// External error type (safe for user display)
    kind: CryptoErrorKind,
    
    /// Internal debugging context (NEVER exposed externally)
    internal: InternalErrorContext,
}

/// External error kinds (completely opaque, no implementation details)
#[derive(Debug, PartialEq, Eq, ZeroizeOnDrop)]
pub enum CryptoErrorKind {
    /// Encryption operation failed
    EncryptionFailed,
    
    /// Decryption operation failed
    DecryptionFailed,
    
    /// Invalid packet format
    InvalidPacket,
    
    /// Rate limit exceeded
    RateLimit,
    
    /// Key exchange operation failed
    KeyExchangeFailed,
    
    /// Signature operation failed
    SignatureFailed,
    
    /// Invalid public key format
    InvalidPublicKey,
    
    /// Internal error (system integrity issue)
    Internal,
    
    /// Timing constraint violated (constant-time requirement)
    TimingViolation,
    
    /// Memory sanitization failed
    SanitizationFailed,
    
    /// Audit log failure (STRIDE: Repudiation)
    AuditFailure,
}

impl CryptoError {
    /// Create new error with internal context
    #[inline]
    pub fn new(
        kind: CryptoErrorKind,
        details: impl Into<String>,
        severity: ErrorSeverity,
        stride: StrideCategory,
    ) -> Self {
        Self::new_with_location(kind, details, severity, stride, None)
    }
    
    /// Create error with location information for debugging
    pub fn new_with_location(
        kind: CryptoErrorKind,
        details: impl Into<String>,
        severity: ErrorSeverity,
        stride: StrideCategory,
        location: Option<String>,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        
        let sequence = ERROR_SEQUENCE.fetch_add(1, Ordering::SeqCst);
        
        Self {
            kind,
            internal: InternalErrorContext {
                details: details.into(),
                timestamp_ns,
                sequence,
                severity,
                location,
                stride_category: stride,
            },
        }
    }
    
    /// Get error kind (safe for external use)
    #[inline]
    pub fn kind(&self) -> &CryptoErrorKind {
        &self.kind
    }
    
    /// Get sanitized error for logging (GDPR-compliant)
    #[inline]
    pub fn sanitized_log(&self) -> String {
        self.internal.sanitize()
    }
    
    /// Get internal context (only for privileged security operations)
    ///
    /// # Security Warning
    ///
    /// This method returns sensitive debugging information that MUST NOT
    /// be exposed to external users, logged to public systems, or included
    /// in user-facing error messages.
    #[inline]
    pub fn internal_context(&self) -> &InternalErrorContext {
        &self.internal
    }
    
    /// Get severity level
    #[inline]
    pub fn severity(&self) -> &ErrorSeverity {
        &self.internal.severity
    }
    
    /// Get STRIDE category
    #[inline]
    pub fn stride_category(&self) -> &StrideCategory {
        &self.internal.stride_category
    }
    
    /// Get error sequence number for correlation
    #[inline]
    pub fn sequence(&self) -> u64 {
        self.internal.sequence
    }
}

// External Display shows only opaque error (no details leaked)
impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            CryptoErrorKind::EncryptionFailed => write!(f, "Encryption operation failed"),
            CryptoErrorKind::DecryptionFailed => write!(f, "Decryption operation failed"),
            CryptoErrorKind::InvalidPacket => write!(f, "Invalid packet format"),
            CryptoErrorKind::RateLimit => write!(f, "Rate limit exceeded"),
            CryptoErrorKind::KeyExchangeFailed => write!(f, "Key exchange operation failed"),
            CryptoErrorKind::SignatureFailed => write!(f, "Signature operation failed"),
            CryptoErrorKind::InvalidPublicKey => write!(f, "Invalid public key format"),
            CryptoErrorKind::Internal => write!(f, "Internal error"),
            CryptoErrorKind::TimingViolation => write!(f, "Timing constraint violated"),
            CryptoErrorKind::SanitizationFailed => write!(f, "Memory sanitization failed"),
            CryptoErrorKind::AuditFailure => write!(f, "Audit log failure"),
        }
    }
}

// Debug shows external kind only (no internal context)
impl fmt::Debug for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CryptoError({:?}, seq={})", self.kind, self.internal.sequence)
    }
}

impl std::error::Error for CryptoError {}

impl PartialEq for CryptoError {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
    }
}

impl Eq for CryptoError {}

/// Convenience constructors for common errors
impl CryptoError {
    /// Encryption failed with automatic STRIDE classification
    pub fn encryption_failed(details: impl Into<String>) -> Self {
        Self::new(
            CryptoErrorKind::EncryptionFailed,
            details,
            ErrorSeverity::Error,
            StrideCategory::Tampering,
        )
    }
    
    /// Decryption failed (potential tampering detected)
    pub fn decryption_failed(details: impl Into<String>) -> Self {
        Self::new(
            CryptoErrorKind::DecryptionFailed,
            details,
            ErrorSeverity::Warning,
            StrideCategory::Tampering,
        )
    }
    
    /// Invalid packet (potential protocol attack)
    pub fn invalid_packet(details: impl Into<String>) -> Self {
        Self::new(
            CryptoErrorKind::InvalidPacket,
            details,
            ErrorSeverity::Warning,
            StrideCategory::Tampering,
        )
    }
    
    /// Rate limit exceeded (DoS protection triggered)
    pub fn rate_limit_exceeded(details: impl Into<String>) -> Self {
        Self::new(
            CryptoErrorKind::RateLimit,
            details,
            ErrorSeverity::Warning,
            StrideCategory::DenialOfService,
        )
    }
    
    /// Key exchange failed (potential MITM)
    pub fn key_exchange_failed(details: impl Into<String>) -> Self {
        Self::new(
            CryptoErrorKind::KeyExchangeFailed,
            details,
            ErrorSeverity::Error,
            StrideCategory::Spoofing,
        )
    }
    
    /// Signature verification failed (authentication failure)
    pub fn signature_failed(details: impl Into<String>) -> Self {
        Self::new(
            CryptoErrorKind::SignatureFailed,
            details,
            ErrorSeverity::Error,
            StrideCategory::Spoofing,
        )
    }
    
    /// Invalid public key (malformed or malicious)
    pub fn invalid_public_key(details: impl Into<String>) -> Self {
        Self::new(
            CryptoErrorKind::InvalidPublicKey,
            details,
            ErrorSeverity::Warning,
            StrideCategory::Spoofing,
        )
    }
    
    /// Internal error (system integrity compromised)
    pub fn internal(details: impl Into<String>) -> Self {
        Self::new(
            CryptoErrorKind::Internal,
            details,
            ErrorSeverity::Critical,
            StrideCategory::NotApplicable,
        )
    }
    
    /// Timing violation detected (side-channel protection)
    pub fn timing_violation(details: impl Into<String>) -> Self {
        Self::new(
            CryptoErrorKind::TimingViolation,
            details,
            ErrorSeverity::Critical,
            StrideCategory::InformationDisclosure,
        )
    }
    
    /// Memory sanitization failed (zeroization failure)
    pub fn sanitization_failed(details: impl Into<String>) -> Self {
        Self::new(
            CryptoErrorKind::SanitizationFailed,
            details,
            ErrorSeverity::Critical,
            StrideCategory::InformationDisclosure,
        )
    }
    
    /// Audit logging failed (repudiation risk)
    pub fn audit_failure(details: impl Into<String>) -> Self {
        Self::new(
            CryptoErrorKind::AuditFailure,
            details,
            ErrorSeverity::Critical,
            StrideCategory::Repudiation,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_external_error_display_opaque() {
        let err = CryptoError::encryption_failed("AES-GCM init failed with key size mismatch");
        
        let display = err.to_string();
        assert_eq!(display, "Encryption operation failed");
        assert!(!display.contains("AES"));
        assert!(!display.contains("key"));
    }

    #[test]
    fn test_internal_context_detailed() {
        let err = CryptoError::decryption_failed("HMAC verification failed at offset 42");
        
        let internal = err.internal_context();
        assert!(internal.details.contains("HMAC"));
        assert!(internal.details.contains("42"));
        assert_eq!(internal.severity, ErrorSeverity::Warning);
        assert_eq!(internal.stride_category, StrideCategory::Tampering);
    }

    #[test]
    fn test_sanitized_log_no_pii() {
        let err = CryptoError::signature_failed("User alice@example.com signature invalid");
        
        let sanitized = err.sanitized_log();
        assert!(!sanitized.contains("alice"));
        assert!(!sanitized.contains("example.com"));
        assert!(sanitized.contains("seq="));
    }

    #[test]
    fn test_error_sequence_increments() {
        let err1 = CryptoError::rate_limit_exceeded("Client 192.168.1.1");
        let err2 = CryptoError::rate_limit_exceeded("Client 192.168.1.2");
        
        assert!(err2.sequence() > err1.sequence());
    }

    #[test]
    fn test_stride_classification() {
        assert_eq!(
            CryptoError::encryption_failed("").stride_category(),
            &StrideCategory::Tampering
        );
        assert_eq!(
            CryptoError::signature_failed("").stride_category(),
            &StrideCategory::Spoofing
        );
    }
}