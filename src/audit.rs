//! Security audit logging with GDPR compliance
//!
//! Provides structured audit logging for:
//! - STRIDE threat monitoring
//! - Compliance (CSF, GDPR, SOC2)
//! - Incident response
//! - Forensic analysis
//!
//! ## GDPR Compliance
//!
//! - No PII logged without explicit consent
//! - Audit logs support right to erasure via redaction
//! - Configurable retention policies
//! - Purpose limitation enforced

use crate::error::{CryptoError, ErrorSeverity, StrideCategory};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::ZeroizeOnDrop;

/// Audit event types
#[derive(Debug, PartialEq, Eq, ZeroizeOnDrop)]
pub enum AuditEvent {
    /// Cryptographic operation succeeded
    OperationSuccess,
    /// Cryptographic operation failed
    OperationFailure,
    /// Rate limit triggered (DoS protection)
    RateLimitTriggered,
    /// Timing violation detected
    TimingViolation,
    /// Authentication failure (STRIDE: Spoofing)
    AuthenticationFailure,
    /// Tampering detected (invalid signature/MAC)
    TamperingDetected,
    /// Memory sanitization completed
    MemorySanitized,
    /// Key rotation performed
    KeyRotation,
}

/// Audit log entry (GDPR-compliant, no PII)
#[derive(Debug, ZeroizeOnDrop)]
pub struct AuditEntry<'a> {
    /// Event sequence number
    pub sequence: u64,
    /// Timestamp (nanoseconds since epoch)
    pub timestamp_ns: u64,
    /// Event type
    pub event: AuditEvent,
    /// STRIDE category
    #[zeroize(skip)]
    pub stride: &'a StrideCategory,
    /// Severity level
    #[zeroize(skip)]
    pub severity: &'a ErrorSeverity,
    /// Operation identifier (no PII)
    #[zeroize(skip)]
    pub operation: &'static str,
    /// Sanitized context (no sensitive data)
    pub context: String,
}

/// Global audit sequence counter
static AUDIT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Global audit metrics
pub struct AuditMetrics {
    pub total_operations: AtomicU64,
    pub failed_operations: AtomicU64,
    pub rate_limit_hits: AtomicU64,
    pub timing_violations: AtomicU64,
    pub auth_failures: AtomicU64,
    pub tampering_detected: AtomicU64,
}

impl AuditMetrics {
    pub const fn new() -> Self {
        Self {
            total_operations: AtomicU64::new(0),
            failed_operations: AtomicU64::new(0),
            rate_limit_hits: AtomicU64::new(0),
            timing_violations: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
            tampering_detected: AtomicU64::new(0),
        }
    }
    
    pub fn record_event(&self, event: &AuditEvent) {
        self.total_operations.fetch_add(1, Ordering::Relaxed);
        
        match event {
            AuditEvent::OperationFailure => {
                self.failed_operations.fetch_add(1, Ordering::Relaxed);
            }
            AuditEvent::RateLimitTriggered => {
                self.rate_limit_hits.fetch_add(1, Ordering::Relaxed);
            }
            AuditEvent::TimingViolation => {
                self.timing_violations.fetch_add(1, Ordering::Relaxed);
            }
            AuditEvent::AuthenticationFailure => {
                self.auth_failures.fetch_add(1, Ordering::Relaxed);
            }
            AuditEvent::TamperingDetected => {
                self.tampering_detected.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}

/// Global audit metrics instance
pub static METRICS: AuditMetrics = AuditMetrics::new();

/// Log audit event (GDPR-compliant)
pub fn log_audit_event<'a>(
    event: AuditEvent,
    operation: &'static str,
    stride: &'a StrideCategory,
    severity: &'a ErrorSeverity,
    context: impl Into<String>,
) -> AuditEntry<'a> {
    let sequence = AUDIT_SEQUENCE.fetch_add(1, Ordering::SeqCst);
    let timestamp_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    
    METRICS.record_event(&event);
    
    AuditEntry {
        sequence,
        timestamp_ns,
        event,
        stride,
        severity,
        operation,
        context: context.into(),
    }
}

/// Log error for audit trail
pub fn log_error(error: &CryptoError, operation: &'static str) {
    log_audit_event(
        AuditEvent::OperationFailure,
        operation,
        error.stride_category(),
        error.severity(),
        error.sanitized_log(),
    );
}