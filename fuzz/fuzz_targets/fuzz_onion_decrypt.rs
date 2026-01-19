//! Fuzz testing harnesses for Veil Crypto
//!
//! Fuzzing focuses on:
//! - Malformed packet inputs (decryption)
//! - Invalid public keys
//! - Boundary conditions in constant-time operations
//! - Error handling robustness
//! - Memory safety invariants

#![no_main]

use libfuzzer_sys::fuzz_target;
use veil_crypto::*;

// ═══════════════════════════════════════════════════════════════════════════
// ONION LAYER DECRYPTION FUZZING
// ═══════════════════════════════════════════════════════════════════════════

fuzz_target!(|data: &[u8]| {
    // Fuzz decryption with arbitrary malformed packets
    // This tests:
    // - Packet size validation
    // - Authentication tag verification
    // - Memory bounds checking
    // - Error handling robustness
    
    let key = [0x42u8; 32];
    
    if let Ok(layer) = OnionLayer::from_key(key) {
        let _ = layer.decrypt(data);
        // Should never panic, always return Result
    }
});