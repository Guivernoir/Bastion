//! Fuzz post-quantum cryptography operations
//!
//! Tests:
//! - Invalid public key handling
//! - Malformed ciphertext decapsulation
//! - Signature verification with corrupted data

#![no_main]

use libfuzzer_sys::fuzz_target;
use veil_crypto::pqc::*;

fuzz_target!(|data: &[u8]| {
    // Test encapsulation with arbitrary "public key" data
    // Should gracefully reject invalid keys
    let _ = HybridKeyExchange::encapsulate(data);
    
    // If we have a valid keypair, test decapsulation with random ciphertext
    if let Ok(kex) = HybridKeyExchange::new() {
        let _ = kex.decapsulate(data);
        
        // Test public key verification with random data
        let _ = kex.verify_public_key(data);
    }
});