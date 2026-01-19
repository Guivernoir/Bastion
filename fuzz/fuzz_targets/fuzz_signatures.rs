//! Fuzz digital signature operations
//!
//! Tests:
//! - Signature verification with malformed signatures
//! - Public key validation
//! - Message tampering detection

#![no_main]

use libfuzzer_sys::fuzz_target;
use veil_crypto::pqc::*;

#[derive(arbitrary::Arbitrary, Debug)]
struct SignatureInput<'a> {
    public_key: &'a [u8],
    message: &'a [u8],
    signature: &'a [u8],
}

fuzz_target!(|input: SignatureInput| {
    // Test signature verification with arbitrary inputs
    // Should never panic, only return error for invalid signatures
    let _ = verify_signature(input.public_key, input.message, input.signature);
    
    // Test batch verification with mixed valid/invalid signatures
    let verifications = vec![
        (input.public_key, input.message, input.signature),
    ];
    
    let _ = verify_signatures_batch(&verifications);
});