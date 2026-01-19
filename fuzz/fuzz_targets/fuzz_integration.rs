//! Integration fuzzing for complete cryptographic workflows
//!
//! Tests:
//! - Full onion encryption/decryption cycles
//! - Key exchange followed by encrypted communication
//! - Signed and encrypted messages
//! - Combined PQC and symmetric operations

#![no_main]

use libfuzzer_sys::fuzz_target;
use veil_crypto::*;
use veil_crypto::pqc::*;

#[derive(arbitrary::Arbitrary, Debug)]
struct WorkflowInput<'a> {
    // Keys
    key1: [u8; 32],
    key2: [u8; 32],
    key3: [u8; 32],
    
    // Messages
    message1: &'a [u8],
    message2: &'a [u8],
    
    // Control flow
    use_three_layers: bool,
    perform_key_exchange: bool,
    sign_message: bool,
}

fuzz_target!(|input: WorkflowInput| {
    // Test 1: Onion encryption workflow
    if input.use_three_layers {
        if let Ok(encryptor) = OnionEncryptor::new(input.key1, input.key2, input.key3) {
            if !input.message1.is_empty() {
                if let Ok(encrypted) = encryptor.encrypt(input.message1) {
                    // Try to decrypt
                    let _ = OnionDecryptor::new(input.key1)
                        .and_then(|dec| dec.decrypt(&encrypted));
                }
            }
        }
    } else {
        // Single layer
        if let Ok(layer) = OnionLayer::from_key(input.key1) {
            if !input.message1.is_empty() {
                if let Ok(encrypted) = layer.encrypt(input.message1) {
                    let _ = layer.decrypt(&encrypted);
                }
            }
        }
    }
    
    // Test 2: Key exchange workflow
    if input.perform_key_exchange {
        if let Ok(alice) = HybridKeyExchange::new() {
            if let Ok(bob) = HybridKeyExchange::new() {
                // Try encapsulation with alice's or random data
                let pk = if input.use_three_layers {
                    bob.public_key()
                } else {
                    input.message2
                };
                
                if let Ok((ciphertext, _key)) = HybridKeyExchange::encapsulate(pk) {
                    // Try decapsulation
                    let _ = bob.decapsulate(&ciphertext);
                }
            }
        }
    }
    
    // Test 3: Signature workflow
    if input.sign_message && !input.message1.is_empty() {
        if let Ok(keypair) = SignatureKeypair::new() {
            if let Ok(signature) = keypair.sign(input.message1) {
                // Verify with correct key
                let _ = verify_signature(keypair.public_key(), input.message1, &signature);
                
                // Try verification with wrong message
                if !input.message2.is_empty() && input.message1 != input.message2 {
                    let _ = verify_signature(keypair.public_key(), input.message2, &signature);
                }
            }
        }
    }
    
    // Test 4: Combined workflow - encrypt then sign
    if input.use_three_layers && input.sign_message && !input.message1.is_empty() {
        // First encrypt
        if let Ok(encryptor) = OnionEncryptor::new(input.key1, input.key2, input.key3) {
            if let Ok(encrypted) = encryptor.encrypt(input.message1) {
                // Then sign the encrypted data
                if let Ok(keypair) = SignatureKeypair::new() {
                    let _ = keypair.sign(&encrypted);
                }
            }
        }
    }
});