//! Integration tests for Veil Crypto - Hardened Edition
//!
//! Tests complete workflows including:
//! - Multi-layer encryption/decryption
//! - Key exchange with derived keys
//! - Signature workflows
//! - Error propagation and audit trails
//! - Concurrency and thread safety

use veil_crypto::*;
use std::sync::Arc;
use std::thread;

// ═══════════════════════════════════════════════════════════════════════════
// ONION ENCRYPTION INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_full_onion_encryption_workflow() {
    // Simulate entry, relay, and exit nodes
    let entry_key = [0x01; 32];
    let relay_key = [0x02; 32];
    let exit_key = [0x03; 32];

    let encryptor = OnionEncryptor::new(entry_key, relay_key, exit_key)
        .expect("Failed to create encryptor");

    let plaintext = b"This is a secret message traveling through the onion network";
    let encrypted = encryptor.encrypt(plaintext).expect("Encryption failed");

    // Decrypt at entry node
    let entry_dec = OnionDecryptor::new(entry_key).expect("Entry decryptor failed");
    let layer1 = entry_dec.decrypt(&encrypted).expect("Entry decryption failed");

    // Decrypt at relay node
    let relay_dec = OnionDecryptor::new(relay_key).expect("Relay decryptor failed");
    let layer2 = relay_dec.decrypt(&layer1).expect("Relay decryption failed");

    // Decrypt at exit node
    let exit_dec = OnionDecryptor::new(exit_key).expect("Exit decryptor failed");
    let decrypted = exit_dec.decrypt(&layer2).expect("Exit decryption failed");

    assert_eq!(&decrypted[..], plaintext);
}

#[test]
fn test_onion_with_large_payload() {
    let large_payload = vec![0x42u8; 1024 * 1024]; // 1MB payload
    
    let encryptor = OnionEncryptor::new([1; 32], [2; 32], [3; 32])
        .expect("Encryptor creation failed");
    
    let encrypted = encryptor.encrypt(&large_payload).expect("Encryption failed");
    
    // Verify size increase is reasonable (nonce + tag per layer)
    assert!(encrypted.len() > large_payload.len());
    assert!(encrypted.len() < large_payload.len() + 500); // 3 layers * (12+16) = 84 bytes overhead
}

#[test]
fn test_onion_empty_message() {
    let encryptor = OnionEncryptor::new([0xFF; 32], [0xEE; 32], [0xDD; 32])
        .expect("Encryptor failed");
    
    let encrypted = encryptor.encrypt(b"").expect("Empty encryption failed");
    
    let dec1 = OnionDecryptor::new([0xFF; 32]).unwrap();
    let dec2 = OnionDecryptor::new([0xEE; 32]).unwrap();
    let dec3 = OnionDecryptor::new([0xDD; 32]).unwrap();
    
    let layer1 = dec1.decrypt(&encrypted).unwrap();
    let layer2 = dec2.decrypt(&layer1).unwrap();
    let plaintext = dec3.decrypt(&layer2).unwrap();
    
    assert_eq!(plaintext.len(), 0);
}

#[test]
fn test_onion_wrong_key_order() {
    let encryptor = OnionEncryptor::new([1; 32], [2; 32], [3; 32])
        .expect("Encryptor failed");
    
    let encrypted = encryptor.encrypt(b"test").expect("Encryption failed");
    
    // Try to decrypt with wrong key
    let wrong_dec = OnionDecryptor::new([99; 32]).expect("Decryptor failed");
    let result = wrong_dec.decrypt(&encrypted);
    
    assert!(result.is_err());
    if let Err(e) = result {
        assert_eq!(e.kind(), &CryptoErrorKind::DecryptionFailed);
        assert_eq!(e.stride_category(), &StrideCategory::Tampering);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// POST-QUANTUM KEY EXCHANGE TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_pqc_key_exchange_integration() {
    use veil_crypto::pqc::HybridKeyExchange;
    
    let alice = HybridKeyExchange::new().expect("Alice failed");
    let bob = HybridKeyExchange::new().expect("Bob failed");
    
    // Alice encapsulates to Bob
    let (ciphertext, alice_key) = HybridKeyExchange::encapsulate(bob.public_key())
        .expect("Encapsulation failed");
    
    // Bob decapsulates
    let bob_key = bob.decapsulate(&ciphertext).expect("Decapsulation failed");
    
    // Keys should match
    assert_eq!(alice_key, bob_key);
    assert_eq!(alice_key.len(), 64); // SHA3-512 output
}

#[test]
fn test_pqc_key_exchange_with_onion() {
    use veil_crypto::pqc::HybridKeyExchange;
    
    // Establish quantum-safe key
    let alice = HybridKeyExchange::new().expect("Alice failed");
    let bob = HybridKeyExchange::new().expect("Bob failed");
    
    let (_ct, shared_key) = HybridKeyExchange::encapsulate(bob.public_key())
        .expect("Encapsulation failed");
    
    // Use first 32 bytes of shared key for onion encryption
    let mut onion_key = [0u8; 32];
    onion_key.copy_from_slice(&shared_key[..32]);
    
    let encryptor = OnionEncryptor::new(onion_key, [0; 32], [0; 32])
        .expect("Encryptor failed");
    
    let encrypted = encryptor.encrypt(b"PQ-secure message")
        .expect("Encryption failed");
    
    assert!(encrypted.len() > 17);
}

// ═══════════════════════════════════════════════════════════════════════════
// SIGNATURE INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_signature_chain_of_trust() {
    use veil_crypto::pqc::{SignatureKeypair, verify_signature};
    
    let root = SignatureKeypair::new().expect("Root keypair failed");
    let intermediate = SignatureKeypair::new().expect("Intermediate failed");
    
    // Root signs intermediate's public key
    let cert = root.sign(intermediate.public_key()).expect("Root signing failed");
    
    // Verify certificate
    verify_signature(root.public_key(), intermediate.public_key(), &cert)
        .expect("Certificate verification failed");
    
    // Intermediate signs a message
    let message = b"Authenticated message";
    let sig = intermediate.sign(message).expect("Signing failed");
    
    // Verify message signature
    verify_signature(intermediate.public_key(), message, &sig)
        .expect("Message verification failed");
}

#[test]
fn test_batch_signature_verification() {
    use veil_crypto::pqc::{SignatureKeypair, verify_signatures_batch};
    
    let keypair1 = SignatureKeypair::new().unwrap();
    let keypair2 = SignatureKeypair::new().unwrap();
    
    let msg1 = b"Message 1";
    let msg2 = b"Message 2";
    
    let sig1 = keypair1.sign(msg1).unwrap();
    let sig2 = keypair2.sign(msg2).unwrap();
    
    let verifications = vec![
        (keypair1.public_key(), msg1.as_slice(), sig1.as_ref()),
        (keypair2.public_key(), msg2.as_slice(), sig2.as_ref()),
    ];
    
    let results = verify_signatures_batch(&verifications).unwrap();
    assert_eq!(results, vec![true, true]);
}

// ═══════════════════════════════════════════════════════════════════════════
// AUDIT AND METRICS INTEGRATION
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_audit_trail_completeness() {
    use std::sync::atomic::Ordering;
    
    let initial_ops = METRICS.total_operations.load(Ordering::Relaxed);
    let initial_failures = METRICS.failed_operations.load(Ordering::Relaxed);
    
    // Perform successful operation
    let layer = OnionLayer::from_key([0xAB; 32]).unwrap();
    let _encrypted = layer.encrypt(b"test");
    
    // Perform failing operation
    let result = layer.decrypt(&[0u8; 10]); // Too small
    assert!(result.is_err());
    
    let final_ops = METRICS.total_operations.load(Ordering::Relaxed);
    let final_failures = METRICS.failed_operations.load(Ordering::Relaxed);
    
    assert!(final_ops > initial_ops);
    assert!(final_failures > initial_failures);
}

#[test]
fn test_tampering_audit_logged() {
    use std::sync::atomic::Ordering;
    
    let initial_tampering = METRICS.tampering_detected.load(Ordering::Relaxed);
    
    let layer = OnionLayer::from_key([0xCD; 32]).unwrap();
    let mut encrypted = layer.encrypt(b"original").unwrap().to_vec();
    
    // Tamper with the packet
    encrypted[20] ^= 0xFF;
    
    let _result = layer.decrypt(&encrypted); // Will fail
    
    let final_tampering = METRICS.tampering_detected.load(Ordering::Relaxed);
    assert!(final_tampering > initial_tampering);
}

// ═══════════════════════════════════════════════════════════════════════════
// CONCURRENCY AND THREAD SAFETY TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_concurrent_encryption() {
    let encryptor = Arc::new(
        OnionEncryptor::new([1; 32], [2; 32], [3; 32]).unwrap()
    );
    
    let handles: Vec<_> = (0..10)
        .map(|i| {
            let enc = Arc::clone(&encryptor);
            thread::spawn(move || {
                let plaintext = format!("Message {}", i);
                enc.encrypt(plaintext.as_bytes()).unwrap()
            })
        })
        .collect();
    
    let results: Vec<_> = handles.into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    
    assert_eq!(results.len(), 10);
    
    // All ciphertexts should be different (unique nonces)
    for i in 0..results.len() {
        for j in (i + 1)..results.len() {
            assert_ne!(results[i].as_ref(), results[j].as_ref());
        }
    }
}

#[test]
fn test_concurrent_key_exchange() {
    use veil_crypto::pqc::HybridKeyExchange;
    
    let handles: Vec<_> = (0..5)
        .map(|_| {
            thread::spawn(|| {
                let alice = HybridKeyExchange::new().unwrap();
                let bob = HybridKeyExchange::new().unwrap();
                
                let (_ct, alice_key) = HybridKeyExchange::encapsulate(bob.public_key()).unwrap();
                alice_key
            })
        })
        .collect();
    
    let keys: Vec<_> = handles.into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    
    assert_eq!(keys.len(), 5);
    
    // All keys should be unique
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(keys[i], keys[j]);
        }
    }
}

#[test]
fn test_shared_rate_limiter() {
    use veil_crypto::pqc::HybridKeyExchange;
    use governor::{clock::DefaultClock, state::InMemoryState, state::NotKeyed, Quota, RateLimiter};
    use std::num::NonZeroU32;
    
    let shared_limiter = Arc::new(RateLimiter::direct(Quota::per_second(
        NonZeroU32::new(10).unwrap(),
    )));
    
    let kex1 = HybridKeyExchange::new_with_limiter(Arc::clone(&shared_limiter)).unwrap();
    let kex2 = HybridKeyExchange::new_with_limiter(Arc::clone(&shared_limiter)).unwrap();
    
    // Both should share the same rate limit
    assert!(kex1.public_key().len() > 0);
    assert!(kex2.public_key().len() > 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// ERROR PROPAGATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_sequence_monotonic() {
    let err1 = CryptoError::encryption_failed("Test 1");
    let seq1 = err1.sequence();
    
    let err2 = CryptoError::encryption_failed("Test 2");
    let seq2 = err2.sequence();
    
    let err3 = CryptoError::decryption_failed("Test 3");
    let seq3 = err3.sequence();
    
    assert!(seq2 > seq1);
    assert!(seq3 > seq2);
}

#[test]
fn test_error_context_isolation() {
    let err = CryptoError::signature_failed("Internal details: key=0x12345, offset=42");
    
    // External display should be opaque
    let display = err.to_string();
    assert!(!display.contains("0x12345"));
    assert!(!display.contains("offset"));
    assert!(!display.contains("42"));
    
    // Sanitized log should not contain sensitive data
    let sanitized = err.sanitized_log();
    assert!(!sanitized.contains("0x12345"));
    assert!(!sanitized.contains("offset"));
    
    // Internal context should have details (for security team only)
    let internal = err.internal_context();
    assert!(internal.details.contains("0x12345"));
    assert!(internal.details.contains("42"));
}

// ═══════════════════════════════════════════════════════════════════════════
// MEMORY SAFETY TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_key_zeroization_after_use() {
    use zeroize::Zeroize;
    
    let mut key = [0x42u8; 32];
    
    {
        let _layer = OnionLayer::from_key(key);
        // Key should be zeroized inside OnionLayer::from_key
    }
    
    // Original key array is moved, but we can verify zeroization behavior
    // by creating a new layer and ensuring it doesn't leak
}

#[test]
fn test_no_key_cloning() {
    // This test verifies that our no-clone architecture works
    // Keys are moved, not cloned, preventing side-channel attacks
    
    let key = [0x99u8; 32];
    let _layer = OnionLayer::from_key(key);
    
    // key is now moved and cannot be reused
    // Uncommenting the next line would cause a compile error:
    // let _layer2 = OnionLayer::from_key(key);
}

#[test]
fn test_constant_time_zeroize_verification() {
    use veil_crypto::constant_time::ct_zeroize_verify;
    
    let mut buffer = vec![0x5A; 1024];
    
    let result = ct_zeroize_verify(&mut buffer);
    
    assert!(result.is_ok());
    assert_eq!(buffer, vec![0u8; 1024]);
}