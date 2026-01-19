//! Property-based tests for cryptographic invariants
//!
//! Uses proptest to verify properties hold across random inputs:
//! - Encryption/decryption roundtrips
//! - Constant-time operations
//! - Error consistency
//! - Audit logging invariants

use proptest::prelude::*;
use veil_crypto::*;
use veil_crypto::constant_time::*;

// ═══════════════════════════════════════════════════════════════════════════
// ONION ENCRYPTION PROPERTIES
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn prop_onion_encrypt_decrypt_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 0..1000),
        key1 in prop::array::uniform32(any::<u8>()),
        key2 in prop::array::uniform32(any::<u8>()),
        key3 in prop::array::uniform32(any::<u8>()),
    ) {
        let encryptor = OnionEncryptor::new(key1, key2, key3)?;
        let encrypted = encryptor.encrypt(&plaintext)?;
        
        // Decrypt through all layers
        let dec1 = OnionDecryptor::new(key1)?;
        let layer1 = dec1.decrypt(&encrypted)?;
        
        let dec2 = OnionDecryptor::new(key2)?;
        let layer2 = dec2.decrypt(&layer1)?;
        
        let dec3 = OnionDecryptor::new(key3)?;
        let decrypted = dec3.decrypt(&layer2)?;
        
        prop_assert_eq!(&decrypted[..], &plaintext[..]);
    }
    
    #[test]
    fn prop_single_layer_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 0..10000),
        key in prop::array::uniform32(any::<u8>()),
    ) {
        let layer = OnionLayer::from_key(key)?;
        let encrypted = layer.encrypt(&plaintext)?;
        let decrypted = layer.decrypt(&encrypted)?;
        
        prop_assert_eq!(&decrypted[..], &plaintext[..]);
    }
    
    #[test]
    fn prop_different_keys_different_ciphertext(
        plaintext in prop::collection::vec(any::<u8>(), 1..100),
        key1 in prop::array::uniform32(any::<u8>()),
        key2 in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(key1 != key2);
        
        let layer1 = OnionLayer::from_key(key1)?;
        let layer2 = OnionLayer::from_key(key2)?;
        
        let enc1 = layer1.encrypt(&plaintext)?;
        let enc2 = layer2.encrypt(&plaintext)?;
        
        // Different keys should produce different ciphertexts
        // (excluding the random nonce component)
        prop_assert_ne!(&enc1[..], &enc2[..]);
    }
    
    #[test]
    fn prop_ciphertext_larger_than_plaintext(
        plaintext in prop::collection::vec(any::<u8>(), 0..1000),
        key in prop::array::uniform32(any::<u8>()),
    ) {
        let layer = OnionLayer::from_key(key)?;
        let encrypted = layer.encrypt(&plaintext)?;
        
        // Ciphertext should be at least nonce + tag larger
        prop_assert!(encrypted.len() >= plaintext.len() + NONCE_SIZE + TAG_SIZE);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANT-TIME OPERATION PROPERTIES
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn prop_ct_eq_reflexive(data in prop::collection::vec(any::<u8>(), 0..1000)) {
        // Any data should equal itself
        prop_assert!(ct_eq(&data, &data));
    }
    
    #[test]
    fn prop_ct_eq_symmetric(
        data1 in prop::collection::vec(any::<u8>(), 0..500),
        data2 in prop::collection::vec(any::<u8>(), 0..500),
    ) {
        // If a == b, then b == a
        let result1 = ct_eq(&data1, &data2);
        let result2 = ct_eq(&data2, &data1);
        prop_assert_eq!(result1, result2);
    }
    
    #[test]
    fn prop_ct_eq_consistent_with_std(
        data1 in prop::collection::vec(any::<u8>(), 0..500),
        data2 in prop::collection::vec(any::<u8>(), 0..500),
    ) {
        // Constant-time equality should match standard equality
        let ct_result = ct_eq(&data1, &data2);
        let std_result = data1 == data2;
        prop_assert_eq!(ct_result, std_result);
    }
    
    #[test]
    fn prop_ct_less_than_antisymmetric(
        data1 in prop::collection::vec(any::<u8>(), 1..100),
        data2 in prop::collection::vec(any::<u8>(), 1..100),
    ) {
        // If a < b, then NOT (b < a)
        if ct_less_than(&data1, &data2) {
            prop_assert!(!ct_less_than(&data2, &data1));
        }
    }
    
    #[test]
    fn prop_ct_xor_involution(
        data1 in prop::collection::vec(any::<u8>(), 0..500),
        data2 in prop::collection::vec(any::<u8>(), 0..500),
    ) {
        let len = data1.len().min(data2.len());
        let mut result = vec![0u8; len];
        let mut double_xor = vec![0u8; len];
        
        // XOR twice should give original
        ct_xor(&data1[..len], &data2[..len], &mut result);
        ct_xor(&result, &data2[..len], &mut double_xor);
        
        prop_assert_eq!(&double_xor[..], &data1[..len]);
    }
    
    #[test]
    fn prop_ct_copy_if_conditional(
        src in prop::collection::vec(any::<u8>(), 10..100),
        dst_init in prop::collection::vec(any::<u8>(), 10..100),
        condition in any::<bool>(),
    ) {
        let len = src.len().min(dst_init.len());
        let mut dst = dst_init[..len].to_vec();
        let original_dst = dst.clone();
        
        ct_copy_if(condition, &src[..len], &mut dst);
        
        if condition {
            prop_assert_eq!(&dst[..], &src[..len]);
        } else {
            prop_assert_eq!(&dst[..], &original_dst[..]);
        }
    }
    
    #[test]
    fn prop_ct_mod_reduce_correct(value in 0u32..1000000, modulus in 1u32..10000) {
        let ct_result = ct_mod_reduce(value, modulus);
        let std_result = value % modulus;
        
        prop_assert_eq!(ct_result, std_result);
        prop_assert!(ct_result < modulus);
    }
    
    #[test]
    fn prop_ct_min_max_consistent(a in any::<u32>(), b in any::<u32>()) {
        let min_val = ct_min_u32(a, b);
        let max_val = ct_max_u32(a, b);
        
        // Min should be <= both values
        prop_assert!(min_val == a || min_val == b);
        prop_assert!(min_val <= a && min_val <= b);
        
        // Max should be >= both values
        prop_assert!(max_val == a || max_val == b);
        prop_assert!(max_val >= a && max_val >= b);
        
        // Min + Max should include both values
        prop_assert!(min_val <= max_val);
    }
    
    #[test]
    fn prop_ct_in_range_boundaries(
        value in any::<u32>(),
        min in any::<u32>(),
        max in any::<u32>(),
    ) {
        prop_assume!(min <= max);
        
        let in_range = ct_in_range(value, min, max);
        let expected = value >= min && value <= max;
        
        prop_assert_eq!(in_range, expected);
    }
    
    #[test]
    fn prop_ct_hamming_weight_correct(value in any::<u32>()) {
        let ct_weight = ct_hamming_weight(value);
        let std_weight = value.count_ones();
        
        prop_assert_eq!(ct_weight, std_weight);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ERROR SYSTEM PROPERTIES
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn prop_error_sequence_monotonic(
        details1 in ".*",
        details2 in ".*",
        details3 in ".*",
    ) {
        let err1 = CryptoError::encryption_failed(details1);
        let seq1 = err1.sequence();
        
        let err2 = CryptoError::decryption_failed(details2);
        let seq2 = err2.sequence();
        
        let err3 = CryptoError::signature_failed(details3);
        let seq3 = err3.sequence();
        
        // Sequences should be strictly increasing
        prop_assert!(seq2 > seq1);
        prop_assert!(seq3 > seq2);
    }
    
    #[test]
    fn prop_error_display_opaque(sensitive_data in ".*") {
        let err = CryptoError::encryption_failed(format!("Sensitive: {}", sensitive_data));
        
        let display = err.to_string();
        
        // External display should NEVER contain sensitive data
        if sensitive_data.len() > 3 {  // Ignore very short strings
            prop_assert!(!display.contains(&sensitive_data));
        }
        
        // Should only contain generic message
        prop_assert_eq!(display, "Encryption operation failed");
    }
    
    #[test]
    fn prop_sanitized_log_no_details(details in ".*") {
        let err = CryptoError::internal(details.clone());
        let sanitized = err.sanitized_log();
        
        // Sanitized log should not contain original details
        if details.len() > 5 {
            prop_assert!(!sanitized.contains(&details));
        }
        
        // But should contain metadata
        prop_assert!(sanitized.contains("seq="));
        prop_assert!(sanitized.contains("sev="));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AUDIT SYSTEM PROPERTIES
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn prop_audit_sequence_increases(
        operation in "encrypt|decrypt|sign|verify",
    ) {
        use std::sync::atomic::Ordering;
        use veil_crypto::audit::*;
        
        let seq1 = log_audit_event(
            AuditEvent::OperationSuccess,
            "test_op",
            &StrideCategory::NotApplicable,
            &ErrorSeverity::Info,
            format!("Operation: {}", operation),
        ).sequence;
        
        let seq2 = log_audit_event(
            AuditEvent::OperationSuccess,
            "test_op",
            &StrideCategory::NotApplicable,
            &ErrorSeverity::Info,
            format!("Operation: {}", operation),
        ).sequence;
        
        prop_assert!(seq2 > seq1);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// POST-QUANTUM CRYPTO PROPERTIES
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn prop_key_exchange_produces_same_shared_secret(
        _seed in any::<u8>(),  // Just to vary the test
    ) {
        use veil_crypto::pqc::HybridKeyExchange;
        
        let alice = HybridKeyExchange::new()?;
        let bob = HybridKeyExchange::new()?;
        
        let (ciphertext, alice_key) = HybridKeyExchange::encapsulate(bob.public_key())?;
        let bob_key = bob.decapsulate(&ciphertext)?;
        
        prop_assert_eq!(alice_key, bob_key);
        prop_assert_eq!(alice_key.len(), 64);
    }
    
    #[test]
    fn prop_signature_verification_soundness(
        message in prop::collection::vec(any::<u8>(), 0..1000),
        _seed in any::<u8>(),
    ) {
        use veil_crypto::pqc::{SignatureKeypair, verify_signature};
        
        let keypair = SignatureKeypair::new()?;
        let signature = keypair.sign(&message)?;
        
        // Valid signature should always verify
        let result = verify_signature(keypair.public_key(), &message, &signature);
        prop_assert!(result.is_ok());
    }
    
    #[test]
    fn prop_signature_different_keys_fail(
        message in prop::collection::vec(any::<u8>(), 1..1000),
        _seed in any::<u8>(),
    ) {
        use veil_crypto::pqc::{SignatureKeypair, verify_signature};
        
        let keypair1 = SignatureKeypair::new()?;
        let keypair2 = SignatureKeypair::new()?;
        
        let signature = keypair1.sign(&message)?;
        
        // Signature from keypair1 should NOT verify with keypair2's public key
        let result = verify_signature(keypair2.public_key(), &message, &signature);
        prop_assert!(result.is_err());
    }
}