//! Unit tests for constant-time operations module
//!
//! Tests focus on:
//! - Correctness of constant-time primitives
//! - Timing violation detection
//! - Edge cases (empty buffers, maximum values)
//! - Memory safety

use veil_crypto::constant_time::*;
use veil_crypto::error::CryptoErrorKind;

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANT-TIME EQUALITY TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_ct_eq_empty_buffers() {
    assert!(ct_eq(b"", b""));
}

#[test]
fn test_ct_eq_single_byte() {
    assert!(ct_eq(b"a", b"a"));
    assert!(!ct_eq(b"a", b"b"));
}

#[test]
fn test_ct_eq_all_zeros() {
    let zeros1 = vec![0u8; 1000];
    let zeros2 = vec![0u8; 1000];
    assert!(ct_eq(&zeros1, &zeros2));
}

#[test]
fn test_ct_eq_all_ones() {
    let ones1 = vec![0xFFu8; 1000];
    let ones2 = vec![0xFFu8; 1000];
    assert!(ct_eq(&ones1, &ones2));
}

#[test]
fn test_ct_eq_one_bit_difference() {
    let mut buf1 = vec![0x00u8; 100];
    let mut buf2 = vec![0x00u8; 100];
    
    buf2[50] = 0x01; // Single bit difference
    
    assert!(!ct_eq(&buf1, &buf2));
}

#[test]
fn test_ct_eq_last_byte_differs() {
    let mut buf1 = vec![0xAAu8; 100];
    let mut buf2 = vec![0xAAu8; 100];
    
    *buf2.last_mut().unwrap() = 0xBB;
    
    assert!(!ct_eq(&buf1, &buf2));
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANT-TIME COMPARISON TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_ct_less_than_basic() {
    assert!(ct_less_than(b"apple", b"banana"));
    assert!(!ct_less_than(b"banana", b"apple"));
    assert!(!ct_less_than(b"same", b"same"));
}

#[test]
fn test_ct_less_than_empty() {
    assert!(!ct_less_than(b"", b""));
    assert!(ct_less_than(b"", b"nonempty"));
    assert!(!ct_less_than(b"nonempty", b""));
}

#[test]
fn test_ct_less_than_prefix() {
    assert!(ct_less_than(b"abc", b"abcd"));
    assert!(!ct_less_than(b"abcd", b"abc"));
}

#[test]
fn test_ct_less_than_numerical_bytes() {
    let num1 = [0x00, 0x00, 0x01];
    let num2 = [0x00, 0x00, 0x02];
    let num3 = [0x00, 0x01, 0x00];
    
    assert!(ct_less_than(&num1, &num2));
    assert!(ct_less_than(&num1, &num3));
    assert!(ct_less_than(&num2, &num3));
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANT-TIME XOR TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_ct_xor_basic() {
    let a = [0xF0u8; 16];
    let b = [0x0Fu8; 16];
    let mut result = [0u8; 16];
    
    ct_xor(&a, &b, &mut result);
    
    assert_eq!(result, [0xFFu8; 16]);
}

#[test]
fn test_ct_xor_identity() {
    let data = [0xAAu8; 32];
    let zeros = [0x00u8; 32];
    let mut result = [0u8; 32];
    
    ct_xor(&data, &zeros, &mut result);
    
    assert_eq!(result, data);
}

#[test]
fn test_ct_xor_self_is_zero() {
    let data = [0x42u8; 64];
    let mut result = [0u8; 64];
    
    ct_xor(&data, &data, &mut result);
    
    assert_eq!(result, [0x00u8; 64]);
}

#[test]
fn test_ct_xor_different_lengths() {
    let a = [0xFFu8; 100];
    let b = [0x00u8; 50];
    let mut result = [0xAAu8; 100];
    
    ct_xor(&a, &b, &mut result);
    
    // Only first 50 bytes should be XORed
    assert_eq!(&result[..50], &[0xFFu8; 50]);
    // Remaining bytes should be unchanged
    assert_eq!(&result[50..], &[0xAAu8; 50]);
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANT-TIME CONDITIONAL OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_ct_copy_if_true_overwrites() {
    let src = [1, 2, 3, 4, 5];
    let mut dst = [0, 0, 0, 0, 0];
    
    ct_copy_if(true, &src, &mut dst);
    
    assert_eq!(dst, [1, 2, 3, 4, 5]);
}

#[test]
fn test_ct_copy_if_false_preserves() {
    let src = [1, 2, 3, 4, 5];
    let mut dst = [9, 9, 9, 9, 9];
    
    ct_copy_if(false, &src, &mut dst);
    
    assert_eq!(dst, [9, 9, 9, 9, 9]);
}

#[test]
fn test_ct_copy_if_partial() {
    let src = [1, 2, 3];
    let mut dst = [0, 0, 0, 0, 0];
    
    ct_copy_if(true, &src, &mut dst);
    
    assert_eq!(&dst[..3], &[1, 2, 3]);
    assert_eq!(&dst[3..], &[0, 0]);
}

#[test]
fn test_ct_select_chooses_correctly() {
    let opt_a = b"option A";
    let opt_b = b"option B";
    
    let selected_true = ct_select(true, opt_a, opt_b);
    let selected_false = ct_select(false, opt_a, opt_b);
    
    assert_eq!(selected_true, opt_a);
    assert_eq!(selected_false, opt_b);
}

// ═══════════════════════════════════════════════════════════════════════════
// ZEROIZATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_ct_zeroize_verify_success() {
    let mut data = vec![0x42u8; 1024];
    
    let result = ct_zeroize_verify(&mut data);
    
    assert!(result.is_ok());
    assert_eq!(data, vec![0u8; 1024]);
}

#[test]
fn test_ct_zeroize_verify_empty() {
    let mut empty: Vec<u8> = vec![];
    
    let result = ct_zeroize_verify(&mut empty);
    
    assert!(result.is_ok());
}

#[test]
fn test_ct_zeroize_verify_large_buffer() {
    let mut large = vec![0xFFu8; 1024 * 1024]; // 1MB
    
    let result = ct_zeroize_verify(&mut large);
    
    assert!(result.is_ok());
    assert!(large.iter().all(|&b| b == 0));
}

// ═══════════════════════════════════════════════════════════════════════════
// ARITHMETIC OPERATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_ct_mod_reduce_simple() {
    assert_eq!(ct_mod_reduce(10, 3), 1);
    assert_eq!(ct_mod_reduce(15, 7), 1);
    assert_eq!(ct_mod_reduce(100, 13), 9);
}

#[test]
fn test_ct_mod_reduce_exact_multiple() {
    assert_eq!(ct_mod_reduce(15, 5), 0);
    assert_eq!(ct_mod_reduce(100, 10), 0);
}

#[test]
fn test_ct_mod_reduce_larger_than_modulus() {
    assert_eq!(ct_mod_reduce(1000, 7), 1000 % 7);
    assert_eq!(ct_mod_reduce(999999, 97), 999999 % 97);
}

#[test]
fn test_ct_mod_reduce_smaller_than_modulus() {
    assert_eq!(ct_mod_reduce(5, 10), 5);
    assert_eq!(ct_mod_reduce(1, 100), 1);
}

#[test]
fn test_ct_min_max_same_values() {
    assert_eq!(ct_min_u32(42, 42), 42);
    assert_eq!(ct_max_u32(42, 42), 42);
}

#[test]
fn test_ct_min_max_extremes() {
    assert_eq!(ct_min_u32(0, u32::MAX), 0);
    assert_eq!(ct_max_u32(0, u32::MAX), u32::MAX);
}

#[test]
fn test_ct_min_max_ordering() {
    for a in [0, 1, 100, 1000, u32::MAX] {
        for b in [0, 1, 100, 1000, u32::MAX] {
            let min = ct_min_u32(a, b);
            let max = ct_max_u32(a, b);
            
            assert!(min <= a && min <= b);
            assert!(max >= a && max >= b);
            assert!(min <= max);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// RANGE CHECK TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_ct_in_range_inclusive() {
    assert!(ct_in_range(5, 1, 10));
    assert!(ct_in_range(1, 1, 10));
    assert!(ct_in_range(10, 1, 10));
}

#[test]
fn test_ct_in_range_exclusive() {
    assert!(!ct_in_range(0, 1, 10));
    assert!(!ct_in_range(11, 1, 10));
}

#[test]
fn test_ct_in_range_single_value() {
    assert!(ct_in_range(5, 5, 5));
    assert!(!ct_in_range(4, 5, 5));
    assert!(!ct_in_range(6, 5, 5));
}

#[test]
fn test_ct_in_range_full_u32() {
    assert!(ct_in_range(u32::MAX / 2, 0, u32::MAX));
    assert!(ct_in_range(0, 0, u32::MAX));
    assert!(ct_in_range(u32::MAX, 0, u32::MAX));
}

// ═══════════════════════════════════════════════════════════════════════════
// BIT MANIPULATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_ct_get_bit_all_positions() {
    let value = 0b10101010_10101010_10101010_10101010u32;
    
    for i in 0..32 {
        let expected = (i % 2) == 1;
        assert_eq!(ct_get_bit(value, i), expected);
    }
}

#[test]
fn test_ct_get_bit_out_of_range() {
    let value = 0xFFFFFFFFu32;
    
    assert!(!ct_get_bit(value, 32));
    assert!(!ct_get_bit(value, 100));
}

#[test]
fn test_ct_get_bit_zero() {
    let value = 0u32;
    
    for i in 0..32 {
        assert!(!ct_get_bit(value, i));
    }
}

#[test]
fn test_ct_hamming_weight_powers_of_two() {
    assert_eq!(ct_hamming_weight(0b1), 1);
    assert_eq!(ct_hamming_weight(0b10), 1);
    assert_eq!(ct_hamming_weight(0b100), 1);
    assert_eq!(ct_hamming_weight(0b1000), 1);
}

#[test]
fn test_ct_hamming_weight_extremes() {
    assert_eq!(ct_hamming_weight(0), 0);
    assert_eq!(ct_hamming_weight(0xFFFFFFFF), 32);
}

#[test]
fn test_ct_hamming_weight_patterns() {
    assert_eq!(ct_hamming_weight(0b10101010), 4);
    assert_eq!(ct_hamming_weight(0b11110000), 4);
    assert_eq!(ct_hamming_weight(0xFF), 8);
    assert_eq!(ct_hamming_weight(0xFFFF), 16);
}

// ═══════════════════════════════════════════════════════════════════════════
// TIMING GUARD TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_timing_guard_within_bounds() {
    let guard = TimingGuard::new("test", 0);
    std::thread::sleep(std::time::Duration::from_micros(50));
    
    let result = guard.verify();
    assert!(result.is_ok());
}

#[test]
fn test_timing_guard_too_fast() {
    let guard = TimingGuard::new("fast_test", 10_000_000); // 10ms minimum
    // Immediately verify without delay
    
    let result = guard.verify();
    assert!(result.is_err());
    
    if let Err(e) = result {
        assert_eq!(e.kind(), &CryptoErrorKind::TimingViolation);
    }
}

#[test]
fn test_timing_violations_counter_increments() {
    let initial = get_timing_violations();
    
    let guard = TimingGuard::new("violation_test", 1_000_000_000);
    let _ = guard.verify(); // Will fail
    
    let after = get_timing_violations();
    assert!(after > initial);
}

#[test]
fn test_timing_guard_multiple_sequential() {
    for i in 0..5 {
        let guard = TimingGuard::new("sequential", 0);
        std::thread::sleep(std::time::Duration::from_micros(20));
        
        let result = guard.verify();
        assert!(result.is_ok(), "Iteration {} failed", i);
    }
}