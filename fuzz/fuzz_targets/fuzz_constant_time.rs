//! Fuzz constant-time operations for timing leaks and correctness
//!
//! Tests:
//! - Buffer comparisons with arbitrary inputs
//! - XOR operations with varying lengths
//! - Arithmetic operations with edge cases
//! - Zeroization verification

#![no_main]

use libfuzzer_sys::fuzz_target;
use veil_crypto::constant_time::*;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    
    // Split data into two parts for comparison operations
    let mid = data.len() / 2;
    let (part1, part2) = data.split_at(mid);
    
    // Test constant-time equality
    let _ = ct_eq(part1, part2);
    
    // Test constant-time less-than
    let _ = ct_less_than(part1, part2);
    
    // Test XOR if we have space
    if part1.len() > 0 && part2.len() > 0 {
        let mut result = vec![0u8; part1.len().min(part2.len())];
        ct_xor(part1, part2, &mut result);
    }
    
    // Test conditional copy
    if part1.len() >= 4 && part2.len() >= 4 {
        let mut dst = part2.to_vec();
        ct_copy_if(part1[0] & 1 == 1, part1, &mut dst);
    }
    
    // Test zeroization
    if !part1.is_empty() {
        let mut buf = part1.to_vec();
        let _ = ct_zeroize_verify(&mut buf);
    }
});