//! Fuzz constant-time arithmetic operations
//!
//! Tests:
//! - Modular reduction edge cases
//! - Min/max with extreme values
//! - Range checking boundary conditions
//! - Bit manipulation operations

#![no_main]

use libfuzzer_sys::fuzz_target;
use veil_crypto::constant_time::*;

#[derive(arbitrary::Arbitrary, Debug)]
struct ArithmeticInput {
    value: u32,
    modulus: u32,
    compare_a: u32,
    compare_b: u32,
    range_min: u32,
    range_max: u32,
    bit_index: u8,
}

fuzz_target!(|input: ArithmeticInput| {
    // Test modular reduction (avoid division by zero)
    if input.modulus > 0 {
        let reduced = ct_mod_reduce(input.value, input.modulus);
        assert!(reduced < input.modulus, "Reduction failed: {} >= {}", reduced, input.modulus);
    }
    
    // Test min/max operations
    let min_val = ct_min_u32(input.compare_a, input.compare_b);
    let max_val = ct_max_u32(input.compare_a, input.compare_b);
    
    assert!(min_val <= input.compare_a && min_val <= input.compare_b);
    assert!(max_val >= input.compare_a && max_val >= input.compare_b);
    assert!(min_val <= max_val);
    
    // Test range checking
    if input.range_min <= input.range_max {
        let in_range = ct_in_range(input.value, input.range_min, input.range_max);
        let expected = input.value >= input.range_min && input.value <= input.range_max;
        assert_eq!(in_range, expected, 
            "Range check failed: {} in [{}, {}] = {}, expected {}",
            input.value, input.range_min, input.range_max, in_range, expected);
    }
    
    // Test bit operations
    let _ = ct_get_bit(input.value, input.bit_index);
    
    let weight = ct_hamming_weight(input.value);
    assert!(weight <= 32, "Hamming weight > 32: {}", weight);
    
    // Verify hamming weight correctness
    let expected_weight = input.value.count_ones();
    assert_eq!(weight, expected_weight, 
        "Hamming weight mismatch: got {}, expected {}", weight, expected_weight);
});