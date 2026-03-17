/// SHA3-512 over one or more input slices.
///
/// The sponge absorbs each input slice in order, so `hash(&[a, b], out)` is
/// equivalent to hashing the concatenation `a || b`.
use super::mlkem1024::keccak::{KeccakSponge, zeroize_sponge};

const SHA3_SUFFIX: u8 = 0x06;

/// SHA3-512 sponge rate in bytes (1088 bits / 8).
pub(crate) const RATE: usize = 72;

/// SHA3-512 digest length in bytes.
pub(crate) const OUTPUT_LEN: usize = 64;

/// SHA3-512 over the concatenation of `inputs`.
pub(crate) fn hash(inputs: &[&[u8]], out: &mut [u8; OUTPUT_LEN]) {
    let mut sponge: KeccakSponge<RATE> = KeccakSponge::new();
    for input in inputs {
        sponge.absorb(input);
    }
    sponge.finalize(SHA3_SUFFIX);
    sponge.squeeze(out);
    zeroize_sponge(&mut sponge);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        let mut out = [0u8; OUTPUT_LEN];
        hash(&[b""], &mut out);
        assert_eq!(
            &out[..8],
            &[0xa6u8, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5],
            "SHA3-512 empty string first 8 bytes mismatch"
        );
    }

    #[test]
    fn multi_input_equals_concat() {
        let a = b"hello";
        let b = b" world";
        let mut out_multi = [0u8; OUTPUT_LEN];
        let mut out_single = [0u8; OUTPUT_LEN];
        hash(&[a, b], &mut out_multi);
        hash(&[b"hello world"], &mut out_single);
        assert_eq!(out_multi, out_single);
    }

    #[test]
    fn deterministic() {
        let mut first = [0u8; OUTPUT_LEN];
        let mut second = [0u8; OUTPUT_LEN];
        hash(&[b"test"], &mut first);
        hash(&[b"test"], &mut second);
        assert_eq!(first, second);
    }
}
