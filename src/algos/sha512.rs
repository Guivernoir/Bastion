// SHA-512 implementation
// no_alloc, no external deps, volatile zeroization, unsafe-aware
// All symbols pub(crate) or private.

use crate::zeroize::zeroize_mem;
use core::ptr;

// ── Constants ────────────────────────────────────────────────────────────────

const BLOCK_LEN: usize = 128;
const DIGEST_LEN: usize = 64;

/// Initial hash values (first 64 bits of fractional parts of sqrt of primes 2..19)
const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Round constants (first 64 bits of fractional parts of cbrt of primes 2..409)
const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

// ── SHA-512 logical functions ────────────────────────────────────────────────

#[inline(always)]
const fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
const fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// Big-sigma 0: Σ₀(a)
#[inline(always)]
const fn bsig0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

/// Big-sigma 1: Σ₁(e)
#[inline(always)]
const fn bsig1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

/// Small-sigma 0: σ₀ — message schedule
#[inline(always)]
const fn ssig0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

/// Small-sigma 1: σ₁ — message schedule
#[inline(always)]
const fn ssig1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

// ── Core compression ────────────────────────────────────────────────────────

/// Compress a single 1024-bit block into `state`.
/// Message schedule lives on the stack; it is zeroized before returning.
fn compress(state: &mut [u64; 8], block: &[u8; BLOCK_LEN]) {
    let mut w = [0u64; 80];

    // Load first 16 words — avoid try_into + unwrap via raw pointer read.
    for i in 0..16 {
        // SAFETY: block is exactly BLOCK_LEN bytes; i*8 is always in bounds.
        w[i] = u64::from_be_bytes(unsafe { *(block.as_ptr().add(i * 8) as *const [u8; 8]) });
    }

    // Expand schedule
    for i in 16..80 {
        w[i] = ssig1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(ssig0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    // 80 rounds — unrolled by the compiler at opt-level >= 2
    for i in 0..80 {
        let t1 = h
            .wrapping_add(bsig1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t2 = bsig0(a).wrapping_add(maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);

    // Burn message schedule — sensitive key-material may be in the input.
    // SAFETY: `w` is a valid writable stack allocation.
    unsafe { zeroize_mem(w.as_mut_ptr() as *mut u8, core::mem::size_of_val(&w)) };
}

// ── Hasher ───────────────────────────────────────────────────────────────────

/// Streaming SHA-512 hasher.
///
/// Sensitive fields are zeroed on [`Drop`].
pub(crate) struct Sha512 {
    state: [u64; 8],
    block: [u8; BLOCK_LEN],
    block_len: usize,
    total_len: u128, // bytes — u128 handles > 2^64 bits per spec
}

impl Sha512 {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            state: IV,
            block: [0u8; BLOCK_LEN],
            block_len: 0,
            total_len: 0,
        }
    }

    /// Feed arbitrary-length input; may be called multiple times.
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u128);

        // Fill any partial block first.
        if self.block_len > 0 {
            let space = BLOCK_LEN - self.block_len;
            let take = data.len().min(space);
            self.block[self.block_len..self.block_len + take].copy_from_slice(&data[..take]);
            self.block_len += take;
            data = &data[take..];

            if self.block_len == BLOCK_LEN {
                // SAFETY: block_len == BLOCK_LEN means the array is full.
                compress(&mut self.state, unsafe {
                    &*(self.block.as_ptr() as *const [u8; BLOCK_LEN])
                });
                // SAFETY: `self.block` is a valid writable array.
                unsafe { zeroize_mem(self.block.as_mut_ptr(), self.block.len()) };
                self.block_len = 0;
            }
        }

        // Process full blocks directly from the input slice — zero copies.
        while data.len() >= BLOCK_LEN {
            // SAFETY: data.len() >= BLOCK_LEN guarantees the cast is valid.
            compress(&mut self.state, unsafe {
                &*(data.as_ptr() as *const [u8; BLOCK_LEN])
            });
            data = &data[BLOCK_LEN..];
        }

        // Buffer the remainder.
        if !data.is_empty() {
            self.block[..data.len()].copy_from_slice(data);
            self.block_len = data.len();
        }
    }

    /// Consume the hasher and return the 64-byte digest.
    ///
    /// The internal state is zeroized via [`Drop`] after `self` is consumed.
    pub(crate) fn finalize(mut self) -> [u8; DIGEST_LEN] {
        let bit_len = self.total_len.wrapping_mul(8);

        // Append the mandatory 0x80 padding byte.
        self.block[self.block_len] = 0x80;
        self.block_len += 1;

        // If there is not enough room for the 16-byte length field,
        // pad with zeros, compress, and start a fresh block.
        if self.block_len > BLOCK_LEN - 16 {
            self.block[self.block_len..].fill(0);
            // SAFETY: block is fully initialized.
            compress(&mut self.state, unsafe {
                &*(self.block.as_ptr() as *const [u8; BLOCK_LEN])
            });
            // SAFETY: `self.block` is a valid writable array.
            unsafe { zeroize_mem(self.block.as_mut_ptr(), self.block.len()) };
            self.block_len = 0;
        }

        // Zero-pad up to the length field position.
        self.block[self.block_len..BLOCK_LEN - 16].fill(0);

        // Append message bit-length as big-endian u128 (two u64s per spec).
        // SHA-512 uses a 128-bit length field.
        let len_bytes = bit_len.to_be_bytes();
        self.block[BLOCK_LEN - 16..].copy_from_slice(&len_bytes);

        // SAFETY: block is fully initialized.
        compress(&mut self.state, unsafe {
            &*(self.block.as_ptr() as *const [u8; BLOCK_LEN])
        });

        // Serialise state to digest.
        let mut digest = [0u8; DIGEST_LEN];
        for (i, &word) in self.state.iter().enumerate() {
            // SAFETY: i < 8, each write is 8 bytes, total 64 bytes — in bounds.
            unsafe {
                ptr::write_unaligned(
                    digest.as_mut_ptr().add(i * 8) as *mut [u8; 8],
                    word.to_be_bytes(),
                );
            }
        }

        // `self` drops here → Drop::drop zeroizes state, block, lengths.
        digest
    }
}

/// One-shot convenience wrapper.
#[inline]
pub(crate) fn hash(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize()
}

impl Drop for Sha512 {
    fn drop(&mut self) {
        // SAFETY: both arrays are valid writable allocations.
        unsafe {
            zeroize_mem(
                self.state.as_mut_ptr() as *mut u8,
                core::mem::size_of_val(&self.state),
            );
            zeroize_mem(self.block.as_mut_ptr(), self.block.len());
        }
        // Volatile-write scalars individually — compiler cannot batch-elide them.
        unsafe {
            ptr::write_volatile(&mut self.block_len, 0usize);
            ptr::write_volatile(&mut self.total_len, 0u128);
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[inline]
    fn hex_nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    }

    fn decode_hex_64(hex: &[u8]) -> [u8; DIGEST_LEN] {
        debug_assert_eq!(hex.len(), DIGEST_LEN * 2);
        let mut out = [0u8; DIGEST_LEN];
        for i in 0..DIGEST_LEN {
            out[i] = (hex_nibble(hex[2 * i]) << 4) | hex_nibble(hex[2 * i + 1]);
        }
        out
    }

    // NIST FIPS 180-4 test vectors

    #[test]
    fn empty_string() {
        let digest = hash(b"");
        assert_eq!(
            digest,
            decode_hex_64(
                b"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                  47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            )
        );
    }

    #[test]
    fn abc() {
        let digest = hash(b"abc");
        assert_eq!(
            digest,
            decode_hex_64(
                b"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                  2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
    }

    #[test]
    fn long_message() {
        // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let digest = hash(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            digest,
            decode_hex_64(
                b"204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335\
                  96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
            )
        );
    }

    #[test]
    fn one_million_a() {
        // "a" repeated 1_000_000 times
        let mut h = Sha512::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        let digest = h.finalize();
        assert_eq!(
            digest,
            decode_hex_64(
                b"e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
                  de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
            )
        );
    }

    #[test]
    fn streaming_equals_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let oneshot = hash(data);

        let mut h = Sha512::new();
        for chunk in data.chunks(7) {
            h.update(chunk);
        }
        let streamed = h.finalize();

        assert_eq!(oneshot, streamed);
    }

    #[test]
    fn cross_block_boundary() {
        // Feed data that straddles a 128-byte block boundary to exercise the
        // partial-block buffering path.
        let data = [0x61u8; 200]; // 200 × 'a'
        let oneshot = hash(&data);

        let mut h = Sha512::new();
        h.update(&data[..100]);
        h.update(&data[100..]);
        assert_eq!(oneshot, h.finalize());
    }

    #[test]
    fn exact_block_size() {
        // Exactly one block — exercises the path where padding goes to a new block.
        let data = [0xffu8; BLOCK_LEN];
        let d1 = hash(&data);
        let mut h = Sha512::new();
        h.update(&data);
        assert_eq!(d1, h.finalize());
    }
}
