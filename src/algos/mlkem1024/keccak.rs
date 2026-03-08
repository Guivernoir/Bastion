/// Keccak-f[1600] permutation and sponge construction.
///
/// This is the single crypto primitive underlying every hash and XOF in ML-KEM:
///   SHA3-256, SHA3-512, SHAKE-128, SHAKE-256.
///
/// Layout: `state[x + 5*y]` for x,y ∈ 0..5. 25 lanes of 64 bits = 1600 bits.
///
/// Correctness reference: NIST FIPS 202 / Keccak team reference implementation.
/// No allocations; state lives on the stack. Caller must zeroize after use.
use core::ptr;

// ── Round constants (ι step) ──────────────────────────────────────────────────

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// ρ rotation offsets indexed as RHO[x + 5*y].
/// lane (0,0) = 0 by spec; remaining 24 lanes per FIPS 202 §3.2.2.
const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, // y=0
    36, 44, 6, 55, 20, // y=1
    3, 10, 43, 25, 39, // y=2
    41, 45, 15, 21, 8, // y=3
    18, 2, 61, 56, 14, // y=4
];

// ── Core permutation ──────────────────────────────────────────────────────────

/// Apply Keccak-f[1600] to `state` in place.
///
/// # Safety
/// Intrinsically safe — only operates on the caller-supplied stack slice.
#[inline(never)] // must not be inlined; see zeroize rationale in zeroize.rs
pub(crate) fn keccak_f1600(state: &mut [u64; 25]) {
    for round in 0..24 {
        // ── θ ─────────────────────────────────────────────────────────────────
        let mut c = [0u64; 5];
        for x in 0..5usize {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5usize {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for i in 0..25usize {
            state[i] ^= d[i % 5];
        }

        // ── ρ + π ─────────────────────────────────────────────────────────────
        // Combine ρ (rotate) and π (permute lanes) into a single pass via temp B.
        let mut b = [0u64; 25];
        for x in 0..5usize {
            for y in 0..5usize {
                let src = x + 5 * y;
                let dst = y + 5 * ((2 * x + 3 * y) % 5);
                b[dst] = state[src].rotate_left(RHO[src]);
            }
        }

        // ── χ ─────────────────────────────────────────────────────────────────
        for x in 0..5usize {
            for y in 0..5usize {
                let i = x + 5 * y;
                state[i] = b[i] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }

        // ── ι ─────────────────────────────────────────────────────────────────
        state[0] ^= RC[round];
    }
}

// ── Sponge state ──────────────────────────────────────────────────────────────

/// Generic Keccak sponge (absorb/squeeze) over `keccak_f1600`.
///
/// `RATE` is in bytes; valid values: 72, 104, 136, 144, 168.
/// Domain-separation byte appended on `finalize()` — 0x06 for SHA3, 0x1F for SHAKE.
///
/// Sensitive: caller must zeroize this struct after use if input was sensitive.
/// Drop is deliberately NOT derived; handle in caller via `zeroize_sponge`.
pub(crate) struct KeccakSponge<const RATE: usize> {
    pub(crate) state: [u64; 25],
    pub(crate) buf: [u8; 168], // max rate (SHAKE-128) — always 168 bytes, unused tail ignored
    pub(crate) pos: usize,     // bytes absorbed into buf since last permutation
    pub(crate) squeez: bool,   // true when in squeeze phase
}

impl<const RATE: usize> KeccakSponge<RATE> {
    #[inline]
    pub(crate) const fn new() -> Self {
        debug_assert!(RATE <= 168, "rate exceeds max lane width");
        Self {
            state: [0u64; 25],
            buf: [0u8; 168],
            pos: 0,
            squeez: false,
        }
    }

    /// Absorb arbitrary-length `data` into the sponge.
    pub(crate) fn absorb(&mut self, mut data: &[u8]) {
        debug_assert!(!self.squeez, "absorb called after finalize");

        // Fill partial block first.
        if self.pos > 0 {
            let space = RATE - self.pos;
            let take = data.len().min(space);
            self.buf[self.pos..self.pos + take].copy_from_slice(&data[..take]);
            self.pos += take;
            data = &data[take..];

            if self.pos == RATE {
                self.absorb_block();
                self.pos = 0;
            }
        }

        // Process full rate-blocks directly.
        while data.len() >= RATE {
            // SAFETY: data.len() >= RATE ensures we only copy RATE bytes.
            self.buf[..RATE].copy_from_slice(&data[..RATE]);
            self.absorb_block();
            data = &data[RATE..];
        }

        // Buffer remainder.
        if !data.is_empty() {
            self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
            self.pos += data.len();
        }
    }

    /// Apply the domain-separation suffix and padding, then enter squeeze phase.
    /// `suffix` = 0x06 for SHA3, 0x1F for SHAKE.
    pub(crate) fn finalize(&mut self, suffix: u8) {
        debug_assert!(!self.squeez);
        self.buf[self.pos] = suffix;
        // Zero any bytes between suffix and end-of-rate-block.
        for b in &mut self.buf[self.pos + 1..RATE] {
            *b = 0;
        }
        // Set the MSB of the last byte in the rate block (multi-rate padding).
        self.buf[RATE - 1] |= 0x80;
        self.absorb_block();
        self.pos = RATE; // force fresh permutation on first squeeze
        self.squeez = true;
    }

    /// Squeeze exactly `out.len()` bytes from the sponge.
    pub(crate) fn squeeze(&mut self, mut out: &mut [u8]) {
        debug_assert!(self.squeez, "squeeze called before finalize");

        while !out.is_empty() {
            if self.pos >= RATE {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
            // Materialise current rate bytes from state lanes (little-endian).
            let lane_idx = self.pos / 8;
            let byte_off = self.pos % 8;
            let avail = RATE - self.pos;
            let take = out.len().min(avail);

            // Emit `take` bytes from state, traversing lane boundaries.
            let mut emitted = 0usize;
            let mut rem = take;
            let mut p = self.pos;
            while rem > 0 {
                let li = p / 8;
                let bo = p % 8;
                let can = (8 - bo).min(rem);
                let w = self.state[li].to_le_bytes();
                out[emitted..emitted + can].copy_from_slice(&w[bo..bo + can]);
                emitted += can;
                rem -= can;
                p += can;
            }
            let _ = (lane_idx, byte_off); // suppress unused warnings

            self.pos += take;
            out = &mut out[take..];
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// XOR `self.buf[..RATE]` into the sponge state and permute.
    #[inline]
    fn absorb_block(&mut self) {
        // XOR rate bytes into the state, eight bytes at a time (LE lanes).
        debug_assert!(RATE % 8 == 0, "rate must be a multiple of 8");
        for i in 0..RATE / 8 {
            let bytes = self.buf[i * 8..i * 8 + 8].try_into().unwrap_or([0u8; 8]); // infallible: slice is exactly 8 bytes
            self.state[i] ^= u64::from_le_bytes(bytes);
        }
        keccak_f1600(&mut self.state);
    }
}

// ── Zeroization of sponge state ───────────────────────────────────────────────

/// Burn a sponge state. Call before dropping any sponge that processed secret data.
#[inline]
pub(crate) fn zeroize_sponge<const RATE: usize>(s: &mut KeccakSponge<RATE>) {
    for w in s.state.iter_mut() {
        // SAFETY: valid aligned reference.
        unsafe { ptr::write_volatile(w, 0u64) };
    }
    for b in s.buf.iter_mut() {
        unsafe { ptr::write_volatile(b, 0u8) };
    }
    unsafe {
        ptr::write_volatile(&mut s.pos, 0usize);
        ptr::write_volatile(&mut s.squeez, false);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
