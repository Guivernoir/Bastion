/// Serialization and deserialization for ML-DSA-87 (FIPS 204 §5.1).
///
/// Bit-packing schemes (all little-endian bit order):
///
///   t1:   10 bits/coeff,  coeffs ∈ [0, 1023]         → 4 coeffs per  5 bytes (× 256 = 320 B)
///   t0:   13 bits/coeff,  biased by 2^12              → 8 coeffs per 13 bytes (× 256 = 416 B)
///   eta:   3 bits/coeff,  η=2, stored as (2 − coeff)  → 8 coeffs per  3 bytes (× 256 =  96 B)
///   z:    20 bits/coeff,  biased by γ₁ = 2^19         → 2 coeffs per  5 bytes (× 256 = 640 B)
///   w1:    4 bits/coeff,  coeffs ∈ [0, 15]            → 2 coeffs per  1 byte  (× 256 = 128 B)
///   hint: sparse (OMEGA + K = 83 bytes total)
///
/// Correctness of every layout is verified by the constants in params.rs
/// (POLYT1_BYTES = 320, POLYT0_BYTES = 416, etc.).
use crate::mlsigcrypt::specs::ml::params::{
    ETA, GAMMA1, K, L, LAMBDA2_BYTES, N, OMEGA, PK_BYTES, PK_RHO_OFF, PK_T1_OFF, POLYETA_BYTES,
    POLYT0_BYTES, POLYT1_BYTES, POLYW1_BYTES, POLYZ_BYTES, SIG_BYTES, SIG_CTILDE_OFF, SIG_H_OFF,
    SIG_Z_OFF, SK_BYTES, SK_K_OFF, SK_RHO_OFF, SK_S1_OFF, SK_S2_OFF, SK_T0_OFF, SK_TR_OFF,
};
use crate::mlsigcrypt::specs::ml::poly::Poly;
use crate::mlsigcrypt::specs::ml::vec::PolyVec;

// ── t1 (10 bits/coeff) ────────────────────────────────────────────────────────
//
// 4 coefficients → 5 bytes.  Layout (40 bits):
//   a0[9:0] | a1[9:0] | a2[9:0] | a3[9:0]
//
// byte 0: a0[7:0]
// byte 1: a0[9:8] | a1[5:0]<<2
// byte 2: a1[9:6] | a2[3:0]<<4
// byte 3: a2[9:4] | a3[1:0]<<6
// byte 4: a3[9:2]

/// Pack 256 t1 coefficients (∈ [0, 1023]) into POLYT1_BYTES = 320 bytes.
pub(crate) fn polyt1_pack(r: &mut [u8; POLYT1_BYTES], a: &Poly) {
    for i in 0..N / 4 {
        let a0 = a.coeffs[4 * i] as u32;
        let a1 = a.coeffs[4 * i + 1] as u32;
        let a2 = a.coeffs[4 * i + 2] as u32;
        let a3 = a.coeffs[4 * i + 3] as u32;
        r[5 * i] = a0 as u8;
        r[5 * i + 1] = (a0 >> 8 | a1 << 2) as u8;
        r[5 * i + 2] = (a1 >> 6 | a2 << 4) as u8;
        r[5 * i + 3] = (a2 >> 4 | a3 << 6) as u8;
        r[5 * i + 4] = (a3 >> 2) as u8;
    }
}

/// Unpack POLYT1_BYTES bytes into 256 t1 coefficients.
pub(crate) fn polyt1_unpack(a: &mut Poly, r: &[u8; POLYT1_BYTES]) {
    for i in 0..N / 4 {
        let r0 = r[5 * i] as u32;
        let r1 = r[5 * i + 1] as u32;
        let r2 = r[5 * i + 2] as u32;
        let r3 = r[5 * i + 3] as u32;
        let r4 = r[5 * i + 4] as u32;
        a.coeffs[4 * i] = ((r0 | r1 << 8) & 0x3FF) as i32;
        a.coeffs[4 * i + 1] = ((r1 >> 2 | r2 << 6) & 0x3FF) as i32;
        a.coeffs[4 * i + 2] = ((r2 >> 4 | r3 << 4) & 0x3FF) as i32;
        a.coeffs[4 * i + 3] = ((r3 >> 6 | r4 << 2) & 0x3FF) as i32;
    }
}

// ── t0 (13 bits/coeff, biased by 2^12) ───────────────────────────────────────
//
// Stored value: v = 2^12 − t0  ∈ [0, 8191]  (13 bits; t0 ∈ (−4096, 4096]).
//
// 8 coefficients → 13 bytes (104 bits):
//
// t[k] bit positions in the 104-bit stream:
//   t[0]: bits  0-12   t[1]: bits 13-25   t[2]: bits 26-38   t[3]: bits 39-51
//   t[4]: bits 52-64   t[5]: bits 65-77   t[6]: bits 78-90   t[7]: bits 91-103

/// Pack 256 t0 coefficients into POLYT0_BYTES = 416 bytes.
pub(crate) fn polyt0_pack(r: &mut [u8; POLYT0_BYTES], a: &Poly) {
    for i in 0..N / 8 {
        let mut t = [0u32; 8];
        for k in 0..8 {
            t[k] = ((1i32 << 12) - a.coeffs[8 * i + k]) as u32;
        }
        r[13 * i] = t[0] as u8;
        r[13 * i + 1] = (t[0] >> 8 | t[1] << 5) as u8;
        r[13 * i + 2] = (t[1] >> 3) as u8;
        r[13 * i + 3] = (t[1] >> 11 | t[2] << 2) as u8;
        r[13 * i + 4] = (t[2] >> 6 | t[3] << 7) as u8;
        r[13 * i + 5] = (t[3] >> 1) as u8;
        r[13 * i + 6] = (t[3] >> 9 | t[4] << 4) as u8;
        r[13 * i + 7] = (t[4] >> 4) as u8;
        r[13 * i + 8] = (t[4] >> 12 | t[5] << 1) as u8;
        r[13 * i + 9] = (t[5] >> 7 | t[6] << 6) as u8;
        r[13 * i + 10] = (t[6] >> 2) as u8;
        r[13 * i + 11] = (t[6] >> 10 | t[7] << 3) as u8;
        r[13 * i + 12] = (t[7] >> 5) as u8;
    }
}

/// Unpack POLYT0_BYTES bytes into 256 t0 coefficients.
pub(crate) fn polyt0_unpack(a: &mut Poly, r: &[u8; POLYT0_BYTES]) {
    for i in 0..N / 8 {
        let b = |j: usize| r[13 * i + j] as u32;
        let t0 = (b(0) | b(1) << 8) & 0x1FFF;
        let t1 = (b(1) >> 5 | b(2) << 3 | b(3) << 11) & 0x1FFF;
        let t2 = (b(3) >> 2 | b(4) << 6) & 0x1FFF;
        let t3 = (b(4) >> 7 | b(5) << 1 | b(6) << 9) & 0x1FFF;
        let t4 = (b(6) >> 4 | b(7) << 4 | b(8) << 12) & 0x1FFF;
        let t5 = (b(8) >> 1 | b(9) << 7) & 0x1FFF;
        let t6 = (b(9) >> 6 | b(10) << 2 | b(11) << 10) & 0x1FFF;
        let t7 = (b(11) >> 3 | b(12) << 5) & 0x1FFF;
        a.coeffs[8 * i] = (1 << 12) - t0 as i32;
        a.coeffs[8 * i + 1] = (1 << 12) - t1 as i32;
        a.coeffs[8 * i + 2] = (1 << 12) - t2 as i32;
        a.coeffs[8 * i + 3] = (1 << 12) - t3 as i32;
        a.coeffs[8 * i + 4] = (1 << 12) - t4 as i32;
        a.coeffs[8 * i + 5] = (1 << 12) - t5 as i32;
        a.coeffs[8 * i + 6] = (1 << 12) - t6 as i32;
        a.coeffs[8 * i + 7] = (1 << 12) - t7 as i32;
    }
}

// ── eta (3 bits/coeff, η=2) ───────────────────────────────────────────────────
//
// Stored value: v = η − coeff  ∈ {0,1,2,3,4}  (3 bits).
// 8 coefficients → 3 bytes (24 bits):
//
// byte 0: t[0] | t[1]<<3 | t[2]<<6
// byte 1: t[2]>>2 | t[3]<<1 | t[4]<<4 | t[5]<<7
// byte 2: t[5]>>1 | t[6]<<2 | t[7]<<5

/// Pack 256 s1/s2 coefficients (η=2, ∈ {−2,…,2}) into POLYETA_BYTES = 96 bytes.
pub(crate) fn polyeta_pack(r: &mut [u8; POLYETA_BYTES], a: &Poly) {
    for i in 0..N / 8 {
        let mut t = [0u32; 8];
        for k in 0..8 {
            t[k] = (ETA - a.coeffs[8 * i + k]) as u32;
        }
        r[3 * i] = (t[0] | t[1] << 3 | t[2] << 6) as u8;
        r[3 * i + 1] = (t[2] >> 2 | t[3] << 1 | t[4] << 4 | t[5] << 7) as u8;
        r[3 * i + 2] = (t[5] >> 1 | t[6] << 2 | t[7] << 5) as u8;
    }
}

/// Unpack POLYETA_BYTES bytes into 256 s1/s2 coefficients.
pub(crate) fn polyeta_unpack(a: &mut Poly, r: &[u8; POLYETA_BYTES]) {
    for i in 0..N / 8 {
        let b0 = r[3 * i] as u32;
        let b1 = r[3 * i + 1] as u32;
        let b2 = r[3 * i + 2] as u32;
        a.coeffs[8 * i] = ETA - (b0 & 0x7) as i32;
        a.coeffs[8 * i + 1] = ETA - ((b0 >> 3) & 0x7) as i32;
        a.coeffs[8 * i + 2] = ETA - ((b0 >> 6 | b1 << 2) & 0x7) as i32;
        a.coeffs[8 * i + 3] = ETA - ((b1 >> 1) & 0x7) as i32;
        a.coeffs[8 * i + 4] = ETA - ((b1 >> 4) & 0x7) as i32;
        a.coeffs[8 * i + 5] = ETA - ((b1 >> 7 | b2 << 1) & 0x7) as i32;
        a.coeffs[8 * i + 6] = ETA - ((b2 >> 2) & 0x7) as i32;
        a.coeffs[8 * i + 7] = ETA - ((b2 >> 5) & 0x7) as i32;
    }
}

// ── z (20 bits/coeff, biased by γ₁ = 2^19) ───────────────────────────────────
//
// Stored value: v = γ₁ − z  ∈ [0, 2γ₁ − 1]  ⊂ [0, 2^20 − 1]  (20 bits).
// 2 coefficients → 5 bytes (40 bits):
//
// byte 0: v0[7:0]
// byte 1: v0[15:8]
// byte 2: v0[19:16] | v1[3:0]<<4
// byte 3: v1[11:4]
// byte 4: v1[19:12]

/// Pack 256 z coefficients (∈ (−γ₁, γ₁)) into POLYZ_BYTES = 640 bytes.
pub(crate) fn polyz_pack(r: &mut [u8; POLYZ_BYTES], a: &Poly) {
    for i in 0..N / 2 {
        let v0 = (GAMMA1 - a.coeffs[2 * i]) as u32;
        let v1 = (GAMMA1 - a.coeffs[2 * i + 1]) as u32;
        r[5 * i] = v0 as u8;
        r[5 * i + 1] = (v0 >> 8) as u8;
        r[5 * i + 2] = (v0 >> 16 | v1 << 4) as u8;
        r[5 * i + 3] = (v1 >> 4) as u8;
        r[5 * i + 4] = (v1 >> 12) as u8;
    }
}

/// Unpack POLYZ_BYTES bytes into 256 z coefficients.
pub(crate) fn polyz_unpack(a: &mut Poly, r: &[u8; POLYZ_BYTES]) {
    for i in 0..N / 2 {
        let b0 = r[5 * i] as u32;
        let b1 = r[5 * i + 1] as u32;
        let b2 = r[5 * i + 2] as u32;
        let b3 = r[5 * i + 3] as u32;
        let b4 = r[5 * i + 4] as u32;
        let v0 = b0 | (b1 << 8) | ((b2 & 0x0F) << 16);
        let v1 = (b2 >> 4) | (b3 << 4) | (b4 << 12);
        a.coeffs[2 * i] = GAMMA1 - v0 as i32;
        a.coeffs[2 * i + 1] = GAMMA1 - v1 as i32;
    }
}

// ── w1 (4 bits/coeff, encode-only) ───────────────────────────────────────────
//
// w1 ∈ [0, 15].  2 coefficients per byte (encode only; w1 is never decoded from σ).

/// Pack 256 w1 coefficients (∈ [0, 15]) into POLYW1_BYTES = 128 bytes.
pub(crate) fn polyw1_pack(r: &mut [u8; POLYW1_BYTES], a: &Poly) {
    for i in 0..N / 2 {
        r[i] = (a.coeffs[2 * i] | (a.coeffs[2 * i + 1] << 4)) as u8;
    }
}

// ── Hint packing (OMEGA + K = 83 bytes) ──────────────────────────────────────
//
// Sparse format:
//   bytes [0, OMEGA)      — coefficient positions of set hints, per-poly, concatenated
//   bytes [OMEGA, OMEGA+K) — cumulative end index after each polynomial
//
// Example: poly 0 has hints at positions {3, 17}, poly 1 has hint at {255}:
//   r[0]=3, r[1]=17, r[2]=255, r[OMEGA]=2, r[OMEGA+1]=3, r[OMEGA+2..OMEGA+K]=3

/// Encode the K hint polynomials into OMEGA + K bytes. Writes zeros for unused slots.
pub(crate) fn pack_hint(r: &mut [u8; OMEGA + K], h: &PolyVec<K>) {
    r.fill(0);
    let mut idx = 0usize;
    for i in 0..K {
        for j in 0..N {
            if h.polys[i].coeffs[j] != 0 {
                r[idx] = j as u8;
                idx += 1;
            }
        }
        r[OMEGA + i] = idx as u8;
    }
}

/// Decode hint bytes into K hint polynomials. Returns false if the encoding is malformed.
///
/// Malformation checks:
///   1. End indices are non-decreasing.
///   2. Total hint count ≤ OMEGA.
///   3. Within each polynomial, positions are strictly increasing.
///   4. Unused bytes in [total_count, OMEGA) are all zero.
pub(crate) fn unpack_hint(h: &mut PolyVec<K>, r: &[u8; OMEGA + K]) -> bool {
    for p in h.polys.iter_mut() {
        p.coeffs.fill(0);
    }

    let mut k = 0usize;
    for i in 0..K {
        let end = r[OMEGA + i] as usize;
        if end < k || end > OMEGA {
            return false;
        }
        // Positions within this polynomial must be strictly increasing.
        for j in k..end {
            if j > k && r[j] <= r[j - 1] {
                return false;
            }
            h.polys[i].coeffs[r[j] as usize] = 1;
        }
        k = end;
    }
    // Unused slots in [k, OMEGA) must be zero.
    for j in k..OMEGA {
        if r[j] != 0 {
            return false;
        }
    }
    true
}

// ── Public key ────────────────────────────────────────────────────────────────

/// Encode (ρ, t1) → PK_BYTES = 2592 bytes.
pub(crate) fn pack_pk(pk: &mut [u8; PK_BYTES], rho: &[u8; 32], t1: &PolyVec<K>) {
    pk[PK_RHO_OFF..PK_T1_OFF].copy_from_slice(rho);
    for i in 0..K {
        let start = PK_T1_OFF + i * POLYT1_BYTES;
        let end = start + POLYT1_BYTES;
        let chunk: &mut [u8; POLYT1_BYTES] = (&mut pk[start..end]).try_into().unwrap();
        polyt1_pack(chunk, &t1.polys[i]);
    }
}

/// Decode PK_BYTES bytes → (ρ, t1).
pub(crate) fn unpack_pk(rho: &mut [u8; 32], t1: &mut PolyVec<K>, pk: &[u8; PK_BYTES]) {
    rho.copy_from_slice(&pk[PK_RHO_OFF..PK_T1_OFF]);
    for i in 0..K {
        let start = PK_T1_OFF + i * POLYT1_BYTES;
        let end = start + POLYT1_BYTES;
        polyt1_unpack(&mut t1.polys[i], pk[start..end].try_into().unwrap());
    }
}

/// Decode only the matrix-seed prefix ρ from an ML public key.
pub(crate) fn unpack_pk_rho(rho: &mut [u8; 32], pk: &[u8; PK_BYTES]) {
    rho.copy_from_slice(&pk[PK_RHO_OFF..PK_T1_OFF]);
}

// ── Secret key ────────────────────────────────────────────────────────────────

/// Encode (ρ, K_seed, tr, s1, s2, t0) → SK_BYTES = 4896 bytes.
pub(crate) fn pack_sk(
    sk: &mut [u8; SK_BYTES],
    rho: &[u8; 32],
    k_seed: &[u8; 32],
    tr: &[u8; 64],
    s1: &PolyVec<L>,
    s2: &PolyVec<K>,
    t0: &PolyVec<K>,
) {
    sk[SK_RHO_OFF..SK_RHO_OFF + 32].copy_from_slice(rho);
    sk[SK_K_OFF..SK_K_OFF + 32].copy_from_slice(k_seed);
    sk[SK_TR_OFF..SK_TR_OFF + 64].copy_from_slice(tr);

    for i in 0..L {
        let start = SK_S1_OFF + i * POLYETA_BYTES;
        let chunk: &mut [u8; POLYETA_BYTES] =
            (&mut sk[start..start + POLYETA_BYTES]).try_into().unwrap();
        polyeta_pack(chunk, &s1.polys[i]);
    }
    for i in 0..K {
        let start = SK_S2_OFF + i * POLYETA_BYTES;
        let chunk: &mut [u8; POLYETA_BYTES] =
            (&mut sk[start..start + POLYETA_BYTES]).try_into().unwrap();
        polyeta_pack(chunk, &s2.polys[i]);
    }
    for i in 0..K {
        let start = SK_T0_OFF + i * POLYT0_BYTES;
        let chunk: &mut [u8; POLYT0_BYTES] =
            (&mut sk[start..start + POLYT0_BYTES]).try_into().unwrap();
        polyt0_pack(chunk, &t0.polys[i]);
    }
}

/// Decode SK_BYTES bytes → (ρ, K_seed, tr, s1, s2, t0).
pub(crate) fn unpack_sk(
    rho: &mut [u8; 32],
    k_seed: &mut [u8; 32],
    tr: &mut [u8; 64],
    s1: &mut PolyVec<L>,
    s2: &mut PolyVec<K>,
    t0: &mut PolyVec<K>,
    sk: &[u8; SK_BYTES],
) {
    rho.copy_from_slice(&sk[SK_RHO_OFF..SK_RHO_OFF + 32]);
    k_seed.copy_from_slice(&sk[SK_K_OFF..SK_K_OFF + 32]);
    tr.copy_from_slice(&sk[SK_TR_OFF..SK_TR_OFF + 64]);

    for i in 0..L {
        let start = SK_S1_OFF + i * POLYETA_BYTES;
        polyeta_unpack(
            &mut s1.polys[i],
            sk[start..start + POLYETA_BYTES].try_into().unwrap(),
        );
    }
    for i in 0..K {
        let start = SK_S2_OFF + i * POLYETA_BYTES;
        polyeta_unpack(
            &mut s2.polys[i],
            sk[start..start + POLYETA_BYTES].try_into().unwrap(),
        );
    }
    for i in 0..K {
        let start = SK_T0_OFF + i * POLYT0_BYTES;
        polyt0_unpack(
            &mut t0.polys[i],
            sk[start..start + POLYT0_BYTES].try_into().unwrap(),
        );
    }
}

/// Decode only the matrix-seed prefix ρ from an ML secret key.
pub(crate) fn unpack_sk_rho(rho: &mut [u8; 32], sk: &[u8; SK_BYTES]) {
    rho.copy_from_slice(&sk[SK_RHO_OFF..SK_RHO_OFF + 32]);
}

// ── Signature ─────────────────────────────────────────────────────────────────

/// Encode (c̃, z, h) → SIG_BYTES = 4627 bytes.
pub(crate) fn pack_sig(
    sig: &mut [u8; SIG_BYTES],
    c_tilde: &[u8; LAMBDA2_BYTES],
    z: &PolyVec<L>,
    h: &PolyVec<K>,
) {
    sig[SIG_CTILDE_OFF..SIG_CTILDE_OFF + LAMBDA2_BYTES].copy_from_slice(c_tilde);

    for i in 0..L {
        let start = SIG_Z_OFF + i * POLYZ_BYTES;
        let chunk: &mut [u8; POLYZ_BYTES] =
            (&mut sig[start..start + POLYZ_BYTES]).try_into().unwrap();
        polyz_pack(chunk, &z.polys[i]);
    }

    let hint_bytes: &mut [u8; OMEGA + K] = (&mut sig[SIG_H_OFF..SIG_H_OFF + OMEGA + K])
        .try_into()
        .unwrap();
    pack_hint(hint_bytes, h);
}

/// Decode SIG_BYTES bytes → (c̃, z, h).  Returns false if hint encoding is malformed.
pub(crate) fn unpack_sig(
    c_tilde: &mut [u8; LAMBDA2_BYTES],
    z: &mut PolyVec<L>,
    h: &mut PolyVec<K>,
    sig: &[u8; SIG_BYTES],
) -> bool {
    c_tilde.copy_from_slice(&sig[SIG_CTILDE_OFF..SIG_CTILDE_OFF + LAMBDA2_BYTES]);

    for i in 0..L {
        let start = SIG_Z_OFF + i * POLYZ_BYTES;
        polyz_unpack(
            &mut z.polys[i],
            sig[start..start + POLYZ_BYTES].try_into().unwrap(),
        );
    }

    let hint_bytes: &[u8; OMEGA + K] = sig[SIG_H_OFF..SIG_H_OFF + OMEGA + K].try_into().unwrap();
    unpack_hint(h, hint_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fill_t1(v: &mut PolyVec<K>) {
        for i in 0..K {
            for j in 0..N {
                v.polys[i].coeffs[j] = ((i * 17 + j * 13) & 0x03ff) as i32;
            }
        }
    }

    fn fill_s_eta<const M: usize>(v: &mut PolyVec<M>) {
        for i in 0..M {
            for j in 0..N {
                let t = ((i * 11 + j * 7) % 5) as i32;
                v.polys[i].coeffs[j] = t - ETA;
            }
        }
    }

    fn fill_t0(v: &mut PolyVec<K>) {
        for i in 0..K {
            for j in 0..N {
                let t = ((i * 29 + j * 31) % 8191) as i32;
                v.polys[i].coeffs[j] = (1 << 12) - t;
            }
        }
    }

    #[test]
    fn pk_pack_unpack_roundtrip() {
        let mut rho = [0u8; 32];
        for (i, b) in rho.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(9).wrapping_add(3);
        }

        let mut t1 = PolyVec::<K>::zero();
        fill_t1(&mut t1);

        let mut pk = [0u8; PK_BYTES];
        pack_pk(&mut pk, &rho, &t1);

        let mut rho2 = [0u8; 32];
        let mut t1_2 = PolyVec::<K>::zero();
        unpack_pk(&mut rho2, &mut t1_2, &pk);

        let mut pk2 = [0u8; PK_BYTES];
        pack_pk(&mut pk2, &rho2, &t1_2);
        assert_eq!(pk, pk2);
    }

    #[test]
    fn sk_pack_unpack_roundtrip() {
        let mut rho = [0u8; 32];
        let mut k_seed = [0u8; 32];
        let mut tr = [0u8; 64];
        for i in 0..32 {
            rho[i] = (i as u8).wrapping_mul(5);
            k_seed[i] = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        for (i, b) in tr.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(11);
        }

        let mut s1 = PolyVec::<L>::zero();
        let mut s2 = PolyVec::<K>::zero();
        let mut t0 = PolyVec::<K>::zero();
        fill_s_eta(&mut s1);
        fill_s_eta(&mut s2);
        fill_t0(&mut t0);

        let mut sk = [0u8; SK_BYTES];
        pack_sk(&mut sk, &rho, &k_seed, &tr, &s1, &s2, &t0);

        let mut rho2 = [0u8; 32];
        let mut k2 = [0u8; 32];
        let mut tr2 = [0u8; 64];
        let mut s1_2 = PolyVec::<L>::zero();
        let mut s2_2 = PolyVec::<K>::zero();
        let mut t0_2 = PolyVec::<K>::zero();
        unpack_sk(
            &mut rho2, &mut k2, &mut tr2, &mut s1_2, &mut s2_2, &mut t0_2, &sk,
        );

        let mut sk2 = [0u8; SK_BYTES];
        pack_sk(&mut sk2, &rho2, &k2, &tr2, &s1_2, &s2_2, &t0_2);
        assert_eq!(sk, sk2);
    }
}
