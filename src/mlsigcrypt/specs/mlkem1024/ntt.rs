/// Number Theoretic Transform (NTT) for Z_q[X]/(X^256 + 1).
///
/// The ring Z_3329[X]/(X^256+1) does not split into linear factors mod q.
/// Instead the NTT maps to a product of 128 quadratic extensions:
///   ∏_{i=0}^{127} Z_q[X]/(X^2 − ζ^{2i+1})
/// where ζ = 17 (a primitive 256th root of unity mod q).
///
/// Layers 1..7 perform the standard Cooley-Tukey butterfly (NTT domain).
/// Layer 8 (basemul) handles the quadratic residue products.
///
/// The `ZETAS` table stores the precomputed Montgomery-domain twiddle factors
/// in the order consumed by the 7-layer butterfly schedule (bit-reversed).
/// Both forward and inverse NTT consume the same table in opposite directions.
///
/// Reference: Kyber reference implementation (ntt.c), FIPS 203 §4.3.
use crate::mlsigcrypt::specs::mlkem1024::field::{INV_NTT_SCALE, barrett_reduce, fqmul};

// ── Zeta table ────────────────────────────────────────────────────────────────

/// Precomputed Montgomery-domain NTT twiddle factors.
/// zetas[k] = mont(ζ^{bit_reverse_7(k)}) mod q, k = 1..128.
/// Index 0 is unused (sentinel); table is 1-indexed during butterfly.
pub(crate) const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

// ── Forward NTT ───────────────────────────────────────────────────────────────

/// In-place forward NTT.
///
/// Input:  standard-order polynomial, coefficients in [0, q)
/// Output: NTT-domain representation, coefficients in (-7q, 7q) — reduce before use.
///
/// 7 Cooley-Tukey butterfly layers, k ascending through ZETAS[1..128].
/// The final pair of coefficients (r[2i], r[2i+1]) forms a degree-1 residue
/// in Z_q[X]/(X^2 − zeta^{2*level+1}).
#[inline]
pub(crate) fn ntt(r: &mut [i16; 256]) {
    let mut k: usize = 1;
    let mut len = 128usize;

    while len >= 2 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            let end = start + len;
            for j in start..end {
                // Cooley-Tukey butterfly: t = zeta * r[j+len], then
                //   r[j+len] = r[j] - t
                //   r[j]     = r[j] + t
                let t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
            start = end + len;
        }
        len >>= 1;
    }
}

// ── Inverse NTT ──────────────────────────────────────────────────────────────

/// In-place inverse NTT.
///
/// Input:  NTT-domain coefficients (output of `ntt()`)
/// Output: standard-order polynomial, coefficients in (-q, q) after scaling.
///
/// 7 Gentleman-Sande butterfly layers, k descending through ZETAS[127..1].
/// Final pass multiplies every coefficient by INV_NTT_SCALE = mont(128^{-1}).
#[inline]
pub(crate) fn inv_ntt(r: &mut [i16; 256]) {
    let mut k: usize = 127;
    let mut len = 2usize;

    while len <= 128 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS[k];
            k = k.wrapping_sub(1);
            let end = start + len;
            for j in start..end {
                // Gentleman-Sande butterfly
                let t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = r[j + len] - t;
                r[j + len] = fqmul(zeta, r[j + len]);
            }
            start = end + len;
        }
        len <<= 1;
    }

    // Scale by 128^{-1} mod q in Montgomery domain.
    for coeff in r.iter_mut() {
        *coeff = fqmul(INV_NTT_SCALE, *coeff);
    }
}

// ── Base multiplication ───────────────────────────────────────────────────────

/// Pointwise multiplication of two NTT-domain polynomials.
///
/// Each pair (a[2i], a[2i+1]) × (b[2i], b[2i+1]) is a multiplication in
/// Z_q[X]/(X^2 − zeta^{2i+1}), i.e. the degree-1 ring for that pair.
///
///   (a0 + a1*X)(b0 + b1*X) mod (X^2 − ζ) = (a0*b0 + a1*b1*ζ) + (a0*b1 + a1*b0)*X
///
/// Result accumulated into `r`; caller should reduce after K multiplications.
#[inline]
pub(crate) fn basemul_acc(r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256], zeta: i16) {
    // Process 128 quadratic pairs.
    for i in (0..256).step_by(2) {
        let a0 = a[i];
        let a1 = a[i + 1];
        let b0 = b[i];
        let b1 = b[i + 1];
        // Use a different zeta for each pair: zeta for pair i = ZETAS[64 + i/2]
        // (the caller passes the correct zeta for this pair externally — see poly.rs)
        r[i] = r[i].wrapping_add(fqmul(a0, b0).wrapping_add(fqmul(fqmul(a1, b1), zeta)));
        r[i + 1] = r[i + 1].wrapping_add(fqmul(a0, b1).wrapping_add(fqmul(a1, b0)));
    }
}

/// Pointwise multiply two NTT-domain polynomials into `out` (not accumulated).
///
/// Uses the per-pair zeta from the second half of ZETAS (indices 64..128).
/// This is the single-product variant; for inner products use `polyvec_basemul_acc`
/// in vec.rs which accumulates K calls.
#[inline]
pub(crate) fn poly_basemul(a: &[i16; 256], b: &[i16; 256], out: &mut [i16; 256]) {
    out.fill(0);
    for i in 0..64usize {
        let zeta = ZETAS[64 + i];
        basemul_pair(
            &a[4 * i..4 * i + 2],
            &b[4 * i..4 * i + 2],
            zeta,
            (&mut out[4 * i..4 * i + 2]).try_into().unwrap(),
        );
        basemul_pair(
            &a[4 * i + 2..4 * i + 4],
            &b[4 * i + 2..4 * i + 4],
            -zeta,
            (&mut out[4 * i + 2..4 * i + 4]).try_into().unwrap(),
        );
    }
}

#[inline]
fn basemul_pair(a: &[i16], b: &[i16], zeta: i16, out: &mut [i16; 2]) {
    out[0] = fqmul(a[1], b[1]);
    out[0] = fqmul(out[0], zeta).wrapping_add(fqmul(a[0], b[0]));
    out[1] = fqmul(a[0], b[1]).wrapping_add(fqmul(a[1], b[0]));
}
