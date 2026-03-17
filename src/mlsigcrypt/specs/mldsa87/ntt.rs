/// 256-point Number Theoretic Transform over Z_q, q = 8380417.
///
/// Twiddle factors are taken from the Dilithium reference implementation.
///
/// Forward NTT (Cooley-Tukey, in-place, bit-reversed output):
///   for len in [128, 64, 32, 16, 8, 4, 2, 1]:
///     for each group of 2*len elements:
///       zeta = zetas[++k]
///       butterfly: (a[j], a[j+len]) → (a[j]+t, a[j]-t) where t = mont(zeta*a[j+len])
///
/// Inverse NTT (Gentleman-Sande, in-place):
///   for len in [1, 2, 4, 8, 16, 32, 64, 128]:
///     for each group of 2*len elements:
///       zeta = zetas[--k]
///       butterfly: t = a[j]; a[j] = t+a[j+len]; a[j+len] = mont(zeta*(t-a[j+len]))
///   final scale: a[j] = mont(INTT_SCALE * a[j])  ∀j
///
/// INTT_SCALE = mont(N^{-1} × R) encodes both the 1/N division and the R factor
/// from the Montgomery arithmetic. ⚠ Verify against FIPS 204 KAT vectors before deployment.
///
/// Reference: crystals-dilithium reference implementation, ntt.c (public domain).
use crate::mlsigcrypt::specs::mldsa87::field::{fqmul, montgomery_reduce};
use crate::mlsigcrypt::specs::mldsa87::params::N;

// ── Zeta table ────────────────────────────────────────────────────────────────

/// Montgomery-domain twiddle factors from the Dilithium reference implementation.
pub(crate) const ZETAS: [i32; 256] = [
    0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2353451, -359251,
    -2091905, 3119733, -2884855, 3111497, 2680103, 2725464, 1024112, -1079900, 3585928, -549488,
    -1119584, 2619752, -2108549, -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497,
    280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439, -3861115,
    -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267, -1643818, 3505694,
    -3821735, 3507263, -2140649, -1600420, 3699596, 811944, 531354, 954230, 3881043, 3900724,
    -2556880, 2071892, -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
    2176455, -1585221, -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
    3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047, -671102, -1228525,
    -22981, -1308169, -381987, 1349076, 1852771, -1430430, -3343383, 264944, 508951, 3097992,
    44288, -1100098, 904516, 3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969,
    -1316856, 189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669,
    -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961, 2091667, 3407706, 2316500,
    3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439, -1235728, 3513181, -3520352,
    -3759364, -1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174, -43260,
    -522500, -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297,
    286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044, 2842341, 2691481, -2590150,
    1265009, 4055324, 1247620, 2486353, 1595974, -3767016, 1250494, 2635921, -3548272, -2994039,
    1869119, 1903435, -1050970, -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115,
    -1962642, -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
    -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993, -2013608, 2432395, 2454455,
    -164721, 1957272, 3369112, 185531, -1207385, -3183426, 162844, 1616392, 3014001, 810149,
    1652634, -3694233, -1799107, -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735,
    472078, -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893, -2939036,
    -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687, -554416, 3919660, -48306,
    -1362209, 3937738, 1400424, -846154, 1976782,
];

/// Final INTT scaling factor encodes 1/N correction in Montgomery form.
///
/// After Gentleman-Sande butterflies, each output is N × NTT^{−1}(input) with a residual R
/// factor from the montgomery_reduce operations. INTT_SCALE = mont(N^{-1} × R^{?}) cancels both.
///
/// ⚠  Value 41978 is taken from the Dilithium reference implementation (ntt.c).
///    It MUST be verified against FIPS 204 KAT vectors before deployment.
pub(crate) const INTT_SCALE: i32 = 41978;

// ── Forward NTT ───────────────────────────────────────────────────────────────

/// In-place forward NTT.
///
/// Input:  standard-order coefficients in [0, q) or (−q, q).
/// Output: NTT-domain (bit-reversed), coefficients in (−7q, 7q) — reduce before use.
///
/// The loop structure follows Cooley-Tukey with `++k` walking through ZETAS[1..255].
#[inline]
pub(crate) fn ntt(a: &mut [i32; N]) {
    let mut k: usize = 0;
    let mut len = 128usize;

    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            k += 1;
            let zeta = ZETAS[k];
            let end = start + len;
            for j in start..end {
                let t = fqmul(zeta, a[j + len]);
                a[j + len] = a[j] - t;
                a[j] += t;
            }
            start = end + len;
        }
        len >>= 1;
    }
}

// ── Inverse NTT ──────────────────────────────────────────────────────────────

/// In-place inverse NTT.
///
/// Input:  NTT-domain coefficients (output of `ntt`).
/// Output: standard-order polynomial, coefficients reduced via INTT_SCALE.
///
/// Gentleman-Sande butterflies with k descending through ZETAS[255..1],
/// followed by scalar multiplication by INTT_SCALE.
#[inline]
pub(crate) fn inv_ntt(a: &mut [i32; N]) {
    let mut k: usize = 256;
    let mut len = 1usize;

    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            k -= 1;
            let zeta = -ZETAS[k];
            let end = start + len;
            for j in start..end {
                let t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = montgomery_reduce(zeta as i64 * (t - a[j + len]) as i64);
            }
            start = end + len;
        }
        len <<= 1;
    }

    // Scale by N^{-1} (absorbed into INTT_SCALE along with the residual R factor).
    for coeff in a.iter_mut() {
        *coeff = montgomery_reduce(INTT_SCALE as i64 * *coeff as i64);
    }
}

// ── Pointwise multiplication ──────────────────────────────────────────────────

/// Pointwise Montgomery multiply two NTT-domain polynomials: out[i] = a[i] × b[i] / R mod q.
#[inline]
pub(crate) fn poly_pointwise_montgomery(a: &[i32; N], b: &[i32; N], out: &mut [i32; N]) {
    for i in 0..N {
        out[i] = fqmul(a[i], b[i]);
    }
}

/// Accumulate pointwise product: out[i] += a[i] × b[i] / R mod q.
#[inline]
pub(crate) fn poly_pointwise_acc(a: &[i32; N], b: &[i32; N], out: &mut [i32; N]) {
    for i in 0..N {
        out[i] = out[i].wrapping_add(fqmul(a[i], b[i]));
    }
}

// ── Reduce ────────────────────────────────────────────────────────────────────

/// Reduce all coefficients to (−2^22, 2^22] via reduce32.
#[inline]
pub(crate) fn poly_reduce(a: &mut [i32; N]) {
    for c in a.iter_mut() {
        *c = crate::mlsigcrypt::specs::mldsa87::field::reduce32(*c);
    }
}

/// Shift all coefficients into [0, q) via caddq.
#[inline]
pub(crate) fn poly_caddq(a: &mut [i32; N]) {
    for c in a.iter_mut() {
        *c = crate::mlsigcrypt::specs::mldsa87::field::caddq(*c);
    }
}
