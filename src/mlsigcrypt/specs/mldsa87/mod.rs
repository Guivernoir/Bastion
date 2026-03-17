pub(crate) mod field;
pub(crate) mod keygen;
pub(crate) mod matrix;
pub(crate) mod ntt;
pub(crate) mod packing;
/// ML-DSA-87 module — NIST security level 5 digital signature scheme.
///
/// FIPS 204 compliant implementation. Parameter set: K=8, L=7, η=2, γ₁=2^19, γ₂=(q−1)/32, ω=75.
///
/// # Public interface
/// The three cryptographic operations are exposed via `keygen`, `sign`, and `verify`.
/// All other items are `pub(crate)` — internal to this module tree.
///
/// # Module layout
///
///   params.rs          — numeric constants and compile-time sanity checks
///   field.rs           — Z_q arithmetic (Montgomery, Barrett, Decompose, hints)
///   ntt.rs             — 256-point NTT over Z_q
///   poly.rs            — Polynomial type [i32; 256] with arithmetic
///   vec.rs             — `PolyVec<M>` generic polynomial vector
///   matrix.rs          — K×L polynomial matrix, matrix-vector products
///   sampling.rs        — ExpandA, ExpandS, ExpandMask, SampleInBall
///   packing.rs         — Bit-packing / encoding for pk, sk, sig
///   keygen.rs          — Algorithm 1: ML-DSA.KeyGen
///   sign.rs            — Algorithm 2: ML-DSA.Sign
///   verify.rs          — Algorithm 3: ML-DSA.Verify
pub(crate) mod params;
pub(crate) mod poly;
pub(crate) mod sampling;
pub(crate) mod sign;
pub(crate) mod vec;
pub(crate) mod verify;

// ── Re-export the primary API ─────────────────────────────────────────────────

#[allow(unused_imports)]
pub(crate) use keygen::keypair;
#[allow(unused_imports)]
pub(crate) use sign::sign;
#[allow(unused_imports)]
pub(crate) use verify::verify;

// ── Key / signature sizes (re-exported for callers) ──────────────────────────

#[allow(unused_imports)]
pub(crate) use params::{PK_BYTES, SIG_BYTES, SK_BYTES};

#[cfg(test)]
mod tests {
    use super::keygen::keypair;
    use super::params::{PK_BYTES, SIG_BYTES, SK_BYTES};
    use super::sign::sign;
    use super::verify::verify;

    #[test]
    fn sign_verify_roundtrip() {
        let seed = [0x42u8; 32];
        let rnd = [0u8; 32];
        let msg = b"ml-dsa87 roundtrip";

        let mut pk = [0u8; PK_BYTES];
        let mut sk = [0u8; SK_BYTES];
        let mut sig = [0u8; SIG_BYTES];

        keypair(&mut pk, &mut sk, &seed);
        sign(&mut sig, msg, &sk, &rnd);
        assert!(verify(&sig, msg, &pk));
    }

    #[test]
    fn tampered_message_fails() {
        let seed = [0xA5u8; 32];
        let rnd = [0x11u8; 32];

        let mut pk = [0u8; PK_BYTES];
        let mut sk = [0u8; SK_BYTES];
        let mut sig = [0u8; SIG_BYTES];
        let msg = b"original";
        let tampered = b"originaL";

        keypair(&mut pk, &mut sk, &seed);
        sign(&mut sig, msg, &sk, &rnd);
        assert!(!verify(&sig, tampered, &pk));
    }

    #[test]
    fn tampered_signature_fails() {
        let seed = [0x5Au8; 32];
        let rnd = [0x22u8; 32];
        let msg = b"signature tamper test";

        let mut pk = [0u8; PK_BYTES];
        let mut sk = [0u8; SK_BYTES];
        let mut sig = [0u8; SIG_BYTES];

        keypair(&mut pk, &mut sk, &seed);
        sign(&mut sig, msg, &sk, &rnd);
        sig[SIG_BYTES - 1] ^= 0x01;
        assert!(!verify(&sig, msg, &pk));
    }

    #[test]
    fn deterministic_with_fixed_seed_and_rnd() {
        let seed = [0x33u8; 32];
        let rnd = [0u8; 32];
        let msg = b"deterministic test";

        let mut pk = [0u8; PK_BYTES];
        let mut sk = [0u8; SK_BYTES];
        let mut sig_a = [0u8; SIG_BYTES];
        let mut sig_b = [0u8; SIG_BYTES];

        keypair(&mut pk, &mut sk, &seed);
        sign(&mut sig_a, msg, &sk, &rnd);
        sign(&mut sig_b, msg, &sk, &rnd);
        assert_eq!(sig_a, sig_b);
    }
}
