#[cfg(test)]
mod tests {
    use crate::mlsigcrypt::specs::ml::field::{caddq, decompose, fqmul, make_hint_ct0, reduce32};
    use crate::mlsigcrypt::specs::ml::keygen::{keypair, keypair_trace};
    use crate::mlsigcrypt::specs::ml::matrix::PolyMatrix;
    use crate::mlsigcrypt::specs::ml::packing::{pack_sig, polyw1_pack, unpack_pk, unpack_sk};
    use crate::mlsigcrypt::specs::ml::params::{
        BETA, GAMMA1, GAMMA2, K, L, LAMBDA2_BYTES, N, OMEGA, PK_BYTES, POLYW1_BYTES, SIG_BYTES,
        SK_BYTES,
    };
    use crate::mlsigcrypt::specs::ml::poly::Poly;
    use crate::mlsigcrypt::specs::ml::sampling::{
        expand_a, expand_mask, sample_in_ball, shake256_absorb_squeeze,
    };
    use crate::mlsigcrypt::specs::ml::vec::PolyVec;
    use hex::decode;

    struct AcvpVector {
        seed: &'static str,
        msg: &'static str,
        key_hash: &'static str,
        sig_hash: &'static str,
    }

    struct AcvpCountVector {
        rejection_count: usize,
        seed: &'static str,
        msg: &'static str,
        key_hash: &'static str,
        sig_hash: &'static str,
    }

    fn hex_to_array<const N: usize>(s: &str) -> [u8; N] {
        let bytes = decode(s).expect("valid hex");
        assert_eq!(bytes.len(), N, "unexpected hex length");
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }

    fn sha256(input: &[u8]) -> [u8; 32] {
        const H0: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        const K256: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        let mut h = H0;
        let bit_len = (input.len() as u64) * 8;
        let mut blocks = Vec::with_capacity(((input.len() + 9) + 63) & !63);
        blocks.extend_from_slice(input);
        blocks.push(0x80);
        while (blocks.len() % 64) != 56 {
            blocks.push(0);
        }
        blocks.extend_from_slice(&bit_len.to_be_bytes());

        let mut w = [0u32; 64];
        for chunk in blocks.chunks_exact(64) {
            for (i, word) in w.iter_mut().take(16).enumerate() {
                let j = i * 4;
                *word = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
            }
            for t in 16..64 {
                let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
                let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
                w[t] = w[t - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[t - 7])
                    .wrapping_add(s1);
            }

            let mut a = h[0];
            let mut b = h[1];
            let mut c = h[2];
            let mut d = h[3];
            let mut e = h[4];
            let mut f = h[5];
            let mut g = h[6];
            let mut hh = h[7];

            for t in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = hh
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K256[t])
                    .wrapping_add(w[t]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);
                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(hh);
        }

        let mut out = [0u8; 32];
        for (i, word) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn digest_hex(input: &[u8]) -> String {
        hex::encode(sha256(input))
    }

    fn first_byte_diff(label: &str, lhs: &[u8], rhs: &[u8]) -> Option<String> {
        lhs.iter()
            .zip(rhs.iter())
            .enumerate()
            .find_map(|(i, (left, right))| {
                (left != right)
                    .then(|| format!("{label}[{i}] local={left:02x} expected={right:02x}"))
            })
            .or_else(|| {
                (lhs.len() != rhs.len())
                    .then(|| format!("{label} length local={} expected={}", lhs.len(), rhs.len()))
            })
    }

    fn first_poly_diff<const M: usize>(
        label: &str,
        lhs: &PolyVec<M>,
        rhs: &PolyVec<M>,
    ) -> Option<String> {
        for i in 0..M {
            for j in 0..N {
                let left = lhs.polys[i].coeffs[j];
                let right = rhs.polys[i].coeffs[j];
                if left != right {
                    return Some(format!(
                        "{label}[poly={i}][coeff={j}] local={left} expected={right}"
                    ));
                }
            }
        }
        None
    }

    fn key_hash_hex(pk: &[u8; PK_BYTES], sk: &[u8; SK_BYTES]) -> String {
        let mut pk_sk = Vec::with_capacity(PK_BYTES + SK_BYTES);
        pk_sk.extend_from_slice(pk);
        pk_sk.extend_from_slice(sk);
        digest_hex(&pk_sk)
    }

    fn assert_hex_eq(label: &str, actual: &str, expected: &str) {
        assert!(
            actual.eq_ignore_ascii_case(expected),
            "{label}: actual={actual} expected={expected}"
        );
    }

    fn sign_internal_with_rejections(
        sig: &mut [u8; SIG_BYTES],
        msg: &[u8],
        sk: &[u8; SK_BYTES],
        rnd: &[u8; 32],
    ) -> usize {
        let mut rho = [0u8; 32];
        let mut k_seed = [0u8; 32];
        let mut tr = [0u8; 64];
        let mut s1: PolyVec<L> = PolyVec::zero();
        let mut s2: PolyVec<K> = PolyVec::zero();
        let mut t0: PolyVec<K> = PolyVec::zero();
        unpack_sk(
            &mut rho,
            &mut k_seed,
            &mut tr,
            &mut s1,
            &mut s2,
            &mut t0,
            sk,
        );

        let mut mu = [0u8; 64];
        shake256_absorb_squeeze(&[&tr, msg], &mut mu);

        let mut rho_prime = [0u8; 64];
        shake256_absorb_squeeze(&[&k_seed[..], &rnd[..], &mu], &mut rho_prime);

        let mut mat_a = PolyMatrix::zero();
        expand_a(&mut mat_a, &rho);

        s1.ntt();
        s2.ntt();
        t0.ntt();

        let mut kappa: u16 = 0;
        let mut rejections = 0usize;

        let mut y: PolyVec<L> = PolyVec::zero();
        let mut y_hat: PolyVec<L> = PolyVec::zero();
        let mut w_hat: PolyVec<K> = PolyVec::zero();
        let mut w: PolyVec<K> = PolyVec::zero();
        let mut w1: PolyVec<K> = PolyVec::zero();
        let mut w0: PolyVec<K> = PolyVec::zero();
        let mut c_hat: Poly = Poly::zero();
        let mut cs1: PolyVec<L> = PolyVec::zero();
        let mut cs2: PolyVec<K> = PolyVec::zero();
        let mut ct0: PolyVec<K> = PolyVec::zero();
        let mut z: PolyVec<L> = PolyVec::zero();
        let mut h: PolyVec<K> = PolyVec::zero();
        let mut c_tilde = [0u8; LAMBDA2_BYTES];
        let mut w1_packed_buf = [0u8; K * POLYW1_BYTES];

        'outer: loop {
            expand_mask(&mut y, &rho_prime, kappa);
            kappa = kappa.wrapping_add(L as u16);

            for i in 0..L {
                y_hat.polys[i].coeffs.copy_from_slice(&y.polys[i].coeffs);
                y_hat.polys[i].ntt();
            }
            mat_a.matvec_ntt(&y_hat, &mut w_hat);

            for i in 0..K {
                w.polys[i].coeffs.copy_from_slice(&w_hat.polys[i].coeffs);
                w.polys[i].inv_ntt();
                w.polys[i].reduce();
                w.polys[i].caddq();
            }

            for i in 0..K {
                for j in 0..N {
                    let (r1, r0) = decompose(w.polys[i].coeffs[j]);
                    w1.polys[i].coeffs[j] = r1;
                    w0.polys[i].coeffs[j] = r0;
                }
            }

            for i in 0..K {
                let start = i * POLYW1_BYTES;
                let end = start + POLYW1_BYTES;
                let packed: &mut [u8; POLYW1_BYTES] = (&mut w1_packed_buf[start..end])
                    .try_into()
                    .expect("fixed-size packed chunk");
                polyw1_pack(packed, &w1.polys[i]);
            }
            shake256_absorb_squeeze(&[&mu, &w1_packed_buf[..]], &mut c_tilde);

            sample_in_ball(&mut c_hat, &c_tilde);
            c_hat.ntt();

            for i in 0..L {
                for j in 0..N {
                    cs1.polys[i].coeffs[j] = fqmul(c_hat.coeffs[j], s1.polys[i].coeffs[j]);
                }
                cs1.polys[i].inv_ntt();
                cs1.polys[i].reduce();
            }
            for i in 0..K {
                for j in 0..N {
                    cs2.polys[i].coeffs[j] = fqmul(c_hat.coeffs[j], s2.polys[i].coeffs[j]);
                    ct0.polys[i].coeffs[j] = fqmul(c_hat.coeffs[j], t0.polys[i].coeffs[j]);
                }
                cs2.polys[i].inv_ntt();
                cs2.polys[i].reduce();
                ct0.polys[i].inv_ntt();
                ct0.polys[i].reduce();
            }

            for i in 0..L {
                for j in 0..N {
                    z.polys[i].coeffs[j] =
                        y.polys[i].coeffs[j].wrapping_add(cs1.polys[i].coeffs[j]);
                }
            }
            if !z.check_norm_lt(GAMMA1 - BETA) {
                rejections += 1;
                continue 'outer;
            }

            let mut reject_r0 = false;
            for i in 0..K {
                for j in 0..N {
                    let r = caddq(reduce32(
                        w.polys[i].coeffs[j].wrapping_sub(cs2.polys[i].coeffs[j]),
                    ));
                    let (_, r0) = decompose(r);
                    w0.polys[i].coeffs[j] = r0;
                    if r0.abs() >= GAMMA2 - BETA {
                        reject_r0 = true;
                    }
                }
            }
            if reject_r0 {
                rejections += 1;
                continue 'outer;
            }

            if !ct0.check_norm_lt(GAMMA2) {
                rejections += 1;
                continue 'outer;
            }

            let mut hint_weight = 0usize;
            for i in 0..K {
                for j in 0..N {
                    let h_bit = make_hint_ct0(
                        ct0.polys[i].coeffs[j],
                        w.polys[i].coeffs[j],
                        cs2.polys[i].coeffs[j],
                    );
                    h.polys[i].coeffs[j] = h_bit;
                    hint_weight += h_bit as usize;
                }
            }
            if hint_weight > OMEGA {
                rejections += 1;
                continue 'outer;
            }

            break 'outer;
        }

        pack_sig(sig, &c_tilde, &z, &h);
        rejections
    }

    #[test]
    fn fips_nist_acvp_table_1_rejection_case_vectors_match() {
        const VECTORS: [AcvpVector; 5] = [
            AcvpVector {
                seed: "0D58219132746BE077DFE821E9F8FD87857B28AB91D6A567E312A73E2636032C",
                msg: "3AA49EF72D010AEC19383BA1E83EC2DD3DCC207A96FFCEB9FFA269E3E3D66400",
                key_hash: "4D261270341A7AC6B66900DDC2B8AB34AB483C897410DDF3B2C072BDDA416434",
                sig_hash: "5049DC39045618B903C71595B3A3E07A731F95D37304623ACC98BCEF4258B4CA",
            },
            AcvpVector {
                seed: "146C47AB9F88408EB76A813294D533B29D7E0FDA75DA5A4E7C69EB61EFEEBB78",
                msg: "82C44F998A8D24F056084D0E80ECFD8434493385A284C69974923C270D397782",
                key_hash: "05194438AF855B79DB8CCCCB647D6BA5C7AAF901BBD09D3B29395F0EA431D164",
                sig_hash: "CFFC5988A351E14A3EE1282F042A143679C4503814296B27993949A7FF966F57",
            },
            AcvpVector {
                seed: "049D9B0B646A2AC7F50B63CE5E4BFE44C9B87634F4FF6C14C513E388B8A1F808",
                msg: "FEBC9F8AE159002BE1A11D395959DD7FC20718135690CDAA2BCFB5801C02AB89",
                key_hash: "AC8FE6B2FE26591B129EA536A9A001C785D8ACBDD9489F6E51469A156E9E635D",
                sig_hash: "FF4006089BDF7337E868F86DDF48F239D2A52EA1D0F686E0103BF19C3B571DB1",
            },
            AcvpVector {
                seed: "9823DDDE446A8EA883DAD3AC6477F79839FDC2D2DEF2416BE0A8B71CFBC3F5C6",
                msg: "F7592C97C1A96A2F4053588F5CDAD4C50BF7C3752709854FA27779B445DD2BA2",
                key_hash: "525010E307C4EA7667D54EE27007C219B01F4CF88DC3AB2DE8E9AAA59440A884",
                sig_hash: "FD7757602B83B0A67A314CD5BCC880E7AE47ACDF4D6AF98269028EFB486838F7",
            },
            AcvpVector {
                seed: "AE213FE8589B414F53780D8B9B6837179967E13CB474C5AD365C043778D2BC90",
                msg: "19C1913BA76FF04596BB7CC80FD825A5AEDEF5D5AD61CEDB5203E6D7EDB18877",
                key_hash: "D4988E91064E5DF6D867434D1DED16DCD8533E39E420DC2B4EB9E40A84146F7D",
                sig_hash: "23FE743EDD101970D499E7EB57A7AA245BAF417E851B260C55DD525A445F08DA",
            },
        ];

        for vector in VECTORS {
            let seed = hex_to_array::<32>(vector.seed);
            let msg = hex_to_array::<32>(vector.msg);

            let mut pk = [0u8; PK_BYTES];
            let mut sk = [0u8; SK_BYTES];
            let mut sig = [0u8; SIG_BYTES];

            keypair(&mut pk, &mut sk, &seed);
            let key_hash = key_hash_hex(&pk, &sk);
            assert_hex_eq("key hash", &key_hash, vector.key_hash);
            sign_internal_with_rejections(&mut sig, &msg, &sk, &[0u8; 32]);
            let sig_hash = digest_hex(&sig);
            assert_hex_eq(
                &format!("signature hash for seed {}", vector.seed),
                &sig_hash,
                vector.sig_hash,
            );
        }
    }

    #[test]
    fn fips_nist_acvp_table_2_rejection_counts_match() {
        const VECTORS: [AcvpCountVector; 5] = [
            AcvpCountVector {
                rejection_count: 64,
                seed: "B5C07ECEFE9E7C3B885FDEF032BDF9F807B4011E2DFE6806C088D2081631C8EB",
                msg: "D1D5C2D167D6E62906790A5FEDF5A0A754CFAF47E6A11AEB93FB8C41934C31F8",
                key_hash: "5D22F4C40F6EEB96BB891DB15884ED4B0009EA02A24D9D1E9ADFC81C7A42EA7F",
                sig_hash: "54F0A9CB26F98B394A35918ECA6760EBD10753FC5CDBA8BE508873AD83538131",
            },
            AcvpCountVector {
                rejection_count: 65,
                seed: "E8FC3C9FAD711DDA2946334FBBD331468D6E9AB48EB86DCD03F300A17AEBC5E5",
                msg: "3B435F7A2CE431C7AB8EAE0991C5DAC610827C99D27803046FBC6C567D6B71F2",
                key_hash: "B6C4DC9B20CE5D0F445931EE316CF0676E806D1A6A98868881D060EA27CEB139",
                sig_hash: "E337495F08773F14FB26A3E229B9B26D086644C7FDC300267F9DCDD5D78DB849",
            },
            AcvpCountVector {
                rejection_count: 64,
                seed: "151F80886D6CE8C3B428964FE02C40CA0C8EFFA100EE089E54D785344FCCF719",
                msg: "C628CE94D2AA99AA50CF15B147D4F9A9C62A3D4612152DE0A502C377F472D614",
                key_hash: "127972C33323FEFBF6B69C19E0C86F41558D9AB2B1A8AD6F39BD0A0245DC8D7E",
                sig_hash: "99B552B21432544248BFF47AC8F24CB78DBB25C9683F3ADCB75614BED58A0358",
            },
            AcvpCountVector {
                rejection_count: 64,
                seed: "48BEFFB4C97E59E474E1906F39888BE5AE62F6A011C05EF6A6B8D1E54F2171B7",
                msg: "D2756A8FB4E47F796AF704ED0FC8C6E573D42DFAB443B329F00F8DB2FF12C465",
                key_hash: "72DA77CF563CBB530129F60129AF989CA4036BA1058267BFBA34A2C70BE803C4",
                sig_hash: "E643914B8556D05360C65EB3E7A06BE7C398B82D49973EEFDC711E65B11EB5E8",
            },
            AcvpCountVector {
                rejection_count: 69,
                seed: "FE2DA9DD93A077FCB6452AC88D0A5762EB896BAAAC6CE7D01CB1370BA8322390",
                msg: "A86B29ADF2300D2636E21D4A350CD18E55A254379C3659A7A95D8734CEC1F005",
                key_hash: "7422DBE3F476FFE41A4EFB33F3DDFD8B328029BA3050603866C36CFBC2EE4B87",
                sig_hash: "8D25818DD972FFF5B9E9B4CC534A95100A1340C1C81D1486A68939D340E0A58B",
            },
        ];

        for vector in VECTORS {
            let seed = hex_to_array::<32>(vector.seed);
            let msg = hex_to_array::<32>(vector.msg);

            let mut pk = [0u8; PK_BYTES];
            let mut sk = [0u8; SK_BYTES];
            let mut sig = [0u8; SIG_BYTES];

            keypair(&mut pk, &mut sk, &seed);
            let key_hash = key_hash_hex(&pk, &sk);
            assert_hex_eq("key hash", &key_hash, vector.key_hash);

            let actual_rejections = sign_internal_with_rejections(&mut sig, &msg, &sk, &[0u8; 32]);
            assert_eq!(
                actual_rejections, vector.rejection_count,
                "seed {}",
                vector.seed
            );
            let sig_hash = digest_hex(&sig);
            assert_hex_eq(
                &format!("signature hash for seed {}", vector.seed),
                &sig_hash,
                vector.sig_hash,
            );
        }
    }

    #[test]
    fn shake256_empty_string_matches_nist_vector() {
        let mut out = [0u8; 32];
        shake256_absorb_squeeze(&[b""], &mut out);
        assert_eq!(
            hex::encode(out),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
    }

    #[test]
    #[ignore = "diagnostic trace for isolating the first ML-DSA-87 keygen divergence against official ACVP vectors"]
    fn fips_nist_acvp_keygen_trace_isolates_first_divergence_for_mldsa87() {
        const SEED: &str = "F7052FBB921759CD8716773BA6355630121D6927899FDDA5768E2BC240FCCB7B";
        const EXPECTED_PK: &str = include_str!("testdata/mldsa87_acvp_keygen_tc51.pk.hex");
        const EXPECTED_SK: &str = include_str!("testdata/mldsa87_acvp_keygen_tc51.sk.hex");
        let seed = hex_to_array::<32>(SEED);
        let expected_pk = hex_to_array::<PK_BYTES>(EXPECTED_PK.trim());
        let expected_sk = hex_to_array::<SK_BYTES>(EXPECTED_SK.trim());

        let trace = keypair_trace(&seed);

        let mut expected_rho_from_pk = [0u8; 32];
        let mut expected_t1 = PolyVec::<K>::zero();
        unpack_pk(&mut expected_rho_from_pk, &mut expected_t1, &expected_pk);

        let mut expected_rho_from_sk = [0u8; 32];
        let mut expected_k_seed = [0u8; 32];
        let mut expected_tr = [0u8; 64];
        let mut expected_s1 = PolyVec::<L>::zero();
        let mut expected_s2 = PolyVec::<K>::zero();
        let mut expected_t0 = PolyVec::<K>::zero();
        unpack_sk(
            &mut expected_rho_from_sk,
            &mut expected_k_seed,
            &mut expected_tr,
            &mut expected_s1,
            &mut expected_s2,
            &mut expected_t0,
            &expected_sk,
        );

        let first = first_byte_diff("seed", &trace.seed, &seed)
            .or_else(|| first_byte_diff("rho(pk)", &trace.rho, &expected_rho_from_pk))
            .or_else(|| first_byte_diff("rho(sk)", &trace.rho, &expected_rho_from_sk))
            .or_else(|| first_byte_diff("K", &trace.k_seed, &expected_k_seed))
            .or_else(|| first_poly_diff("s1", &trace.s1, &expected_s1))
            .or_else(|| first_poly_diff("s2", &trace.s2, &expected_s2))
            .or_else(|| first_poly_diff("t0", &trace.t0, &expected_t0))
            .or_else(|| first_poly_diff("t1", &trace.t1, &expected_t1))
            .or_else(|| first_byte_diff("pk", &trace.pk, &expected_pk))
            .or_else(|| first_byte_diff("tr", &trace.tr, &expected_tr))
            .or_else(|| first_byte_diff("sk", &trace.sk, &expected_sk));

        if let Some(diff) = first {
            panic!("first divergence: {diff}");
        }
    }
}
