#![allow(missing_docs)]
#![allow(unsafe_code)]

use crypto_bastion::{compare, encapsulate, encrypt, hash, layer_encrypt, onion, sign};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

struct CountingAlloc;

static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static DEALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static REALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static DEALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static REALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAlloc = CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: forwarding to the process global allocator with the same layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        DEALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: forwarding to the process global allocator with the same ptr/layout pair.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        REALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        REALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        // SAFETY: forwarding to the process global allocator with the same ptr/layout contract.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: forwarding to the process global allocator with the same layout.
        unsafe { System.alloc_zeroed(layout) }
    }
}

#[derive(Clone, Copy)]
struct AllocSnapshot {
    alloc_calls: u64,
    dealloc_calls: u64,
    realloc_calls: u64,
    alloc_bytes: u64,
    dealloc_bytes: u64,
    realloc_bytes: u64,
}

#[derive(Clone, Copy)]
struct AllocDelta {
    alloc_calls: u64,
    dealloc_calls: u64,
    realloc_calls: u64,
    alloc_bytes: u64,
    dealloc_bytes: u64,
    realloc_bytes: u64,
}

struct Metric {
    name: &'static str,
    iters: u64,
    total_ns: u128,
    avg_ns: u128,
    ops_per_sec: f64,
    rss_before_kb: u64,
    rss_after_kb: u64,
    rss_delta_kb: i64,
    alloc: AllocDelta,
}

struct CtCheck {
    name: &'static str,
    class_a: &'static str,
    class_b: &'static str,
    avg_a_ns: u128,
    avg_b_ns: u128,
    ratio_ppm: u64,
    threshold_ppm: u64,
    pass: bool,
}

#[inline]
fn alloc_snapshot() -> AllocSnapshot {
    AllocSnapshot {
        alloc_calls: ALLOC_CALLS.load(Ordering::Relaxed),
        dealloc_calls: DEALLOC_CALLS.load(Ordering::Relaxed),
        realloc_calls: REALLOC_CALLS.load(Ordering::Relaxed),
        alloc_bytes: ALLOC_BYTES.load(Ordering::Relaxed),
        dealloc_bytes: DEALLOC_BYTES.load(Ordering::Relaxed),
        realloc_bytes: REALLOC_BYTES.load(Ordering::Relaxed),
    }
}

#[inline]
fn alloc_delta(before: AllocSnapshot, after: AllocSnapshot) -> AllocDelta {
    AllocDelta {
        alloc_calls: after.alloc_calls.saturating_sub(before.alloc_calls),
        dealloc_calls: after.dealloc_calls.saturating_sub(before.dealloc_calls),
        realloc_calls: after.realloc_calls.saturating_sub(before.realloc_calls),
        alloc_bytes: after.alloc_bytes.saturating_sub(before.alloc_bytes),
        dealloc_bytes: after.dealloc_bytes.saturating_sub(before.dealloc_bytes),
        realloc_bytes: after.realloc_bytes.saturating_sub(before.realloc_bytes),
    }
}

#[inline]
fn rss_kb() -> u64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };

    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
        }
    }
    0
}

fn measure<F>(name: &'static str, iters: u64, mut f: F) -> Metric
where
    F: FnMut(),
{
    for _ in 0..8 {
        f();
    }

    let rss_before = rss_kb();
    let alloc_before = alloc_snapshot();
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();
    let alloc_after = alloc_snapshot();
    let rss_after = rss_kb();

    let total_ns = elapsed.as_nanos();
    let avg_ns = if iters == 0 {
        0
    } else {
        total_ns / iters as u128
    };
    let ops_per_sec = if total_ns == 0 {
        0.0
    } else {
        (iters as f64 * 1_000_000_000.0) / total_ns as f64
    };

    Metric {
        name,
        iters,
        total_ns,
        avg_ns,
        ops_per_sec,
        rss_before_kb: rss_before,
        rss_after_kb: rss_after,
        rss_delta_kb: rss_after as i64 - rss_before as i64,
        alloc: alloc_delta(alloc_before, alloc_after),
    }
}

fn avg_ns<F>(iters: u64, mut f: F) -> u128
where
    F: FnMut(),
{
    for _ in 0..8 {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed().as_nanos();
    if iters == 0 {
        0
    } else {
        elapsed / iters as u128
    }
}

fn ct_check<F, G>(
    name: &'static str,
    iters: u64,
    class_a: &'static str,
    mut fa: F,
    class_b: &'static str,
    mut fb: G,
    threshold_ppm: u64,
) -> CtCheck
where
    F: FnMut(),
    G: FnMut(),
{
    let avg_a_ns = avg_ns(iters, || fa());
    let avg_b_ns = avg_ns(iters, || fb());
    let max = avg_a_ns.max(avg_b_ns);
    let min = avg_a_ns.min(avg_b_ns);
    let ratio_ppm = if min == 0 {
        u64::MAX
    } else {
        ((max * 1_000_000u128) / min) as u64
    };
    let pass = ratio_ppm <= threshold_ppm;
    CtCheck {
        name,
        class_a,
        class_b,
        avg_a_ns,
        avg_b_ns,
        ratio_ppm,
        threshold_ppm,
        pass,
    }
}

fn write_report(metrics: &[Metric], ct_checks: &[CtCheck]) -> std::io::Result<()> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut out = String::new();
    out.push_str("Bastion API Benchmark Results\n");
    out.push_str("============================\n");
    out.push_str(&format!("timestamp_unix={ts}\n\n"));

    out.push_str("Columns:\n");
    out.push_str("- perf: avg_ns/op, ops/sec\n");
    out.push_str("- alloc: calls/bytes/realloc, expected_zero_alloc (PASS|FAIL)\n");
    out.push_str("- memory: rss_before_kb, rss_after_kb, rss_delta_kb\n\n");

    for m in metrics {
        let alloc_total_calls = m.alloc.alloc_calls + m.alloc.realloc_calls;
        let expected_zero_alloc = if alloc_total_calls == 0 {
            "PASS"
        } else {
            "FAIL"
        };
        let net_bytes = (m.alloc.alloc_bytes as i128 + m.alloc.realloc_bytes as i128)
            - m.alloc.dealloc_bytes as i128;

        out.push_str(&format!("[{}]\n", m.name));
        out.push_str(&format!(
            "iters={} total_ns={} avg_ns={} ops_per_sec={:.2}\n",
            m.iters, m.total_ns, m.avg_ns, m.ops_per_sec
        ));
        out.push_str(&format!(
            "alloc_calls={} realloc_calls={} dealloc_calls={} alloc_bytes={} realloc_bytes={} dealloc_bytes={} net_bytes={}\n",
            m.alloc.alloc_calls,
            m.alloc.realloc_calls,
            m.alloc.dealloc_calls,
            m.alloc.alloc_bytes,
            m.alloc.realloc_bytes,
            m.alloc.dealloc_bytes,
            net_bytes
        ));
        out.push_str(&format!(
            "expected_zero_alloc={expected_zero_alloc} rss_before_kb={} rss_after_kb={} rss_delta_kb={}\n\n",
            m.rss_before_kb, m.rss_after_kb, m.rss_delta_kb
        ));
    }

    out.push_str("Constant-Time Timing Spread Checks\n");
    out.push_str("==================================\n");
    out.push_str("ratio_ppm = max(avg_a, avg_b) / min(avg_a, avg_b) scaled by 1_000_000\n\n");
    for c in ct_checks {
        let status = if c.pass { "PASS" } else { "FAIL" };
        out.push_str(&format!("[ct/{}]\n", c.name));
        out.push_str(&format!(
            "class_a={} avg_a_ns={} class_b={} avg_b_ns={}\n",
            c.class_a, c.avg_a_ns, c.class_b, c.avg_b_ns
        ));
        out.push_str(&format!(
            "ratio_ppm={} threshold_ppm={} status={}\n\n",
            c.ratio_ppm, c.threshold_ppm, status
        ));
    }

    std::fs::write("results.txt", out)
}

fn main() -> std::io::Result<()> {
    let msg = vec![0xABu8; 4096];
    let msg_other = vec![0xBAu8; 4096];

    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let aad = vec![0x33u8; 32];
    let plaintext = vec![0x44u8; 1024];
    let plaintext_alt = vec![0x77u8; 1024];
    let mut encrypt_out = vec![0u8; plaintext.len()];
    let mut encrypt_tag = [0u8; 16];

    let kem_pk = vec![0x55u8; 1568];
    let kem_pk_alt = vec![0xA5u8; 1568];
    let dsa_sk = vec![0x66u8; 4896];
    let sign_msg = vec![0x77u8; 256];
    let sign_msg_alt = vec![0x13u8; 256];
    let mut kem_ct_out = [0u8; 1568];
    let mut kem_ss_out = [0u8; 32];
    let mut dsa_sig_out = [0u8; 4627];

    let kem0 = vec![0x01u8; 1568];
    let kem1 = vec![0x02u8; 1568];
    let kem2 = vec![0x03u8; 1568];
    let dsa0 = vec![0x11u8; 4896];
    let dsa1 = vec![0x22u8; 4896];
    let dsa2 = vec![0x33u8; 4896];
    let layer_plaintext = vec![0x99u8; 128];
    let layer_plaintext_alt = vec![0x55u8; 128];

    let kem_3 = [kem0.as_slice(), kem1.as_slice(), kem2.as_slice()];
    let dsa_3 = [dsa0.as_slice(), dsa1.as_slice(), dsa2.as_slice()];
    let kem_2 = [kem0.as_slice(), kem1.as_slice()];
    let dsa_2 = [dsa0.as_slice(), dsa1.as_slice()];
    let mut layer_out = vec![0u8; layer_plaintext.len() + (3 * 6223)];
    let mut onion_out = vec![0u8; layer_plaintext.len() + (2 * 6223)];

    let metrics = vec![
        measure("hash/4k", 20_000, || {
            let d = hash(black_box(&msg));
            black_box(d);
        }),
        measure("compare/equal-4k", 20_000, || {
            let eq = compare(black_box(&msg), black_box(&msg));
            black_box(eq);
        }),
        measure("compare/diff-4k", 20_000, || {
            let eq = compare(black_box(&msg), black_box(&msg_other));
            black_box(eq);
        }),
        measure("encrypt/1k", 4_000, || {
            let out = encrypt(
                black_box(&key),
                black_box(&nonce),
                black_box(&aad),
                black_box(&plaintext),
                black_box(&mut encrypt_out),
                black_box(&mut encrypt_tag),
            );
            let _ = black_box(out);
        }),
        measure("encapsulate", 500, || {
            let out = encapsulate(
                black_box(&kem_pk),
                black_box(&mut kem_ct_out),
                black_box(&mut kem_ss_out),
            );
            let _ = black_box(out);
        }),
        measure("sign/256b", 150, || {
            let out = sign(
                black_box(&dsa_sk),
                black_box(&sign_msg),
                black_box(&mut dsa_sig_out),
            );
            let _ = black_box(out);
        }),
        measure("layer_encrypt/3", 40, || {
            let out = layer_encrypt(
                black_box(&layer_plaintext),
                black_box(kem_3),
                black_box(dsa_3),
                black_box(&mut layer_out),
            );
            let _ = black_box(out);
        }),
        measure("onion/2", 40, || {
            let out = onion(
                black_box(&layer_plaintext),
                black_box(&kem_2),
                black_box(&dsa_2),
                black_box(&mut onion_out),
            );
            let _ = black_box(out);
        }),
    ];

    let mut ct_encrypt_out_a = vec![0u8; plaintext.len()];
    let mut ct_encrypt_tag_a = [0u8; 16];
    let mut ct_encrypt_out_b = vec![0u8; plaintext.len()];
    let mut ct_encrypt_tag_b = [0u8; 16];
    let mut ct_kem_ct_a = [0u8; 1568];
    let mut ct_kem_ss_a = [0u8; 32];
    let mut ct_kem_ct_b = [0u8; 1568];
    let mut ct_kem_ss_b = [0u8; 32];
    let mut ct_sig_a = [0u8; 4627];
    let mut ct_sig_b = [0u8; 4627];
    let mut ct_layer_a = vec![0u8; layer_plaintext.len() + (3 * 6223)];
    let mut ct_layer_b = vec![0u8; layer_plaintext.len() + (3 * 6223)];
    let mut ct_onion_a = vec![0u8; layer_plaintext.len() + (2 * 6223)];
    let mut ct_onion_b = vec![0u8; layer_plaintext.len() + (2 * 6223)];

    let ct_checks = vec![
        ct_check(
            "hash",
            12_000,
            "msg_ab",
            || {
                black_box(hash(black_box(&msg)));
            },
            "msg_ba",
            || {
                black_box(hash(black_box(&msg_other)));
            },
            1_200_000,
        ),
        ct_check(
            "compare",
            12_000,
            "equal",
            || {
                black_box(compare(black_box(&msg), black_box(&msg)));
            },
            "different",
            || {
                black_box(compare(black_box(&msg), black_box(&msg_other)));
            },
            1_200_000,
        ),
        ct_check(
            "encrypt",
            3_000,
            "pt_44",
            || {
                let _ = black_box(encrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&aad),
                    black_box(&plaintext),
                    black_box(&mut ct_encrypt_out_a),
                    black_box(&mut ct_encrypt_tag_a),
                ));
            },
            "pt_77",
            || {
                let _ = black_box(encrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&aad),
                    black_box(&plaintext_alt),
                    black_box(&mut ct_encrypt_out_b),
                    black_box(&mut ct_encrypt_tag_b),
                ));
            },
            1_250_000,
        ),
        ct_check(
            "encapsulate",
            400,
            "pk_55",
            || {
                let _ = black_box(encapsulate(
                    black_box(&kem_pk),
                    black_box(&mut ct_kem_ct_a),
                    black_box(&mut ct_kem_ss_a),
                ));
            },
            "pk_a5",
            || {
                let _ = black_box(encapsulate(
                    black_box(&kem_pk_alt),
                    black_box(&mut ct_kem_ct_b),
                    black_box(&mut ct_kem_ss_b),
                ));
            },
            1_300_000,
        ),
        ct_check(
            "sign",
            120,
            "msg_77",
            || {
                let _ = black_box(sign(
                    black_box(&dsa_sk),
                    black_box(&sign_msg),
                    black_box(&mut ct_sig_a),
                ));
            },
            "msg_13",
            || {
                let _ = black_box(sign(
                    black_box(&dsa_sk),
                    black_box(&sign_msg_alt),
                    black_box(&mut ct_sig_b),
                ));
            },
            1_300_000,
        ),
        ct_check(
            "layer_encrypt",
            30,
            "pt_99",
            || {
                let _ = black_box(layer_encrypt(
                    black_box(&layer_plaintext),
                    black_box(kem_3),
                    black_box(dsa_3),
                    black_box(&mut ct_layer_a),
                ));
            },
            "pt_55",
            || {
                let _ = black_box(layer_encrypt(
                    black_box(&layer_plaintext_alt),
                    black_box(kem_3),
                    black_box(dsa_3),
                    black_box(&mut ct_layer_b),
                ));
            },
            1_300_000,
        ),
        ct_check(
            "onion",
            30,
            "pt_99",
            || {
                let _ = black_box(onion(
                    black_box(&layer_plaintext),
                    black_box(&kem_2),
                    black_box(&dsa_2),
                    black_box(&mut ct_onion_a),
                ));
            },
            "pt_55",
            || {
                let _ = black_box(onion(
                    black_box(&layer_plaintext_alt),
                    black_box(&kem_2),
                    black_box(&dsa_2),
                    black_box(&mut ct_onion_b),
                ));
            },
            1_300_000,
        ),
    ];

    write_report(&metrics, &ct_checks)?;
    println!("wrote results.txt");
    Ok(())
}
