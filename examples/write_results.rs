#![allow(missing_docs)]
#![allow(unsafe_code)]

use crypto_bastion::{
    MLSIGCRYPT_PACKET_OVERHEAD, MLSIGCRYPT_PUBLIC_KEY_SIZE, MLSIGCRYPT_SECRET_KEY_SIZE,
    mlsigcrypt_keygen, mlsigcrypt_signcrypt, mlsigcrypt_unsigncrypt,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_KEYGEN_FLOOR_NS: u64 = 0;
const DEFAULT_SIGNCRYPT_FLOOR_NS: u64 = 20_000_000;
const DEFAULT_UNSIGNCRYPT_FLOOR_NS: u64 = 10_000_000;
const ENV_KEYGEN_FLOOR_NS: &str = "BASTION_MLSIGCRYPT_KEYGEN_FLOOR_NS";
const ENV_SIGNCRYPT_FLOOR_NS: &str = "BASTION_MLSIGCRYPT_SIGNCRYPT_FLOOR_NS";
const ENV_UNSIGNCRYPT_FLOOR_NS: &str = "BASTION_MLSIGCRYPT_UNSIGNCRYPT_FLOOR_NS";

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
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        DEALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        REALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        REALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
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

#[derive(Clone, Copy)]
struct TimingFloors {
    keygen_ns: u64,
    signcrypt_ns: u64,
    unsigncrypt_ns: u64,
}

fn parse_floor_ns(value: Option<std::ffi::OsString>, default: u64) -> u64 {
    value
        .and_then(|raw| raw.into_string().ok())
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn configured_timing_floors() -> TimingFloors {
    TimingFloors {
        keygen_ns: parse_floor_ns(
            std::env::var_os(ENV_KEYGEN_FLOOR_NS),
            DEFAULT_KEYGEN_FLOOR_NS,
        ),
        signcrypt_ns: parse_floor_ns(
            std::env::var_os(ENV_SIGNCRYPT_FLOOR_NS),
            DEFAULT_SIGNCRYPT_FLOOR_NS,
        ),
        unsigncrypt_ns: parse_floor_ns(
            std::env::var_os(ENV_UNSIGNCRYPT_FLOOR_NS),
            DEFAULT_UNSIGNCRYPT_FLOOR_NS,
        ),
    }
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
    let avg_a_ns = avg_ns(iters, &mut fa);
    let avg_b_ns = avg_ns(iters, &mut fb);
    let max = avg_a_ns.max(avg_b_ns);
    let min = avg_a_ns.min(avg_b_ns);
    let ratio_ppm = if min == 0 {
        u64::MAX
    } else {
        ((max * 1_000_000u128) / min) as u64
    };

    CtCheck {
        name,
        class_a,
        class_b,
        avg_a_ns,
        avg_b_ns,
        ratio_ppm,
        threshold_ppm,
        pass: ratio_ppm <= threshold_ppm,
    }
}

fn write_report(
    metrics: &[Metric],
    ct_checks: &[CtCheck],
    floors: TimingFloors,
) -> std::io::Result<()> {
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

    out.push_str("Timing Floor Configuration:\n");
    out.push_str("===========================\n");
    out.push_str(&format!(
        "{}={}ns\n{}={}ns\n{}={}ns\n\n",
        ENV_KEYGEN_FLOOR_NS,
        floors.keygen_ns,
        ENV_SIGNCRYPT_FLOOR_NS,
        floors.signcrypt_ns,
        ENV_UNSIGNCRYPT_FLOOR_NS,
        floors.unsigncrypt_ns
    ));

    for metric in metrics {
        let alloc_total_calls = metric.alloc.alloc_calls + metric.alloc.realloc_calls;
        let expected_zero_alloc = if alloc_total_calls == 0 {
            "PASS"
        } else {
            "FAIL"
        };
        let net_bytes = metric
            .alloc
            .alloc_bytes
            .saturating_add(metric.alloc.realloc_bytes)
            .saturating_sub(metric.alloc.dealloc_bytes);

        out.push_str(&format!("[{}]\n", metric.name));
        out.push_str(&format!(
            "iters={} total_ns={} avg_ns={} ops_per_sec={:.2}\n",
            metric.iters, metric.total_ns, metric.avg_ns, metric.ops_per_sec
        ));
        out.push_str(&format!(
            "alloc_calls={} realloc_calls={} dealloc_calls={} alloc_bytes={} realloc_bytes={} dealloc_bytes={} net_bytes={}\n",
            metric.alloc.alloc_calls,
            metric.alloc.realloc_calls,
            metric.alloc.dealloc_calls,
            metric.alloc.alloc_bytes,
            metric.alloc.realloc_bytes,
            metric.alloc.dealloc_bytes,
            net_bytes
        ));
        out.push_str(&format!(
            "expected_zero_alloc={} rss_before_kb={} rss_after_kb={} rss_delta_kb={}\n\n",
            expected_zero_alloc, metric.rss_before_kb, metric.rss_after_kb, metric.rss_delta_kb
        ));
    }

    out.push_str("Constant-Time Timing Spread Checks\n");
    out.push_str("==================================\n");
    out.push_str("ratio_ppm = max(avg_a, avg_b) / min(avg_a, avg_b) scaled by 1_000_000\n\n");

    for check in ct_checks {
        let status = if check.pass { "PASS" } else { "FAIL" };
        out.push_str(&format!("[ct/{}]\n", check.name));
        out.push_str(&format!(
            "class_a={} avg_a_ns={} class_b={} avg_b_ns={}\n",
            check.class_a, check.avg_a_ns, check.class_b, check.avg_b_ns
        ));
        out.push_str(&format!(
            "ratio_ppm={} threshold_ppm={} status={}\n\n",
            check.ratio_ppm, check.threshold_ppm, status
        ));
    }

    std::fs::write("results.txt", out)
}

fn main() -> std::io::Result<()> {
    let aad = vec![0x5Cu8; 48];
    let msg = vec![0xC3u8; 256];
    let msg_alt = vec![0x3Cu8; 256];

    let mut sender_pk = [0u8; MLSIGCRYPT_PUBLIC_KEY_SIZE];
    let mut sender_sk = [0u8; MLSIGCRYPT_SECRET_KEY_SIZE];
    let mut recipient_pk = [0u8; MLSIGCRYPT_PUBLIC_KEY_SIZE];
    let mut recipient_sk = [0u8; MLSIGCRYPT_SECRET_KEY_SIZE];
    let mut keygen_pk = [0u8; MLSIGCRYPT_PUBLIC_KEY_SIZE];
    let mut keygen_sk = [0u8; MLSIGCRYPT_SECRET_KEY_SIZE];

    let _ = mlsigcrypt_keygen(&mut sender_pk, &mut sender_sk);
    let _ = mlsigcrypt_keygen(&mut recipient_pk, &mut recipient_sk);

    let mut packet = vec![0u8; MLSIGCRYPT_PACKET_OVERHEAD + msg.len()];
    let mut packet_alt = vec![0u8; MLSIGCRYPT_PACKET_OVERHEAD + msg_alt.len()];
    let mut opened = vec![0u8; msg.len()];
    let mut opened_alt = vec![0u8; msg_alt.len()];

    let packet_len =
        mlsigcrypt_signcrypt(&sender_sk, &recipient_pk, &aad, &msg, &mut packet).unwrap_or(0);
    let packet_alt_len =
        mlsigcrypt_signcrypt(&sender_sk, &recipient_pk, &aad, &msg_alt, &mut packet_alt)
            .unwrap_or(0);
    let floors = configured_timing_floors();

    let metrics = vec![
        measure("mlsigcrypt_keygen", 30, || {
            let out = mlsigcrypt_keygen(black_box(&mut keygen_pk), black_box(&mut keygen_sk));
            let _ = black_box(out);
        }),
        measure("mlsigcrypt_signcrypt/256b", 80, || {
            let out = mlsigcrypt_signcrypt(
                black_box(&sender_sk),
                black_box(&recipient_pk),
                black_box(&aad),
                black_box(&msg),
                black_box(&mut packet),
            );
            let _ = black_box(out);
        }),
        measure("mlsigcrypt_unsigncrypt/256b", 80, || {
            let out = mlsigcrypt_unsigncrypt(
                black_box(&recipient_sk),
                black_box(&sender_pk),
                black_box(&aad),
                black_box(&packet[..packet_len]),
                black_box(&mut opened),
            );
            let _ = black_box(out);
        }),
    ];

    let mut ct_packet_a = vec![0u8; MLSIGCRYPT_PACKET_OVERHEAD + msg.len()];
    let mut ct_packet_b = vec![0u8; MLSIGCRYPT_PACKET_OVERHEAD + msg_alt.len()];

    let ct_checks = vec![
        ct_check(
            "mlsigcrypt_signcrypt",
            60,
            "msg_c3",
            || {
                let _ = black_box(mlsigcrypt_signcrypt(
                    black_box(&sender_sk),
                    black_box(&recipient_pk),
                    black_box(&aad),
                    black_box(&msg),
                    black_box(&mut ct_packet_a),
                ));
            },
            "msg_3c",
            || {
                let _ = black_box(mlsigcrypt_signcrypt(
                    black_box(&sender_sk),
                    black_box(&recipient_pk),
                    black_box(&aad),
                    black_box(&msg_alt),
                    black_box(&mut ct_packet_b),
                ));
            },
            1_400_000,
        ),
        ct_check(
            "mlsigcrypt_unsigncrypt",
            60,
            "pkt_c3",
            || {
                let _ = black_box(mlsigcrypt_unsigncrypt(
                    black_box(&recipient_sk),
                    black_box(&sender_pk),
                    black_box(&aad),
                    black_box(&packet[..packet_len]),
                    black_box(&mut opened),
                ));
            },
            "pkt_3c",
            || {
                let _ = black_box(mlsigcrypt_unsigncrypt(
                    black_box(&recipient_sk),
                    black_box(&sender_pk),
                    black_box(&aad),
                    black_box(&packet_alt[..packet_alt_len]),
                    black_box(&mut opened_alt),
                ));
            },
            1_400_000,
        ),
    ];

    write_report(&metrics, &ct_checks, floors)?;
    println!("wrote results.txt");
    Ok(())
}
