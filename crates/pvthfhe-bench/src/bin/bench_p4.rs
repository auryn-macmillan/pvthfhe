//! P4 benchmark binary: measures HermineAdapter performance at n ∈ {128, 512, 1024}.
//!
//! Outputs one JSON file per n to `.sisyphus/evidence/benchmarks/p4/` and prints
//! a summary table to stdout (which `just bench-p4` tees into run.log).

#![allow(missing_docs, deprecated, clippy::expect_used, clippy::as_conversions)]

use pvthfhe_keygen::{hermine::HermineAdapter, KeygenAdapter, Participant};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, time::Instant};

/// Result record for one (n, run) combination.
#[derive(Debug, Serialize, Deserialize)]
struct P4BenchResult {
    n: usize,
    threshold: usize,
    /// Wall-clock time for `generate_session` + `generate_shares` for one dealer (ms).
    keygen_ms: f64,
    /// Wall-clock time for `verify_transcript` × n dealers (ms).
    verify_ms: f64,
    /// Wall-clock time for `reconstruct_bfv_key` from threshold shares (ms).
    reconstruct_ms: f64,
    /// Serialized size of commitments for one dealer (bytes) — proxy for share/proof size.
    share_bytes: usize,
    /// Number of iterations averaged over.
    iters: usize,
}

/// Single end-to-end run for one value of n; returns timings and proof size.
fn run_once(n: usize, threshold: usize) -> (f64, f64, f64, usize) {
    let adapter = HermineAdapter::new();

    // Build participant list
    let participants: Vec<Participant> = (1..=(n as u16)).map(|id| Participant { id }).collect();

    // ── keygen (session + single dealer shares) ──────────────────────────────
    let t0 = Instant::now();
    let session = adapter
        .generate_session(&participants, threshold as u16)
        .expect("generate_session");
    let (shares, artifact) = adapter
        .generate_shares(&session, 1)
        .expect("generate_shares");
    let keygen_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // Proxy share/proof size: total commitment bytes
    let share_bytes: usize = shares
        .iter()
        .filter_map(|s| s.commitment.as_ref())
        .map(|c| c.len())
        .sum();

    // ── verify (n transcripts — simulate by repeating verify_transcript n times) ──
    let mut artifacts = Vec::with_capacity(n);
    // Reuse the single artifact n times as a simulation
    for _ in 0..n {
        artifacts.push(artifact.clone());
    }
    let t1 = Instant::now();
    for a in &artifacts {
        adapter.verify_transcript(a).expect("verify_transcript");
    }
    let verify_ms = t1.elapsed().as_secs_f64() * 1000.0;

    // ── reconstruct from threshold shares ───────────────────────────────────
    let quorum = &shares[..threshold.min(shares.len())];
    let t2 = Instant::now();
    adapter
        .reconstruct_bfv_key(quorum)
        .expect("reconstruct_bfv_key");
    let reconstruct_ms = t2.elapsed().as_secs_f64() * 1000.0;

    (keygen_ms, verify_ms, reconstruct_ms, share_bytes)
}

fn bench_n(n: usize, iters: usize) -> P4BenchResult {
    let threshold = n / 2 + 1;

    // Warm up
    for _ in 0..2 {
        run_once(n, threshold);
    }

    let mut keygen_sum = 0.0f64;
    let mut verify_sum = 0.0f64;
    let mut reconstruct_sum = 0.0f64;
    let mut share_bytes = 0usize;

    for _ in 0..iters {
        let (k, v, r, sb) = run_once(n, threshold);
        keygen_sum += k;
        verify_sum += v;
        reconstruct_sum += r;
        share_bytes = sb; // same every iter (deterministic)
    }

    P4BenchResult {
        n,
        threshold,
        keygen_ms: keygen_sum / iters as f64,
        verify_ms: verify_sum / iters as f64,
        reconstruct_ms: reconstruct_sum / iters as f64,
        share_bytes,
        iters,
    }
}

fn main() {
    let out_dir = Path::new(".sisyphus/evidence/benchmarks/p4");
    fs::create_dir_all(out_dir).expect("create output dir");

    let sizes = [128usize, 512, 1024];
    let iters = 10usize;

    println!("P4 Hermine Benchmark — n ∈ {sizes:?}, {iters} iterations each");
    println!(
        "{:<6} {:<10} {:<10} {:<14} {:<12}",
        "n", "keygen_ms", "verify_ms", "reconstruct_ms", "share_bytes"
    );
    println!("{}", "-".repeat(56));

    let mut all_results = Vec::new();

    for &n in &sizes {
        eprint!("Benchmarking n={n}...");
        let result = bench_n(n, iters);
        println!(
            "{:<6} {:<10.3} {:<10.3} {:<14.3} {:<12}",
            result.n, result.keygen_ms, result.verify_ms, result.reconstruct_ms, result.share_bytes
        );
        eprintln!(" done");

        let json = serde_json::to_string_pretty(&result).expect("serialize");
        let path = out_dir.join(format!("p4-n{n}.json"));
        fs::write(&path, &json).expect("write json");
        eprintln!("  wrote {}", path.display());

        all_results.push(result);
    }

    // Write combined JSON
    let combined_json = serde_json::to_string_pretty(&all_results).expect("serialize combined");
    let combined_path = out_dir.join("p4-all.json");
    fs::write(&combined_path, combined_json).expect("write combined json");
    eprintln!("  wrote {}", combined_path.display());

    println!();
    println!("Done. Results in {}", out_dir.display());
}
