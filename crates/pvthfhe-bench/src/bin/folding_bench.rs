#![allow(missing_docs, clippy::as_conversions)]

use pvthfhe_bench::{
    folding::{
        accumulator_size_bytes, prove_final_snark, run_folding_loop, sample_r1cs_instance, verify_final_snark,
    },
    summarize_samples, BenchEnv,
};
use serde::Serialize;
use std::{fs, path::PathBuf, time::Instant};

const CASES: [usize; 4] = [16, 64, 256, 1024];
const N_RUNS: usize = 10;

#[derive(Debug, Serialize)]
struct FoldingBenchResult {
    name: String,
    mean: f64,
    median: f64,
    p99: f64,
    stddev: f64,
    n_runs: usize,
    env: BenchEnv,
    fold_count: usize,
    per_fold_ms: f64,
    accumulator_bytes: usize,
    final_snark_prover_ms: f64,
    final_snark_bytes: usize,
    verifier_ms: f64,
}

fn main() {
    let verify_only = std::env::args().skip(1).any(|arg| arg == "--verify-only");
    if verify_only {
        verify_mode();
        return;
    }

    let env = BenchEnv::capture();
    let output_dir = repo_root().join("bench/results");
    if let Err(_err) = fs::create_dir_all(&output_dir) {
        std::process::abort();
    }

    for fold_count in CASES {
        let result = benchmark_case(fold_count, env.clone());
        let path = output_dir.join(format!("folding-{fold_count}.json"));
        let json = match serde_json::to_vec(&result) {
            Ok(json) => json,
            Err(_err) => std::process::abort(),
        };
        if let Err(_err) = fs::write(&path, json) {
            std::process::abort();
        }
        println!("wrote {}", path.display());
    }
}

fn benchmark_case(fold_count: usize, env: BenchEnv) -> FoldingBenchResult {
    let instance = sample_r1cs_instance();
    let mut fold_samples_ms = Vec::with_capacity(N_RUNS);
    let mut prover_samples_ms = Vec::with_capacity(N_RUNS);
    let mut verifier_samples_ms = Vec::with_capacity(N_RUNS);
    let mut accumulator_bytes = 0;
    let mut final_snark_bytes = 0;

    for _ in 0..N_RUNS {
        let summary = run_folding_loop(&instance, fold_count);
        let proof_start = Instant::now();
        let proof = prove_final_snark(&summary.accumulator, &instance);
        let prover_ms = proof_start.elapsed().as_secs_f64() * 1_000.0;

        let verify_start = Instant::now();
        let verified = verify_final_snark(&proof, &summary.accumulator, &instance);
        let verifier_ms = verify_start.elapsed().as_secs_f64() * 1_000.0;
        assert!(verified, "final snark verification must succeed");

        accumulator_bytes = accumulator_size_bytes(&summary.accumulator);
        final_snark_bytes = proof.bytes.len();
        fold_samples_ms.push(summary.total_fold_ms);
        prover_samples_ms.push(prover_ms);
        verifier_samples_ms.push(verifier_ms);
    }

    let fold_stats = summarize_samples(&fold_samples_ms);
    let p99 = percentile(&fold_samples_ms, 0.99);
    let prover_stats = summarize_samples(&prover_samples_ms);
    let verifier_stats = summarize_samples(&verifier_samples_ms);

    FoldingBenchResult {
        name: format!("folding-N{fold_count}"),
        mean: fold_stats.mean_ns,
        median: fold_stats.median_ns,
        p99,
        stddev: fold_stats.stddev_ns,
        n_runs: N_RUNS,
        env,
        fold_count,
        per_fold_ms: fold_stats.mean_ns / fold_count as f64,
        accumulator_bytes,
        final_snark_prover_ms: prover_stats.mean_ns,
        final_snark_bytes,
        verifier_ms: verifier_stats.mean_ns,
    }
}

fn percentile(samples: &[f64], quantile: f64) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(|left, right| left.total_cmp(right));
    let index = ((sorted.len() - 1) as f64 * quantile).ceil() as usize;
    sorted[index]
}

fn verify_mode() {
    let instance = sample_r1cs_instance();
    for fold_count in CASES {
        let summary = run_folding_loop(&instance, fold_count);
        let proof = prove_final_snark(&summary.accumulator, &instance);
        assert!(verify_final_snark(&proof, &summary.accumulator, &instance));
        println!(
            "verified fold_count={fold_count} accumulator_bytes={} final_snark_bytes={}",
            accumulator_size_bytes(&summary.accumulator),
            proof.bytes.len()
        );
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap_or_else(|| std::process::abort())
        .to_path_buf()
}
