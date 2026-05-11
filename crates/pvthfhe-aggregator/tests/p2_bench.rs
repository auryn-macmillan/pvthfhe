//! P2 benchmark matrix: surrogate hash-chain folding at n ∈ {128, 512, 1024}.
//!
//! NOTE: All measurements use the surrogate hash-chain implementation of HashChainFoldingScheme.
//! Results are *not* from a native LatticeFold+ or RLWE-based prover; they reflect SHA-256
//! hash-chain accumulation cost only.  Label all artifacts accordingly.
//!
//! Outputs:
//!   bench/p2/results-128.json
//!   bench/p2/results-512.json
//!   bench/p2/results-1024.json

#![cfg(feature = "real-folding")]
#![allow(missing_docs, clippy::unwrap_used, clippy::as_conversions)]

use pvthfhe_aggregator::folding::{
    finalize, fold, verify_acc, FoldAccumulator, FoldStatement, FoldWitness, NizkProof,
    NizkStatement,
};
use serde::Serialize;
use std::time::Instant;

fn ok<T, E: std::fmt::Debug>(r: Result<T, E>, ctx: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => unreachable!("{ctx}: {e:?}"),
    }
}

// ---------- helpers -----------------------------------------------------------

fn make_acc(n: usize) -> FoldAccumulator {
    FoldAccumulator::new(
        vec![0u8; 32],
        0,
        format!("bench-n{n}"),
        (65537, n, 17),
        [0u8; 32],
    )
}

fn make_stmt(fold_index: u64, n: usize, tag: u8) -> FoldStatement {
    let session = format!("bench-n{n}");
    let params = (65537, n, 17);
    FoldStatement {
        fold_index,
        session_id: session.clone(),
        params,
        nizk_statement: NizkStatement {
            session_id: session,
            params,
            ciphertext_bytes: vec![tag; n / 8], // scales with n for realistic sizing
        },
    }
}

fn make_witness(tag: u8, n: usize) -> FoldWitness {
    FoldWitness {
        nizk_proof: NizkProof {
            nizk_backend_id: NizkProof::EXPECTED_BACKEND_ID,
            // All-same-byte vector passes the uniformity check in validate_witness.
            proof_bytes: vec![tag; n],
        },
        fold_randomness: vec![tag; 32],
    }
}

fn accumulator_size(acc: &FoldAccumulator) -> usize {
    // acc_commitment (vec<u8>) + statement_hash_chain (32 bytes) + session_id + params fields
    acc.acc_commitment().len() + 32 + acc.session_id().len() + 8 + 8 + 8 // params: u64, usize (as u64), u64
}

// ---------- measurement types -------------------------------------------------

#[derive(Serialize)]
struct BenchRow {
    n: usize,
    fold_depth: u32,
    implementation: &'static str,
    fold_time_us: f64,
    verify_time_us: f64,
    finalize_time_us: f64,
    proof_size_bytes: usize,
    acc_size_bytes: usize,
}

#[derive(Serialize)]
struct BenchResults {
    schema_version: &'static str,
    date: &'static str,
    implementation_note: &'static str,
    n: usize,
    rows: Vec<BenchRow>,
}

// ---------- core measurement --------------------------------------------------

fn measure(n: usize, fold_depth: u32) -> BenchRow {
    let tag: u8 = 0x05;
    let params = (65537_u64, n, 17_u64);

    // Build up `fold_depth` folds, timing the whole loop.
    let mut acc = make_acc(n);
    let fold_start = Instant::now();
    for i in 0..fold_depth {
        let stmt = make_stmt(i as u64 + 1, n, tag);
        let wit = make_witness(tag, n);
        acc = ok(fold(&acc, &wit, &stmt), "fold must succeed in benchmark");
    }
    let fold_elapsed_us = fold_start.elapsed().as_secs_f64() * 1_000_000.0;

    // Verify the accumulated proof.
    let verify_start = Instant::now();
    ok(
        verify_acc(&acc, &params),
        "verify_acc must succeed in benchmark",
    );
    let verify_elapsed_us = verify_start.elapsed().as_secs_f64() * 1_000_000.0;

    let finalize_start = Instant::now();
    let final_proof = ok(finalize(&acc), "finalize must succeed in benchmark");
    let finalize_elapsed_us = finalize_start.elapsed().as_secs_f64() * 1_000_000.0;

    let proof_size = final_proof.proof_bytes.len();
    let acc_size = accumulator_size(&acc);

    BenchRow {
        n,
        fold_depth,
        implementation: "surrogate-hash-chain",
        fold_time_us: fold_elapsed_us,
        verify_time_us: verify_elapsed_us,
        finalize_time_us: finalize_elapsed_us,
        proof_size_bytes: proof_size,
        acc_size_bytes: acc_size,
    }
}

// ---------- output helper -----------------------------------------------------

fn write_results(n: usize, rows: Vec<BenchRow>) {
    let results = BenchResults {
        schema_version: "1",
        date: "2026-05-03",
        implementation_note: concat!(
            "Surrogate hash-chain implementation of HashChainFoldingScheme. ",
            "Uses SHA-256 accumulation as a standin for LatticeFold+ over RLWE. ",
            "Timings reflect hash-chain cost only, not real lattice prover work."
        ),
        n,
        rows,
    };

    // Ensure output directory exists (best-effort; test runner must have write access).
    let out_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../bench/p2");
    ok(std::fs::create_dir_all(&out_dir), "create bench/p2 dir");

    let out_path = out_dir.join(format!("results-{n}.json"));
    let json = ok(serde_json::to_string_pretty(&results), "JSON serialization");
    ok(std::fs::write(&out_path, &json), "write results JSON");
    println!("Wrote {}", out_path.display());
}

// ---------- test entry points -------------------------------------------------

#[test]
fn bench_p2_n128() {
    let n = 128;
    let rows: Vec<BenchRow> = [1u32, 5, 10]
        .iter()
        .map(|&d| {
            let row = measure(n, d);
            println!(
                "n={n} depth={d}: fold={:.1}µs verify={:.1}µs finalize={:.1}µs proof={}B acc={}B",
                row.fold_time_us,
                row.verify_time_us,
                row.finalize_time_us,
                row.proof_size_bytes,
                row.acc_size_bytes,
            );
            row
        })
        .collect();
    write_results(n, rows);
}

#[test]
fn bench_p2_n512() {
    let n = 512;
    let rows: Vec<BenchRow> = [1u32, 5, 10]
        .iter()
        .map(|&d| {
            let row = measure(n, d);
            println!(
                "n={n} depth={d}: fold={:.1}µs verify={:.1}µs finalize={:.1}µs proof={}B acc={}B",
                row.fold_time_us,
                row.verify_time_us,
                row.finalize_time_us,
                row.proof_size_bytes,
                row.acc_size_bytes,
            );
            row
        })
        .collect();
    write_results(n, rows);
}

#[test]
fn bench_p2_n1024() {
    let n = 1024;
    let rows: Vec<BenchRow> = [1u32, 5, 10]
        .iter()
        .map(|&d| {
            let row = measure(n, d);
            println!(
                "n={n} depth={d}: fold={:.1}µs verify={:.1}µs finalize={:.1}µs proof={}B acc={}B",
                row.fold_time_us,
                row.verify_time_us,
                row.finalize_time_us,
                row.proof_size_bytes,
                row.acc_size_bytes,
            );
            row
        })
        .collect();
    write_results(n, rows);
}
