//! Criterion bench for F9 aggregate_1024 support.
#![allow(missing_docs)]

use criterion::{criterion_group, criterion_main, Criterion};
use pvthfhe_aggregator::folding::HashChainCycloAdapter;
use pvthfhe_cyclo::CcsPShareInstance;
use pvthfhe_cyclo::CycloError;
use pvthfhe_types::CcsWitnessSecret;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::Instant;

const N_SHARES: u16 = 1024;
const WALL_TIME_CAP_MS: u128 = 5_000;

#[derive(Serialize)]
struct AggregateBenchResult {
    n: usize,
    wall_ms: u128,
    status: &'static str,
    batch_count: usize,
    batch_size: usize,
}

fn make_share(participant_id: u16) -> CcsPShareInstance {
    let seed = participant_id.to_le_bytes();
    let ajtai_commitment_bytes = vec![seed[0]; 32];
    let public_io_bytes = vec![seed[1].wrapping_add(1); 32];
    let ccs_witness_bytes = vec![(seed[0] % 101).wrapping_add(seed[1] % 2); 32];
    let sha256_binding_bytes: [u8; 32] = Sha256::new()
        .chain_update(&ajtai_commitment_bytes)
        .chain_update(&public_io_bytes)
        .chain_update(&ccs_witness_bytes)
        .finalize()
        .into();

    CcsPShareInstance {
        participant_id,
        ajtai_commitment_bytes: ajtai_commitment_bytes.into(),
        public_io_bytes: public_io_bytes.into(),
        ccs_witness_bytes: CcsWitnessSecret::new(ccs_witness_bytes),
        sha256_binding_bytes: sha256_binding_bytes.to_vec().into(),
        ccs_matrix_bytes: vec![].into(),
    }
}

fn write_result(result: &AggregateBenchResult) {
    let status = write_result_impl(result);
    assert!(
        status.is_ok(),
        "write aggregate_1024 result failed: {:?}",
        status.err()
    );
}

fn write_result_impl(result: &AggregateBenchResult) -> io::Result<()> {
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../bench/results");
    fs::create_dir_all(&out_dir)?;

    let json = serde_json::to_string_pretty(result)
        .map_err(|error| io::Error::other(format!("serde_json serialization failed: {error}")))?;
    fs::write(out_dir.join("aggregate_1024.json"), json)?;

    Ok(())
}

fn run_aggregate_1024() -> Result<AggregateBenchResult, CycloError> {
    let adapter = HashChainCycloAdapter::new();
    let shares: Vec<CcsPShareInstance> = (1..=N_SHARES).map(make_share).collect();
    let mut rng = StdRng::from_seed([0x5A; 32]);

    let start = Instant::now();
    let report = adapter.fold_all(&shares, "aggregate-1024-bench", &mut rng)?;
    let wall_ms = start.elapsed().as_millis();

    adapter.verify_fold_all(&report, &shares)?;

    let status = if wall_ms <= WALL_TIME_CAP_MS {
        "pass"
    } else {
        "fail"
    };
    let result = AggregateBenchResult {
        n: usize::from(N_SHARES),
        wall_ms,
        status,
        batch_count: report.batch_count(),
        batch_size: report.batch_size(),
    };
    write_result(&result);
    Ok(result)
}

fn bench_aggregate_1024(c: &mut Criterion) {
    let baseline_result = run_aggregate_1024();
    assert!(
        baseline_result.is_ok(),
        "aggregate_1024 bench setup failed: {:?}",
        baseline_result.err()
    );
    let baseline = match baseline_result {
        Ok(result) => result,
        Err(_) => return,
    };
    assert_eq!(
        baseline.status, "pass",
        "aggregate_1024 wall-time cap exceeded"
    );

    c.bench_function("aggregate_1024", |b| {
        b.iter(|| {
            let result_state = run_aggregate_1024();
            assert!(
                result_state.is_ok(),
                "aggregate_1024 benchmark iteration failed: {:?}",
                result_state.err()
            );
            let result = match result_state {
                Ok(result) => result,
                Err(_) => return,
            };
            assert_eq!(
                result.status, "pass",
                "aggregate_1024 wall-time cap exceeded"
            );
        })
    });
}

criterion_group!(benches, bench_aggregate_1024);
criterion_main!(benches);
