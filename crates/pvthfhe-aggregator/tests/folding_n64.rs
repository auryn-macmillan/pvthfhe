//! Integration tests: folding_n64.
#![allow(clippy::unwrap_used)]

use pvthfhe_aggregator::folding::{FoldingAccumulator, PartyProof};
use serde_json::json;
use std::fs;
use std::path::PathBuf;

#[test]
fn test_folding_n64() {
    let mut accumulator = FoldingAccumulator::new();

    for i in 0_u32..64_u32 {
        let proof = PartyProof {
            party_id: i,
            share_hash: [u8::try_from(i).unwrap_or(u8::MAX); 32],
            nizk_bytes: vec![1, 2, 3, 4],
        };
        accumulator.add_proof(proof).unwrap();
    }

    let final_snark = accumulator.finalize().unwrap();

    assert!(final_snark.proof_size_bytes > 0);
    assert!(final_snark.prover_time_ms < 5000);
    assert_eq!(final_snark.public_inputs.len(), 64);

    let bench_data = json!({
        "n": 64,
        "proof_size_bytes": final_snark.proof_size_bytes,
        "prover_time_ms": final_snark.prover_time_ms,
        "scheme": "simulated_fold_sha256"
    });

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../.sisyphus/evidence/task-37-bench.json");

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, bench_data.to_string()).unwrap();
}
