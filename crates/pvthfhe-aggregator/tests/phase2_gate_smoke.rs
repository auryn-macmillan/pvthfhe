//! Smoke test for the Phase 2 gate output.

use std::fs;
use std::path::PathBuf;

#[test]
fn phase2_gate_writes_pass_result_to_bench_results() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../bench/results/phase2-gate.json");
    let raw =
        fs::read_to_string(&path).expect("phase2 gate should write bench/results/phase2-gate.json");

    assert!(
        raw.contains("\"status\": \"pass\""),
        "phase2 gate JSON should report pass status: {raw}"
    );
    assert!(
        raw.contains("\"gate\": \"phase2-cyclo\""),
        "phase2 gate JSON should identify the Cyclo gate: {raw}"
    );
    assert!(
        raw.contains("\"checks\""),
        "phase2 gate JSON should include checks: {raw}"
    );
}
