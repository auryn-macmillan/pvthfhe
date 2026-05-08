use std::{
    fs,
    path::{Path, PathBuf},
    process::Command as StdCommand,
    sync::{Mutex, OnceLock},
};

use assert_cmd::Command;
use serde_json::Value;

static E2E_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_timings(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn read_json(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn comparison_row<'a>(comparison: &'a Value, name: &str) -> &'a Value {
    comparison["circuit_timings"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["name"] == name))
        .unwrap_or_else(|| panic!("missing comparison row {name}"))
}

fn run_e2e_and_bench() -> Result<(Value, Value), Box<dyn std::error::Error>> {
    let _guard = E2E_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("e2e lock poisoned");
    let workspace_root = workspace_root();
    let artifact_path = workspace_root.join("bench/results/e2e_timings.json");
    let comparison_path = workspace_root.join("bench/results/comparison-dryrun.json");

    if artifact_path.exists() {
        fs::remove_file(&artifact_path)?;
    }
    if comparison_path.exists() {
        fs::remove_file(&comparison_path)?;
    }

    let mut e2e = Command::cargo_bin("pvthfhe-e2e")?;
    e2e.current_dir(&workspace_root)
        .args(["--n", "3", "--t", "1", "--seed", "1"])
        .env("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
    e2e.assert().success();

    let bench_output = StdCommand::new("cargo")
        .current_dir(&workspace_root)
        .args([
            "run",
            "--quiet",
            "-p",
            "pvthfhe-bench",
            "--bin",
            "bench_comparison",
            "--",
            "--e2e-timings",
            "bench/results/e2e_timings.json",
            "--n",
            "3",
            "--t",
            "1",
            "--seed",
            "1",
            "--dry-run",
        ])
        .output()?;

    assert!(
        bench_output.status.success(),
        "bench_comparison failed: {}",
        String::from_utf8_lossy(&bench_output.stderr)
    );

    Ok((read_timings(&artifact_path)?, read_json(&comparison_path)?))
}

fn phase_f64(timings: &Value, phase: &str, metric: &str) -> f64 {
    timings["phases"][phase][metric].as_f64().unwrap_or_default()
}

fn phase_u64(timings: &Value, phase: &str, metric: &str) -> u64 {
    timings["phases"][phase][metric].as_u64().unwrap_or_default()
}

fn phase_array_len(timings: &Value, phase: &str, metric: &str) -> usize {
    timings["phases"][phase][metric]
        .as_array()
        .map(|items| items.len())
        .unwrap_or_default()
}

fn phase_array_sum(timings: &Value, phase: &str, metric: &str) -> f64 {
    timings["phases"][phase][metric]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_f64())
        .sum()
}

#[test]
fn compressor_prove_ms_populated() -> Result<(), Box<dyn std::error::Error>> {
    let (timings, comparison) = run_e2e_and_bench()?;
    let row = comparison_row(&comparison, "ZkDkgAggregation");

    assert!(phase_f64(&timings, "compressor_prove", "total_ms") > 0.0);
    assert_eq!(row["status"], "real");
    assert!(row["prove_ms"].as_f64().unwrap_or(0.0) > 0.0);

    Ok(())
}

#[test]
fn onchain_verify_ms_populated() -> Result<(), Box<dyn std::error::Error>> {
    let (timings, comparison) = run_e2e_and_bench()?;
    let row = comparison_row(&comparison, "onchain_verify");

    assert!(phase_f64(&timings, "onchain_verify", "total_ms") > 0.0);
    assert_eq!(row["status"], "real-fallback");
    assert!(row["prove_ms"].as_f64().unwrap_or(0.0) > 0.0);

    Ok(())
}

#[test]
fn partial_decrypt_ms_populated() -> Result<(), Box<dyn std::error::Error>> {
    let (timings, comparison) = run_e2e_and_bench()?;
    let row = comparison_row(&comparison, "ZkThresholdShareDecryption");

    assert!(phase_f64(&timings, "partial_decrypt", "total_ms") > 0.0);
    assert_eq!(phase_u64(&timings, "partial_decrypt", "instances_run"), 1);
    assert_eq!(phase_array_len(&timings, "partial_decrypt", "per_instance_ms"), 1);
    assert_eq!(row["status"], "real");
    assert_eq!(
        row["prove_ms"].as_f64().unwrap_or_default(),
        phase_array_sum(&timings, "partial_decrypt", "per_instance_ms")
    );

    Ok(())
}

#[test]
fn aggregate_decrypt_ms_populated() -> Result<(), Box<dyn std::error::Error>> {
    let (timings, comparison) = run_e2e_and_bench()?;
    let decrypted_shares_row = comparison_row(&comparison, "ZkDecryptedSharesAggregation");
    let decryption_row = comparison_row(&comparison, "ZkDecryptionAggregation");

    assert!(phase_f64(&timings, "aggregate_decrypt", "total_ms") > 0.0);
    assert_eq!(
        decrypted_shares_row["prove_ms"].as_f64(),
        decryption_row["prove_ms"].as_f64()
    );
    assert!(
        decrypted_shares_row["comparability_note"]
            .as_str()
            .unwrap_or_default()
            .contains("merged")
    );
    assert!(
        decryption_row["comparability_note"]
            .as_str()
            .unwrap_or_default()
            .contains("merged")
    );

    Ok(())
}

#[test]
fn pvss_verify_ms_populated() -> Result<(), Box<dyn std::error::Error>> {
    let (timings, comparison) = run_e2e_and_bench()?;
    let row = comparison_row(&comparison, "ZkVerifyShareProofs");

    assert_eq!(
        row["prove_ms"].as_f64().unwrap_or_default(),
        phase_f64(&timings, "pvss_share_encrypt", "verify_ms")
    );
    assert_eq!(row["status"], "real");

    Ok(())
}

#[test]
fn nizk_prove_ms_populated() -> Result<(), Box<dyn std::error::Error>> {
    let (timings, comparison) = run_e2e_and_bench()?;
    let row = comparison_row(&comparison, "ZkPkBfv");

    assert_eq!(phase_u64(&timings, "nizk_prove", "instances_run"), 3);
    assert_eq!(phase_array_len(&timings, "nizk_prove", "per_instance_ms"), 3);
    assert_eq!(row["status"], "real");
    assert!(
        (row["prove_ms"].as_f64().unwrap_or_default()
            - phase_array_sum(&timings, "nizk_prove", "per_instance_ms"))
            .abs()
            < 1e-6
    );

    Ok(())
}

#[test]
fn keygen_ms_populated() -> Result<(), Box<dyn std::error::Error>> {
    let (timings, comparison) = run_e2e_and_bench()?;
    let row = comparison_row(&comparison, "ZkShareComputation");

    assert!(phase_f64(&timings, "keygen", "total_ms") > 0.0);
    assert_eq!(phase_u64(&timings, "keygen", "instances_run"), 1);
    assert_eq!(row["status"], "real");
    assert_eq!(
        row["prove_ms"].as_f64().unwrap_or_default(),
        phase_f64(&timings, "keygen", "total_ms")
    );

    Ok(())
}

#[test]
fn pvss_decrypt_prove_ms_populated() -> Result<(), Box<dyn std::error::Error>> {
    let (timings, comparison) = run_e2e_and_bench()?;
    let row = comparison_row(&comparison, "ZkDkgShareDecryption");

    assert_eq!(phase_u64(&timings, "pvss_decrypt_prove", "instances_run"), 1);
    assert_eq!(phase_array_len(&timings, "pvss_decrypt_prove", "per_instance_ms"), 1);
    assert_eq!(row["status"], "real");
    assert_eq!(
        row["prove_ms"].as_f64().unwrap_or_default(),
        phase_array_sum(&timings, "pvss_decrypt_prove", "per_instance_ms")
    );

    Ok(())
}

#[test]
fn cyclo_fold_ms_populated() -> Result<(), Box<dyn std::error::Error>> {
    let (timings, comparison) = run_e2e_and_bench()?;
    let node_row = comparison_row(&comparison, "ZkNodeDkgFold");
    let pk_row = comparison_row(&comparison, "ZkPkAggregation");

    assert!(phase_f64(&timings, "cyclo_fold", "total_ms") > 0.0);
    assert_eq!(node_row["prove_ms"].as_f64(), pk_row["prove_ms"].as_f64());
    assert!(node_row["comparability_note"].as_str().unwrap_or_default().contains("merged"));
    assert!(pk_row["comparability_note"].as_str().unwrap_or_default().contains("merged"));

    Ok(())
}

#[test]
fn noir_sonobe_wrap_ms_present() -> Result<(), Box<dyn std::error::Error>> {
    let (timings, _) = run_e2e_and_bench()?;

    assert!(phase_f64(&timings, "noir_sonobe_wrap", "total_ms") >= 0.0);
    assert_eq!(phase_u64(&timings, "noir_sonobe_wrap", "instances_run"), 1);

    Ok(())
}
