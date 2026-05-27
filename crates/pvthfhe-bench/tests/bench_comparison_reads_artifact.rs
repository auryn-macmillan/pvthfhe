use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{json, Value};

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "pvthfhe-bench-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap_or_else(|err| panic!("create {}: {err}", path.display()));
    path
}

fn write_json(path: &Path, value: &Value) {
    let body = serde_json::to_vec_pretty(value).expect("serialize fixture JSON");
    fs::write(path, body).unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
}

fn read_json(path: &Path) -> Value {
    let raw =
        fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
}

fn bench_comparison_bin() -> &'static str {
    env!("CARGO_BIN_EXE_bench_comparison")
}

fn valid_e2e_timings_fixture() -> Value {
    json!({
        "schema_version": "1.0.0",
        "n": 3,
        "t": 1,
        "seed": 1,
        "compressor_backend_id": "nova-bn254-grumpkin",
        "phases": {
            "keygen": { "total_ms": 10.0, "instances_run": 1 },
            "nizk_prove": { "total_ms": 11.0, "instances_run": 3, "per_instance_ms": [3.0, 4.0, 4.0] },
            "nizk_verify": { "total_ms": 12.0, "instances_run": 3, "per_instance_ms": [4.0, 4.0, 4.0] },
            "pvss_share_encrypt": {
                "total_ms": 300.0,
                "instances_run": 3,
                "deal_ms": 287.0,
                "verify_ms": 9.0,
                "recover_ms": 4.0
            },
            "pvss_decrypt_prove": { "total_ms": 13.0, "instances_run": 3, "per_instance_ms": [4.0, 4.0, 5.0] },
            "cyclo_fold": { "total_ms": 14.0, "instances_run": 1 },
            "compressor_prove": { "total_ms": 15.0, "instances_run": 1 },
            "compressor_verify": { "total_ms": 16.0, "instances_run": 1 },
            "partial_decrypt": { "total_ms": 17.0, "instances_run": 3, "per_instance_ms": [5.0, 6.0, 6.0] },
            "aggregate_decrypt": { "total_ms": 18.0, "instances_run": 1 },
            "noir_nova_wrap": { "total_ms": 19.0, "instances_run": 1 },
            "onchain_verify": { "total_ms": 20.0, "instances_run": 1 }
        },
        "produced_at_unix_secs": 1,
        "git_sha": "deadbee"
    })
}

#[test]
fn reads_artifact_for_zk_share_encryption() {
    let temp_dir = unique_temp_dir("reads-artifact");
    let timings_path = temp_dir.join("e2e_timings.json");
    write_json(&timings_path, &valid_e2e_timings_fixture());

    let output = Command::new(bench_comparison_bin())
        .current_dir(&temp_dir)
        .args([
            "--e2e-timings",
            timings_path.to_str().expect("utf8 timings path"),
            "--n",
            "3",
            "--t",
            "1",
            "--seed",
            "1",
            "--dry-run",
        ])
        .output()
        .expect("run bench_comparison");

    assert!(
        output.status.success(),
        "bench_comparison should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let comparison = read_json(&temp_dir.join("bench/results/comparison-dryrun.json"));
    let row = comparison["circuit_timings"]
        .as_array()
        .expect("circuit_timings array")
        .iter()
        .find(|row| row["name"] == "ZkShareEncryption")
        .expect("ZkShareEncryption row present");

    assert_eq!(row["prove_ms"], json!(287.0));
    assert_eq!(row["status"], json!("real"));
}

#[test]
fn missing_artifact_exits_nonzero() {
    let temp_dir = unique_temp_dir("missing-artifact");
    let missing_path = "/nonexistent/path.json";

    let output = Command::new(bench_comparison_bin())
        .current_dir(&temp_dir)
        .args([
            "--e2e-timings",
            missing_path,
            "--n",
            "3",
            "--t",
            "1",
            "--seed",
            "1",
            "--dry-run",
        ])
        .output()
        .expect("run bench_comparison");

    assert!(!output.status.success(), "missing artifact should fail");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(missing_path),
        "stderr should mention missing artifact path, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn schema_version_mismatch_exits_nonzero() {
    let temp_dir = unique_temp_dir("schema-mismatch");
    let timings_path = temp_dir.join("e2e_timings.json");
    let mut fixture = valid_e2e_timings_fixture();
    fixture["schema_version"] = json!("0.9.0");
    write_json(&timings_path, &fixture);

    let output = Command::new(bench_comparison_bin())
        .current_dir(&temp_dir)
        .args([
            "--e2e-timings",
            timings_path.to_str().expect("utf8 timings path"),
            "--n",
            "3",
            "--t",
            "1",
            "--seed",
            "1",
            "--dry-run",
        ])
        .output()
        .expect("run bench_comparison");

    assert!(
        !output.status.success(),
        "schema version mismatch should fail"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("version"),
        "stderr should mention version mismatch, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
