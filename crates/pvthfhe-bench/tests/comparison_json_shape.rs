use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use pvthfhe_bench::comparison_map::COMPARISON_ROW_NAMES;
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

fn valid_e2e_timings_fixture() -> Value {
    json!({
        "schema_version": "1.0.0",
        "n": 3,
        "t": 1,
        "seed": 1,
        "compressor_backend_id": "sonobe-nova-bn254-grumpkin",
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
            "pvss_decrypt_prove": { "total_ms": 13.0, "instances_run": 1, "per_instance_ms": [13.0] },
            "cyclo_fold": { "total_ms": 14.0, "instances_run": 1 },
            "compressor_prove": { "total_ms": 15.0, "instances_run": 1 },
            "compressor_verify": { "total_ms": 16.0, "instances_run": 1 },
            "partial_decrypt": { "total_ms": 17.0, "instances_run": 1, "per_instance_ms": [17.0] },
            "aggregate_decrypt": { "total_ms": 18.0, "instances_run": 1 },
            "noir_sonobe_wrap": { "total_ms": 19.0, "instances_run": 1 },
            "onchain_verify": { "total_ms": 20.0, "instances_run": 1 }
        },
        "produced_at_unix_secs": 1,
        "git_sha": "deadbee"
    })
}

#[test]
fn comparison_json_shape() {
    let temp_dir = unique_temp_dir("comparison-json-shape");
    let timings_path = temp_dir.join("e2e_timings.json");
    let output_path = temp_dir.join("bench/results/comparison-dryrun.json");
    write_json(&timings_path, &valid_e2e_timings_fixture());

    let status = Command::new(env!("CARGO_BIN_EXE_bench_comparison"))
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
        .status()
        .expect("run bench_comparison --dry-run");

    assert!(
        status.success(),
        "bench_comparison --dry-run should succeed"
    );

    let output = fs::read_to_string(&output_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", output_path.display()));
    let json: Value = serde_json::from_str(&output).expect("parse comparison JSON");

    for key in [
        "circuit_timings",
        "phase_totals",
        "hardware",
        "backend_ids",
        "commit_sha",
        "comparison_target",
    ] {
        assert!(json.get(key).is_some(), "missing top-level key {key}");
    }

    let circuit_timings = json["circuit_timings"]
        .as_array()
        .expect("circuit_timings must be an array");
    assert_eq!(
        circuit_timings.len(),
        COMPARISON_ROW_NAMES.len(),
        "expected exactly {} circuit rows",
        COMPARISON_ROW_NAMES.len()
    );

    let names = circuit_timings
        .iter()
        .map(|row| {
            row["name"]
                .as_str()
                .unwrap_or_else(|| panic!("circuit row missing string name: {row:?}"))
        })
        .collect::<Vec<_>>();
    assert_eq!(names, COMPARISON_ROW_NAMES);

    for row in circuit_timings {
        for key in [
            "name",
            "prove_ms",
            "verify_ms",
            "witness_ms",
            "vk_kb",
            "proof_kb",
            "status",
            "cardinality_tag",
            "instances_run",
            "comparability_note",
        ] {
            assert!(
                row.get(key).is_some(),
                "missing circuit key {key} in row {row:?}"
            );
        }

        if row["prove_ms"].is_null()
            && row["verify_ms"].is_null()
            && row["witness_ms"].is_null()
            && row["vk_kb"].is_null()
            && row["proof_kb"].is_null()
        {
            assert!(
                row.get("gap_reason").and_then(Value::as_str).is_some(),
                "rows with null timing/size fields must include gap_reason: {row:?}"
            );
        }
    }
}
