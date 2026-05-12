use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use pvthfhe_bench::comparison_map::{
    comparison_row_name, mapping_for, CIRCUIT_MAP, INTERFOLD_CIRCUIT_NAMES,
};
use serde_json::{json, Value};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json(path: &Path) -> Value {
    let raw =
        fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
}

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

fn baseline_names() -> Vec<String> {
    let baseline = read_json(&repo_root().join("bench/results/interfold-trbfv-baseline.json"));
    baseline["circuit_timings"]
        .as_array()
        .expect("baseline circuit_timings must be an array")
        .iter()
        .map(|row| {
            row["name"]
                .as_str()
                .unwrap_or_else(|| panic!("baseline row missing string name: {row:?}"))
                .to_owned()
        })
        .collect()
}

fn refresh_dryrun_json() {
    let temp_dir = unique_temp_dir("circuit-name-map");
    let timings_path = temp_dir.join("e2e_timings.json");
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

    let source = temp_dir.join("bench/results/comparison-dryrun.json");
    let dest = repo_root().join("bench/results/comparison-dryrun.json");
    fs::copy(&source, &dest)
        .unwrap_or_else(|err| panic!("copy {} to {}: {err}", source.display(), dest.display()));
}

#[test]
fn every_baseline_circuit_name_has_a_mapping_entry() {
    let names = baseline_names();
    let unique_names = names.iter().collect::<HashSet<_>>();

    assert_eq!(
        names.len(),
        12,
        "expected exactly 12 Interfold circuit names"
    );
    assert_eq!(
        names, INTERFOLD_CIRCUIT_NAMES,
        "baseline must preserve the exact ordered Interfold circuit names"
    );
    assert_eq!(CIRCUIT_MAP.len(), 12, "expected exactly 12 mapping entries");
    assert_eq!(
        unique_names.len(),
        names.len(),
        "baseline circuit names must be unique"
    );

    for name in names {
        let mapping = mapping_for(&name).unwrap_or_else(|| panic!("missing mapping for {name}"));
        assert!(
            !mapping.pvthfhe_name.is_empty() || mapping.gap_reason.is_some(),
            "mapping for {name} must provide a PVTHFHE analogue or explicit gap reason"
        );
        assert!(
            !mapping.cardinality.is_empty(),
            "mapping for {name} must declare cardinality"
        );
        assert!(
            !mapping.aggregation_rule.is_empty(),
            "mapping for {name} must declare aggregation_rule"
        );
    }
}

#[test]
fn every_baseline_circuit_has_a_pvthfhe_timing_or_gap_reason() {
    refresh_dryrun_json();
    let dryrun = read_json(&repo_root().join("bench/results/comparison-dryrun.json"));
    let rows = dryrun["circuit_timings"]
        .as_array()
        .expect("comparison dryrun circuit_timings must be an array");

    for interfold_name in baseline_names() {
        let mapping = mapping_for(&interfold_name)
            .unwrap_or_else(|| panic!("missing mapping for {interfold_name}"));
        let comparison_name = comparison_row_name(&interfold_name);
        let row = rows
            .iter()
            .find(|row| row["name"] == comparison_name)
            .unwrap_or_else(|| {
                panic!("missing comparison row for {interfold_name} as {comparison_name}")
            });
        let has_timing = ["prove_ms", "verify_ms", "witness_ms"]
            .iter()
            .any(|key| row[*key].is_number());

        assert!(
            has_timing || mapping.gap_reason.is_some(),
            "{interfold_name} must have a PVTHFHE timing in comparison-dryrun.json or an explicit gap reason in CIRCUIT_MAP"
        );
    }
}
