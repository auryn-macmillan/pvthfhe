use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

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

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json(path: &Path) -> Value {
    let raw = fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
}

fn write_json(path: &Path, value: &Value) {
    let body = serde_json::to_vec_pretty(value).expect("serialize fixture JSON");
    fs::write(path, body).unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
}

fn circuit_rows(markdown: &str) -> Vec<Vec<String>> {
    let mut in_circuit_table = false;
    let mut rows = Vec::new();
    for line in markdown.lines() {
        if line == "| Circuit | Cardinality | PVTHFHE (ms) | Interfold (ms) | Ratio | Status | Notes |" {
            in_circuit_table = true;
            continue;
        }
        if !in_circuit_table {
            continue;
        }
        if line.is_empty() {
            break;
        }
        if line.starts_with("|---") {
            continue;
        }
        if !line.starts_with('|') {
            continue;
        }
        let cells = line
            .split('|')
            .skip(1)
            .map(str::trim)
            .filter(|cell| !cell.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if cells.len() == 7 {
            rows.push(cells);
        }
    }
    rows
}

#[test]
fn render_comparison_smoke_has_no_na_pvthfhe_cells_and_shows_merged_notes() {
    let repo_root = repo_root();
    let temp_dir = unique_temp_dir("render-comparison-smoke");
    let comparison_input_path = temp_dir.join("comparison-dryrun.json");
    let output_dir = temp_dir.join("rendered");

    let mut comparison = read_json(&repo_root.join("bench/results/comparison-dryrun.json"));
    comparison["commit_sha"] = Value::String("deadbee".to_owned());
    write_json(&comparison_input_path, &comparison);

    let status = Command::new(env!("CARGO_BIN_EXE_render_comparison"))
        .current_dir(&repo_root)
        .args([
            "--comparison-json",
            comparison_input_path.to_str().expect("utf8 comparison path"),
            "--baseline-json",
            repo_root
                .join("bench/results/interfold-trbfv-baseline.json")
                .to_str()
                .expect("utf8 baseline path"),
            "--template",
            repo_root
                .join("bench/templates/comparison.md.tera")
                .to_str()
                .expect("utf8 template path"),
            "--output-dir",
            output_dir.to_str().expect("utf8 output dir"),
        ])
        .status()
        .expect("run render_comparison");

    assert!(status.success(), "render_comparison should succeed");

    let markdown_path = output_dir.join("comparison-deadbee.md");
    let markdown = fs::read_to_string(&markdown_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", markdown_path.display()));
    let rows = circuit_rows(&markdown);

    assert_eq!(rows.len(), 12, "expected 12 circuit rows: {rows:?}");
    assert!(
        rows.iter().all(|row| row[2] != "n/a"),
        "expected zero n/a values in the PVTHFHE column: {rows:?}"
    );
    assert!(
        rows.iter().any(|row| row[6].contains("merged")),
        "expected at least one merged note in the Notes column: {rows:?}"
    );
}
