//! Integration test ensuring lattice PVSS is wired into e2e and bench comparison.

use std::{fs, path::PathBuf, process::Command};

use serde_json::Value;

#[test]
fn e2e_uses_lattice_pvss_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let bin = std::env::var("CARGO_BIN_EXE_pvthfhe-e2e")?;

    let e2e_output = Command::new(bin)
        .args(["--n", "5", "--t", "2", "--seed", "1"])
        .env("RUST_LOG", "info")
        .env_remove("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK")
        .output()?;

    assert!(
        e2e_output.status.success(),
        "e2e failed: {}",
        String::from_utf8_lossy(&e2e_output.stderr)
    );

    let e2e_stdout = String::from_utf8_lossy(&e2e_output.stdout);
    let e2e_stderr = String::from_utf8_lossy(&e2e_output.stderr);
    let e2e_combined = format!("{e2e_stdout}\n{e2e_stderr}");
    assert!(
        e2e_combined.contains("pvss_backend_id=lattice-pvss-bfv-d2")
            || e2e_combined.contains("pvss_backend_id=\"lattice-pvss-bfv-d2\""),
        "expected lattice PVSS backend id in output, got:\n{e2e_combined}"
    );

    let share_encryption_proof_ms = e2e_combined
        .split("share_encryption_proof_ms=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse::<u128>().ok())
        .ok_or("missing share_encryption_proof_ms")?;
    assert!(
        share_encryption_proof_ms > 0,
        "expected share_encryption_proof_ms > 0 in output, got:\n{e2e_combined}"
    );

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let json_path = repo_root.join("bench/results/comparison-dryrun.json");
    if json_path.exists() {
        fs::remove_file(&json_path)?;
    }

    let bench_output = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "-p",
            "pvthfhe-bench",
            "--bin",
            "bench_comparison",
            "--",
            "--n",
            "5",
            "--t",
            "2",
            "--seed",
            "1",
            "--dry-run",
        ])
        .current_dir(&repo_root)
        .output()?;

    assert!(
        bench_output.status.success(),
        "bench_comparison failed: {}",
        String::from_utf8_lossy(&bench_output.stderr)
    );

    let json: Value = serde_json::from_str(&fs::read_to_string(&json_path)?)?;
    let share_encryption_row = json["circuit_timings"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["name"] == "ZkShareEncryption"))
        .ok_or("missing ZkShareEncryption row")?;

    assert_eq!(share_encryption_row["status"], "real");

    Ok(())
}
