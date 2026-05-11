//! RED integration test for the demo's full phase coverage.

use assert_cmd::prelude::*;
use std::process::Command;

#[test]
fn demo_runs_full_pipeline() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("pvthfhe-cli")?;
    let output = cmd
        .args([
            "demo",
            "--n",
            "3",
            "--threshold",
            "2",
            "--seed",
            "0",
        ])
        .env_remove("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK")
        .output()?;

    assert!(
        output.status.success(),
        "demo failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    for phase in [
        "keygen",
        "nizk_prove",
        "nizk_verify",
        "pvss_share_encrypt",
        "cyclo_fold",
        "compressor_prove",
        "compressor_verify",
        "partial_decrypt",
        "aggregate_decrypt",
        "plaintext_roundtrip: OK",
    ] {
        assert!(
            combined.to_lowercase().contains(&phase.to_lowercase()),
            "missing phase marker {phase} in output:\n{combined}"
        );
    }

    Ok(())
}
