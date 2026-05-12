//! Integration test for e2e timings artifact emission.

use assert_cmd::Command;
use serde_json::Value;

#[test]
fn e2e_writes_timings() -> Result<(), Box<dyn std::error::Error>> {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let artifact_path = workspace_root.join("bench/results/e2e_timings.json");

    if artifact_path.exists() {
        std::fs::remove_file(&artifact_path)?;
    }

    let mut command = Command::cargo_bin("pvthfhe-e2e")?;
    command
        .current_dir(&workspace_root)
        .args(["--n", "3", "--t", "1", "--seed", "1"])
        .env("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");

    command.assert().success();

    assert!(
        artifact_path.exists(),
        "missing artifact at {artifact_path:?}"
    );

    let timings: Value = serde_json::from_slice(&std::fs::read(&artifact_path)?)?;
    assert!(
        timings["phases"]["pvss_share_encrypt"]["deal_ms"]
            .as_f64()
            .unwrap_or_default()
            > 0.0
    );
    assert!(
        timings["phases"]["pvss_share_encrypt"]["verify_ms"]
            .as_f64()
            .unwrap_or_default()
            > 0.0
    );
    assert!(
        timings["phases"]["pvss_share_encrypt"]["recover_ms"]
            .as_f64()
            .unwrap_or_default()
            > 0.0
    );
    assert_eq!(timings["schema_version"], "1.0.0");

    Ok(())
}
