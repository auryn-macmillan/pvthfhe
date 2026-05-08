//! Integration test ensuring the default e2e compressor is Sonobe.

use std::process::Command;

#[test]
fn e2e_uses_sonobe_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let bin = std::env::var("CARGO_BIN_EXE_pvthfhe-e2e")?;

    let output = Command::new(bin)
        .args(["--n", "3", "--t", "2", "--seed", "1", "--dry-run"])
        .env("RUST_LOG", "info")
        .env_remove("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK")
        .output()?;

    assert!(
        output.status.success(),
        "e2e failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    assert!(
        combined.contains("compressor_backend_id=sonobe-nova-bn254-grumpkin")
            || combined.contains("compressor_backend_id=\"sonobe-nova-bn254-grumpkin\""),
        "expected sonobe compressor backend id in output, got:\n{combined}"
    );

    Ok(())
}
