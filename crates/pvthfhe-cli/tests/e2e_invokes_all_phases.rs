//! Integration test for full phase coverage in the e2e binary.

use std::process::Command;

#[test]
fn e2e_invokes_all_phases() -> Result<(), Box<dyn std::error::Error>> {
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

    for phase in [
        "keygen",
        "nizk_prove",
        "nizk_verify",
        "pvss_share_encrypt",
        "cyclo_fold",
        "compressor_prove",
        "compressor_verify",
        "noir_decrypt_share",
        "noir_aggregator_final",
        "noir_nova_wrap",
        "onchain_verify",
    ] {
        assert!(
            combined.contains(phase),
            "missing phase marker {phase} in output:\n{combined}"
        );
    }

    Ok(())
}
