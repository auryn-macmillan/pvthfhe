//! Integration test for full phase coverage in the e2e binary.

use std::process::Command;

#[test]
fn e2e_invokes_all_phases() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "-p",
            "pvthfhe-cli",
            "--bin",
            "pvthfhe-e2e",
            "--",
            "--n",
            "3",
            "--t",
            "2",
            "--seed",
            "1",
        ])
        .env("RUST_LOG", "info")
        .env_remove("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK")
        .current_dir(env!("CARGO_MANIFEST_DIR").trim_end_matches("/crates/pvthfhe-cli"))
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
        "cyclo_fold",
        "compressor_prove",
        "compressor_verify",
        "noir_decrypt_share",
        "noir_aggregator_final",
        "noir_sonobe_wrap",
        "onchain_verify",
    ] {
        assert!(
            combined.contains(phase),
            "missing phase marker {phase} in output:\n{combined}"
        );
    }

    assert!(
        !combined.contains("pvss_share_encrypt"),
        "pvss_share_encrypt should be absent before Phase P:\n{combined}"
    );

    Ok(())
}
