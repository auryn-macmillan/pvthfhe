//! Integration test for demo n-cap validation.

use std::process::Command;

#[test]
fn demo_rejects_n_above_shamir_cap_before_demo_steps() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "-p",
            "pvthfhe-cli",
            "--",
            "demo",
            "--n",
            "256",
            "--threshold",
            "129",
            "--seed",
            "1",
        ])
        .env_remove("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK")
        .current_dir(env!("CARGO_MANIFEST_DIR").trim_end_matches("/crates/pvthfhe-cli"))
        .output()?;

    assert!(
        !output.status.success(),
        "demo unexpectedly succeeded: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("255"), "missing 255 in stderr: {stderr}");
    assert!(
        stderr.contains("Shamir") || stderr.contains("GF(256)") || stderr.contains("maximum"),
        "missing cap rationale in stderr: {stderr}"
    );
    assert!(
        !stderr.contains("step 4/9"),
        "failure happened too late (reached step 4/9): {stderr}"
    );

    Ok(())
}
