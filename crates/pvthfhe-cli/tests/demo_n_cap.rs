//! Integration test for demo threshold-policy validation.
//!
//! The demo rejects t > floor(n/2)+1 (the honest-majority threshold policy)
//! before running any pipeline steps. (There is no party-count cap: the
//! Shamir field migrated from GF(256) to BN254, lifting the old 255 cap.)

use std::process::Command;

#[test]
fn demo_rejects_threshold_above_policy_cap_before_demo_steps(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "-p",
            "pvthfhe-cli",
            "--",
            "demo",
            "--n",
            "10",
            "--threshold",
            "7",
            "--seed",
            "0",
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
    assert!(
        stderr.contains("exceeds max_t"),
        "missing threshold-policy rationale in stderr: {stderr}"
    );
    assert!(
        !stderr.contains("step 4/9"),
        "failure happened too late (reached step 4/9): {stderr}"
    );

    Ok(())
}
