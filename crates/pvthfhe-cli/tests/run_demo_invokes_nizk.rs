//! Integration test for NIZK wiring in the demo keygen path.

use std::process::Command;

#[test]
fn run_demo_invokes_nizk() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "-p",
            "pvthfhe-cli",
            "--",
            "demo",
            "--n",
            "3",
            "--threshold",
            "2",
            "--seed",
            "0",
        ])
        .env("RUST_LOG", "info")
        .env_remove("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK")
        .current_dir(env!("CARGO_MANIFEST_DIR").trim_end_matches("/crates/pvthfhe-cli"))
        .output()?;

    assert!(
        output.status.success(),
        "demo failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    let prove_calls = combined.matches("nizk_prove").count();
    let verify_calls = combined.matches("nizk_verify").count();

    assert_eq!(
        prove_calls, 3,
        "expected 3 prove calls in tracing output, got {prove_calls}; output:\n{combined}"
    );
    assert_eq!(
        verify_calls, 6,
        "expected 6 verify calls in tracing output, got {verify_calls}; output:\n{combined}"
    );

    Ok(())
}
