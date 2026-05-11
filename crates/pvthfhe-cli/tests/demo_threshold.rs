//! Integration test for demo threshold threading.

use std::process::Command;

#[test]
fn demo_threshold_threads_flag_through_demo() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "-p",
            "pvthfhe-cli",
            "--",
            "demo",
            "--n",
            "5",
            "--threshold",
            "3",
            "--seed",
            "0",
        ])
        .env_remove("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK")
        .current_dir(env!("CARGO_MANIFEST_DIR").trim_end_matches("/crates/pvthfhe-cli"))
        .output()?;

    assert!(
        output.status.success(),
        "demo failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("threshold=3"),
        "missing threshold=3 in: {stdout}"
    );
    assert!(
        stdout.contains("keygen_ms=") || stdout.contains("keygen_ms:"),
        "missing keygen_ms in: {stdout}"
    );
    assert!(
        stdout.contains("decrypt_ms=") || stdout.contains("decrypt_ms:"),
        "missing decrypt_ms in: {stdout}"
    );
    assert!(
        stdout.contains("plaintext_roundtrip: OK"),
        "missing successful plaintext round-trip in: {stdout}"
    );

    Ok(())
}
