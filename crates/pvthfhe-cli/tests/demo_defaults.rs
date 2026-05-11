//! RED integration test for the demo's clap defaults.

use assert_cmd::prelude::*;
use std::process::Command;

#[test]
fn demo_defaults_match_locked_values() -> Result<(), Box<dyn std::error::Error>> {
    // Clap help formatting is stable here and avoids relying on runtime demo output.
    let output = Command::cargo_bin("pvthfhe-cli")?
        .args(["demo", "--help"])
        .output()?;

    assert!(output.status.success(), "help failed: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[default: 8]"), "missing n default in: {stdout}");
    assert!(stdout.contains("[default: 0]"), "missing seed default in: {stdout}");

    Ok(())
}
