//! R8.3 RED: CLI subcommands must be wired to real functionality.
//!
//! On current `main`, all subcommands (`keygen`, `encrypt`, `partial-decrypt`,
//! `aggregate`, `verify`) print a "stub" banner. This test asserts that each
//! subcommand output does NOT contain "(stub)" and produces real hex output.
//! It FAILS on current main because every subcommand is a stub.

use assert_cmd::prelude::*;
use std::process::Command;

fn run_subcommand(args: &[&str]) -> std::process::Output {
    Command::cargo_bin("pvthfhe-cli")
        .expect("pvthfhe-cli binary")
        .args(args)
        .env_remove("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK")
        .output()
        .expect("subcommand execution")
}

#[test]
fn keygen_subcommand_not_stub() {
    let output = run_subcommand(&["keygen", "--n", "5", "--threshold", "2"]);
    // On current main: prints "keygen: n=5 threshold=2 (stub)"
    // After GREEN: produces real key material output
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        !combined.to_lowercase().contains("(stub)"),
        "keygen subcommand should not be a stub:\n{combined}"
    );
    assert!(
        combined.len() > 30,
        "keygen output too short (likely still a stub): {combined}"
    );
}

#[test]
fn encrypt_subcommand_not_stub() {
    let output = run_subcommand(&[
        "encrypt",
        "--plaintext",
        "414243",
        "--pk",
        "000102030405060708090a0b0c0d0e0f",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        !combined.to_lowercase().contains("(stub)"),
        "encrypt subcommand should not be a stub:\n{combined}"
    );
    assert!(
        combined.len() > 20,
        "encrypt output too short (likely still a stub): {combined}"
    );
}

#[test]
fn partial_decrypt_subcommand_not_stub() {
    let output = run_subcommand(&[
        "partial-decrypt",
        "--party-id",
        "1",
        "--ciphertext",
        "deadbeef",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        !combined.to_lowercase().contains("(stub)"),
        "partial-decrypt subcommand should not be a stub:\n{combined}"
    );
    assert!(
        combined.len() > 20,
        "partial-decrypt output too short (likely still a stub): {combined}"
    );
}

#[test]
fn aggregate_subcommand_not_stub() {
    let output = run_subcommand(&[
        "aggregate",
        "--ciphertext",
        "deadbeef",
        "--shares",
        "01020304,05060708",
        "--threshold",
        "2",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        !combined.to_lowercase().contains("(stub)"),
        "aggregate subcommand should not be a stub:\n{combined}"
    );
    assert!(
        combined.len() > 20,
        "aggregate output too short (likely still a stub): {combined}"
    );
}
