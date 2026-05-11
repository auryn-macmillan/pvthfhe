//! R4.3 RED — single-fold-path enforcement in release builds.
//!
//! Extends R0.6 (`single_fold_path.rs`): verifies that the legacy fold path is
//! `compile_error!`'d so that release builds reject the `legacy-fold` feature,
//! and only the real folding path (default `real-folding`) compiles.

use std::process::Command;

fn run_cargo_check(features: Option<&str>) -> bool {
    let mut cmd = Command::new("cargo");
    cmd.args(["check", "-p", "pvthfhe-aggregator", "--message-format=json"]);
    if let Some(f) = features {
        cmd.args(["--features", f]);
    }
    // Don't inherit cargo test's color/terminal settings
    cmd.env("CARGO_TERM_COLOR", "never");
    let output = cmd
        .output()
        .expect("failed to execute cargo check for R4.3 test");
    output.status.success()
}

/// R4.3-T1 (RED): legacy-fold feature must be rejected with compile_error!
/// in release builds. This test FAILS until the GREEN change adds the
/// `compile_error!` gate on the legacy-fold feature.
#[test]
fn test_legacy_fold_rejected_in_release() {
    // The `compile_error!` fires in every profile; `check` is sufficient
    // because it performs full AST/cfg expansion.
    let success = run_cargo_check(Some("legacy-fold"));
    assert!(
        !success,
        "R4.3: legacy-fold feature must be rejected with compile_error! \
         in release builds. Currently it compiles — RED test expected."
    );
}

/// R4.3-T2 (GREEN guard): default features (real-folding) must check clean.
/// This is a regression guard — the canonical fold path must always compile.
#[test]
fn test_default_features_check_clean() {
    let success = run_cargo_check(None);
    assert!(
        success,
        "R4.3: default features (real-folding) must check clean in release builds; \
         only the canonical fold path must compile."
    );
}
