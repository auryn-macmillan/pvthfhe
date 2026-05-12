//! Integration tests for demo banner output.

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

#[test]
fn demo_prints_banner_and_backend_ids() {
    let mut cmd = Command::cargo_bin("pvthfhe-cli").expect("pvthfhe-cli binary");

    // Keep the smoke test on the smallest full-pipeline path shared with
    // demo_runs_full_pipeline to avoid expensive larger-N Sonobe runs.
    cmd.args(["demo", "--n", "3", "--threshold", "2", "--seed", "0"])
        .assert()
        .success()
        .stdout(contains("backend_id_p2: cyclo-rlwe-t10-lemma9-heuristic"))
        .stdout(contains("backend_id_p3: ultra-honk-micronova"))
        .stdout(contains(
            "note: on-chain Solidity verify is NOT run by demo (use bench-comparison)",
        ))
        .stdout(contains("surrogates active").not());
}
