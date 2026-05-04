//! Integration tests for demo banner output.

use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn demo_prints_banner_and_backend_ids() {
    let mut cmd = Command::cargo_bin("pvthfhe-cli").expect("pvthfhe-cli binary");

    cmd.args(["demo", "--n", "4", "--seed", "0"])
        .assert()
        .success()
        .stdout(contains("P1 NIZK: conditional soundness only"))
        .stdout(contains("backend_id_p2: cyclo-rlwe-t10-lemma9-heuristic"))
        .stdout(contains("backend_id_p3: ultra-honk-micronova"));
}
