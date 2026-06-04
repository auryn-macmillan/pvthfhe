#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Follow-on plan coverage checks for deferred real-FHE work.

use std::{fs, path::PathBuf};

fn read_followon_plan() -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push(".sisyphus/plans/pvthfhe-followon.md");
    fs::read_to_string(path).expect("read pvthfhe-followon.md")
}

#[test]
fn followon_plan_tracks_real_fhe_demo_deferred_items() {
    let followon = read_followon_plan();

    for needle in [
        "Greco well-formedness ZK proofs",
        "Eval-key/relinearization DKG",
        "Multi-ciphertext encrypt",
        "Cross-process share distribution",
        "Smudging-noise tuning at n≥1024",
    ] {
        assert!(
            followon.contains(needle),
            "expected deferred item in pvthfhe-followon.md: {needle}"
        );
    }
}
