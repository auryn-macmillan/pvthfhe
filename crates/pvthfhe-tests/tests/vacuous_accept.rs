//! Vacuous-accept audit for `PvtFheVerifier.sol`.
//!
//! Verifies that every Solidity function returning `true` has at least one
//! verification check (require, revert, _honkVerifier, registry.mark, etc.)
//! before the `return true` — no vacuous accept paths.
//!
//! Migrated from `.sisyphus/scripts/check-vacuous-accept.py`.

use std::fs;
use std::path::Path;

const CONTRACT_PATH: &str = "contracts/src/PvtFheVerifier.sol";

#[test]
fn no_vacuous_accept_paths_in_verifier() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join(CONTRACT_PATH);
    let src = fs::read_to_string(&path).expect("failed to read PvtFheVerifier.sol");

    let check_keywords = [
        "require", "revert", "_honkVerifier", "registry.mark",
        "_consumeIvcProof", "verifyStoredPublicAnchors", "recordSmudgeSlotUse",
    ];

    let functions: Vec<&str> = src.split("function ").collect();
    let mut vacuous = false;

    for f in functions.iter().skip(1) {
        let parts: Vec<&str> = f.split("return true").collect();
        if parts.len() <= 1 {
            continue;
        }
        let before = parts[0];
        let has_check = check_keywords.iter().any(|kw| before.contains(kw));
        if !has_check {
            let name = f.split('(').next().unwrap_or("unknown").trim();
            eprintln!("VACUOUS ACCEPT: function {name} returns true without verification checks");
            vacuous = true;
        }
    }

    assert!(!vacuous, "found vacuous accept paths in PvtFheVerifier.sol");
}
