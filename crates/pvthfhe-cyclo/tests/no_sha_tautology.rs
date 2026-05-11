//! C.2 test: `check_satisfiability` in `ccs_encode.rs` must use real CCS check,
//! not a SHA-256 tautology that compares against `sha256_binding`.
//!
//! This test greps the source file and fails if any SHA-binding tautology
//! patterns are found inside the `check_satisfiability` function body.

use std::fs;
use std::process::Command;

const SOURCE_PATH: &str = "src/ccs_encode.rs";

/// Extracts the body of `check_satisfiability` from the source text.
fn extract_fn_body(source: &str) -> String {
    let mut in_fn = false;
    let mut depth = 0usize;
    let mut body = String::new();

    for line in source.lines() {
        if line.contains("pub fn check_satisfiability") {
            in_fn = true;
            depth = 0;
            continue;
        }
        if !in_fn {
            continue;
        }
        // Track brace depth
        let opens = line.chars().filter(|&c| c == '{').count();
        let closes = line.chars().filter(|&c| c == '}').count();
        if opens > 0 && depth == 0 {
            // Function body starts; skip the opening brace line content before it
            depth = opens.saturating_sub(closes);
            continue;
        }
        if closes > 0 {
            if closes >= depth {
                in_fn = false;
                break;
            }
            depth -= closes;
        }
        depth += opens;
        body.push_str(line);
        body.push('\n');
    }
    body
}

#[test]
fn check_satisfiability_has_no_sha256_tautology() {
    let source = fs::read_to_string(SOURCE_PATH)
        .expect("ccs_encode.rs must exist");

    let fn_body = extract_fn_body(&source);

    // Pattern 1: `sha256_binding` inside check_satisfiability is forbidden
    assert!(
        !fn_body.contains("sha256_binding"),
        "C.2 FAIL: check_satisfiability references sha256_binding (SHA tautology detected)\n\
         Body:\n{fn_body}"
    );

    // Pattern 2: recomputing SHA-256 of instance fields inside satisfiability check
    // (the old tautology recomputed sha256 and compared against the stored binding)
    let has_sha_recompute = fn_body.contains("Sha256::new()")
        || fn_body.contains("chain_update")
        || fn_body.contains("finalize");
    assert!(
        !has_sha_recompute,
        "C.2 FAIL: check_satisfiability contains SHA-256 recomputation (tautology pattern)\n\
         Body:\n{fn_body}"
    );

    // Positive check: the function must reference `parse_matrix` (real CCS path)
    assert!(
        fn_body.contains("parse_matrix"),
        "C.2 FAIL: check_satisfiability must use parse_matrix for real CCS check"
    );
}
