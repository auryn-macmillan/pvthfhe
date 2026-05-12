//! R3.3 RED: Ajtai matrix `A` must be CRS-bound to on-chain epoch.
//!
//! The current `compute_ajtai_commitment` seeds the Ajtai matrix with
//! `ccs_instance_id` = `SHA256(session_id || participant_id || ...)`, which
//! is prover-influenced via `participant_id`.  A malicious prover could
//! grind Ajtai matrices across `participant_id` choices until they find one
//! favourable for a trapdoor-grinding attack.
//!
//! **Fix**: The matrix seed MUST be `H(epoch ‖ protocol_constants ‖ session_id)`,
//! eliminating prover influence and binding the CRS to the on-chain epoch.
//!
//! ## RED assertions
//!
//! 1.  Static: `compute_ajtai_commitment(&ccs_id, …)` does NOT appear in
//!     `adapter.rs` — the `ccs_id` is no longer accepted as the matrix seed.
//! 2.  Static: the adapter source references `derive_epoch_crs_seed` or an
//!     equivalently-named epoch→crs-seed derivation function.
//! 3.  Runtime: `AjtaiMatrix::from_seed` with two different seeds (one
//!     epoch-derived, one ccs-instance-derived) produces different matrices,
//!     proving the derivation choice is cryptographically meaningful.

use std::path::PathBuf;
use std::process::Command;

use pvthfhe_nizk::ajtai::{AjtaiMatrix, AjtaiParams};

// ── helpers ──────────────────────────────────────────────────────────

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn adapter_src() -> PathBuf {
    crate_root().join("src").join("adapter.rs")
}

/// SHA-256 helper for test-only seed derivation (mirrors production code).
fn sha256(data: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for chunk in data {
        h.update(chunk);
    }
    h.finalize().into()
}

fn epoch_crs_seed(epoch: u64, session_id: &str) -> [u8; 32] {
    sha256(&[
        &epoch.to_be_bytes(),
        b"pvthfhe-ajtai-crs/v1",
        session_id.as_bytes(),
    ])
}

fn ccs_instance_seed(
    session_id: &str,
    participant_id: u16,
    q: u64,
    degree: u64,
    error_bound: u64,
) -> [u8; 32] {
    sha256(&[
        session_id.as_bytes(),
        &participant_id.to_be_bytes(),
        &q.to_be_bytes(),
        &degree.to_be_bytes(),
        &error_bound.to_be_bytes(),
        b"cyclo-ajtai-d2/v1",
    ])
}

// ── static: adapter.rs code-pattern assertions ───────────────────────

#[test]
fn adapter_does_not_seed_ajtai_from_ccs_instance_id() {
    let path = adapter_src();
    assert!(path.exists(), "adapter.rs not found at {}", path.display());

    // Search for the old pattern: compute_ajtai_commitment(&ccs_id, …
    let out = Command::new("rg")
        .args([
            "--line-number",
            "--no-heading",
            r"compute_ajtai_commitment\(&ccs_id",
        ])
        .arg(&path)
        .output()
        .expect("rg must be installed");

    assert!(
        out.status.success() || out.status.code() == Some(1),
        "rg failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let matches = String::from_utf8_lossy(&out.stdout);
    let match_count = matches.lines().filter(|l| !l.is_empty()).count();

    assert_eq!(
        match_count, 0,
        "adapter.rs still seeds Ajtai matrix from ccs_instance_id (prover-influenced):\n{matches}\n\
         Fix: replace `compute_ajtai_commitment(&ccs_id, …)` with epoch-bound `derive_epoch_crs_seed(…)`."
    );
}

#[test]
fn adapter_references_epoch_crs_derivation() {
    let path = adapter_src();
    assert!(path.exists(), "adapter.rs not found at {}", path.display());

    // Search for the new pattern: derive_epoch_crs_seed or equivalent
    let out = Command::new("rg")
        .args([
            "--line-number",
            "--no-heading",
            r"derive_epoch_crs_seed|epoch_crs|epoch.*crs.*seed",
        ])
        .arg(&path)
        .output()
        .expect("rg must be installed");

    assert!(
        out.status.success() || out.status.code() == Some(1),
        "rg failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let matches = String::from_utf8_lossy(&out.stdout);
    let match_count = matches.lines().filter(|l| !l.is_empty()).count();

    assert!(
        match_count > 0,
        "adapter.rs does not reference epoch→CRS seed derivation.\n\
         Fix: add `derive_epoch_crs_seed(epoch, session_id)` and call it to seed the Ajtai matrix."
    );
}

// ── runtime: seed-choice is cryptographically meaningful ─────────────

#[test]
fn epoch_seed_and_ccs_seed_produce_different_matrices() {
    let params = AjtaiParams::default();
    let m: usize = 13; // AJTAI_RANK; m must be ≥ rank for square-ish test

    let epoch: u64 = 42;
    let session = "test-session";
    let participant: u16 = 7;
    let q: u64 = 0xFFFF_FFFF_FFFF_0001;
    let degree: u64 = 8192;
    let error_bound: u64 = 20;

    let seed_epoch = epoch_crs_seed(epoch, session);
    let seed_ccs = ccs_instance_seed(session, participant, q, degree, error_bound);

    // Sanity: the two seeds must differ — otherwise this test is meaningless.
    assert_ne!(
        seed_epoch, seed_ccs,
        "epoch seed and ccs seed are accidentally equal — adjust test parameters"
    );

    let matrix_epoch = AjtaiMatrix::from_seed(seed_epoch, &params, m)
        .expect("epoch-derived matrix construction failed");
    let matrix_ccs = AjtaiMatrix::from_seed(seed_ccs, &params, m)
        .expect("ccs-derived matrix construction failed");

    assert!(
        !matrix_epoch.eq(&matrix_ccs),
        "epoch-derived and ccs-derived Ajtai matrices are identical — \
         seed choice is cryptographically irrelevant; the CRS-binding fix is meaningless"
    );
}
