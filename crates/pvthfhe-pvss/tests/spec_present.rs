//! Spec-presence guard for the lattice PVSS freeze.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn pvss_spec_and_assumption_ledger_are_present() -> Result<(), Box<dyn std::error::Error>> {
    let repo_root = repo_root();

    let spec_path = repo_root.join(".sisyphus/design/spec-pvss.md");
    let spec_contents = fs::read_to_string(&spec_path)?;

    assert!(
        spec_contents.contains("status: frozen"),
        "expected spec-pvss.md to contain frozen status marker"
    );
    assert!(
        spec_contents.contains("sharing_relation:"),
        "expected spec-pvss.md to contain sharing_relation: marker"
    );
    assert!(
        spec_contents.contains("per_recipient_encryption:"),
        "expected spec-pvss.md to contain per_recipient_encryption: marker"
    );
    assert!(
        spec_contents.contains("nizk_statement:"),
        "expected spec-pvss.md to contain nizk_statement: marker"
    );
    assert!(
        spec_contents.contains("GoWithCaveat"),
        "expected spec-pvss.md to record the GoWithCaveat disclosure"
    );

    let p2p3_spec_path = repo_root.join(".sisyphus/design/spec-real-p2p3.md");
    let p2p3_spec_contents = fs::read_to_string(&p2p3_spec_path)?;

    assert!(
        p2p3_spec_contents.contains("§5 Lattice PVSS Addendum"),
        "expected spec-real-p2p3.md to contain the PVSS addendum marker"
    );

    let ledger_path = repo_root.join(".sisyphus/design/assumptions-ledger.md");
    let ledger_contents = fs::read_to_string(&ledger_path)?;

    assert!(
        ledger_contents.contains("pvss-bfv-composition"),
        "expected assumptions-ledger.md to record pvss-bfv-composition"
    );

    Ok(())
}
