//! Spec guard for the Sonobe substitute addendum.

use std::fs;
use std::path::{Path, PathBuf};

const SPEC_PATH: &str = ".sisyphus/design/spec-real-p2p3.md";
const MIGRATION_PATH: &str = ".sisyphus/design/sonobe-migration.md";
const REQUIRED_SPEC_STRINGS: [&str; 9] = [
    "### 4.2 Sonobe substitute",
    "ProofCompressor",
    "migration: sonobe → micronova",
    "bounded migration surface",
    "#### Invariant 1 — Trait surface",
    "#### Invariant 2 — Step-circuit shape",
    "#### Invariant 3 — Accumulator-state encoding",
    "#### Invariant 4 — Setup artifacts",
    "#### Invariant 5 — Verifier-key semantics",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_file(relative_path: &str) -> String {
    let full_path = repo_root().join(relative_path);
    fs::read_to_string(&full_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {}", full_path.display(), error))
}

fn migration_touch_point_count(doc: &str) -> usize {
    doc.lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("- `crates/")
                || trimmed.starts_with("- `Justfile`")
                || trimmed.starts_with("- `SECURITY.md`")
        })
        .count()
}

#[test]
fn spec_addendum_and_migration_contract_are_present() {
    let spec = read_repo_file(SPEC_PATH);
    let migration = read_repo_file(MIGRATION_PATH);

    for required in REQUIRED_SPEC_STRINGS {
        assert!(
            spec.contains(required),
            "spec addendum is missing required string: {required}"
        );
    }

    let touch_point_count = migration_touch_point_count(&migration);
    assert!(
        touch_point_count <= 8,
        "sonobe migration doc must enumerate at most 8 touch points, found {touch_point_count}"
    );
    assert!(
        touch_point_count >= 1,
        "sonobe migration doc must enumerate at least one touch point"
    );
}
