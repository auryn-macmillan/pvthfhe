//! R0.4 RED: every raw `b"pvthfhe/..."` byte literal in the workspace must be a `Tag` variant.
//! Fails on current `main` because the enum is empty. GREEN will populate.

use std::collections::BTreeSet;
use std::process::Command;

fn workspace_root() -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().parent().unwrap().to_path_buf()
}

#[test]
fn every_pvthfhe_byte_literal_is_a_tag_variant() {
    let root = workspace_root();
    let output = Command::new("rg")
        .arg("--no-heading")
        .arg("--no-line-number")
        .arg("-o")
        .arg(r#"b"pvthfhe/[^"]*""#)
        .arg("--glob")
        .arg("!target/**")
        .arg("--glob")
        .arg("!crates/pvthfhe-domain-tags/tests/exhaustive.rs")
        .arg("--glob")
        .arg("!crates/pvthfhe-domain-tags/lints/forbid_raw_pvthfhe_domain_tag.sh")
        .arg(".")
        .current_dir(&root)
        .output()
        .expect("ripgrep must be installed and on PATH; install via `cargo install ripgrep` or system pkg");

    assert!(
        output.status.success() || output.status.code() == Some(1),
        "rg failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();

    let mut found: BTreeSet<Vec<u8>> = BTreeSet::new();
    for line in stdout.lines() {
        if let Some(start) = line.rfind(r#"b""#) {
            let after = &line[start + 2..];
            if let Some(end) = after.find('"') {
                found.insert(after.as_bytes()[..end].to_vec());
            }
        }
    }

    assert!(
        !found.is_empty(),
        "RED sanity: rg must find at least one b\"pvthfhe/...\" literal in the workspace; if this assertion fires, the test itself is broken"
    );

    let known: BTreeSet<Vec<u8>> = pvthfhe_domain_tags::Tag::all_literals()
        .iter()
        .map(|b| b.to_vec())
        .collect();

    let missing: Vec<String> = found
        .difference(&known)
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .collect();

    assert!(
        missing.is_empty(),
        "R0.4 RED: the following `b\"pvthfhe/...\"` byte literals are NOT covered by pvthfhe_domain_tags::Tag::all_literals():\n  - {}\n\nGREEN must add a Tag variant for each.",
        missing.join("\n  - ")
    );
}
