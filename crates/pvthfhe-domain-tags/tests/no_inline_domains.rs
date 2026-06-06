//! M2 RED: no raw domain string literals outside `crates/pvthfhe-domain-tags/src/lib.rs`.
//!
//! This test greps all crate source directories for `b"pvthfhe` and `"pvthfhe/`
//! patterns, excluding the domain-tags crate itself and test files.
//! It is expected to be RED until all inline domain strings are consolidated.
//!
//! Every inline match found means a Tag variant still needs to be registered
//! and the call site must be migrated to `Tag::Variant.as_bytes()`.

use std::collections::BTreeSet;
use std::process::Command;

fn workspace_root() -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().parent().unwrap().to_path_buf()
}

#[test]
fn no_inline_domain_tag_literals_anywhere() {
    let root = workspace_root();

    // Pattern: byte-string literals starting with b"pvthfhe (any separator char)
    let output_bytes = Command::new("rg")
        .arg("--no-heading")
        .arg("--no-line-number")
        .arg("--line-number")
        .arg("-o")
        .arg(r#"b"pvthfhe[^"]*"#)
        .arg("--glob")
        .arg("!**/target/**")
        .arg("--glob")
        .arg("!**/tests/**")
        .arg("--glob")
        .arg("!crates/pvthfhe-domain-tags/src/**")
        .arg("--glob")
        .arg("!crates/pvthfhe-domain-tags/tests/**")
        .arg("crates/")
        .current_dir(&root)
        .output()
        .expect("ripgrep (rg) must be installed and on PATH");

    assert!(
        output_bytes.status.success() || output_bytes.status.code() == Some(1),
        "rg for byte literals failed: {}",
        String::from_utf8_lossy(&output_bytes.stderr)
    );

    let mut found: BTreeSet<String> = BTreeSet::new();
    let stdout_bytes = String::from_utf8(output_bytes.stdout).unwrap();
    for line in stdout_bytes.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            found.insert(trimmed.to_string());
        }
    }

    // Pattern: plain string literals starting with "pvthfhe/
    let output_str = Command::new("rg")
        .arg("--no-heading")
        .arg("--line-number")
        .arg("-o")
        .arg(r#""pvthfhe/[^"]*"#)
        .arg("--glob")
        .arg("!**/target/**")
        .arg("--glob")
        .arg("!**/tests/**")
        .arg("--glob")
        .arg("!crates/pvthfhe-domain-tags/src/**")
        .arg("--glob")
        .arg("!crates/pvthfhe-domain-tags/tests/**")
        .arg("crates/")
        .current_dir(&root)
        .output()
        .expect("ripgrep (rg) must be installed and on PATH");

    assert!(
        output_str.status.success() || output_str.status.code() == Some(1),
        "rg for string literals failed: {}",
        String::from_utf8_lossy(&output_str.stderr)
    );

    let stdout_str = String::from_utf8(output_str.stdout).unwrap();
    for line in stdout_str.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            found.insert(trimmed.to_string());
        }
    }

    if found.is_empty() {
        // No inline domain strings found — this is GREEN.
        // The test passes when everything is consolidated.
        return;
    }

    // RED: emit all remaining inline domain strings for visibility.
    let mut report = String::from("M2 RED: inline domain string literals still present:\n");
    for f in &found {
        report.push_str(&format!("  {f}\n"));
    }
    report.push_str(
        "\nEach must be registered as a Tag variant and replaced with Tag::Variant.as_bytes().",
    );

    panic!("{report}");
}
