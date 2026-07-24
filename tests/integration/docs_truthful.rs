use std::{fs, path::Path};

fn readme_comparison_report_path(readme: &str) -> &str {
    let marker = "](bench/results/comparison-";
    let start = readme
        .find(marker)
        .unwrap_or_else(|| panic!("README should link a comparison markdown report"));
    let remainder = &readme[start + 2..];
    let end = remainder
        .find(')')
        .unwrap_or_else(|| panic!("README comparison report link should terminate"));
    &remainder[..end]
}

fn markdown_table_rows(markdown: &str) -> Vec<&str> {
    markdown
        .lines()
        .filter(|line| {
            line.starts_with('|') && !line.starts_with("|---") && !line.contains("PVTHFHE (ms)")
        })
        .collect()
}

/// Anti-regression guard for doc honesty (from the Stage-0 era): the docs must
/// never again claim tautological surrogates or killswitch verifiers.
fn assert_no_killswitch_claims(doc: &str, name: &str) {
    for claim in [
        "Noir circuits are tautological surrogates",
        "verifier accepts any proof bytes",
        "verifier is a Stage 0 killswitch",
        "on-chain verifier is a Stage 0 killswitch and reverts on all inputs",
        "PvtFheVerifier reverts on all inputs",
    ] {
        assert!(
            !doc.contains(claim),
            "{name} still contains a killswitch-era claim: {claim}"
        );
    }
}

#[test]
fn test_docs_truthful() {
    let readme = fs::read_to_string("README.md").expect("Failed to read README.md");
    let architecture =
        fs::read_to_string("ARCHITECTURE.md").expect("Failed to read ARCHITECTURE.md");
    let security = fs::read_to_string("SECURITY.md").expect("Failed to read SECURITY.md");
    let warning = fs::read_to_string("WARNING.md").expect("Failed to read WARNING.md");
    let status = fs::read_to_string("STATUS.md").expect("Failed to read STATUS.md");

    assert_no_killswitch_claims(&readme, "README.md");
    assert_no_killswitch_claims(&security, "SECURITY.md");
    assert_no_killswitch_claims(&warning, "WARNING.md");
    assert_no_killswitch_claims(&status, "STATUS.md");

    // README describes the current stack and links a live comparison report.
    assert!(
        readme.contains("LatticeFold+"),
        "README should describe the LatticeFold+ stack"
    );
    assert!(
        readme.contains("DO NOT DEPLOY"),
        "README should carry the DO NOT DEPLOY banner"
    );
    assert!(
        readme.contains("bench/results/comparison"),
        "README should link to benchmark comparison"
    );

    let comparison_report_path = readme_comparison_report_path(&readme);
    assert!(
        Path::new(comparison_report_path).exists(),
        "README comparison report should exist: {comparison_report_path}"
    );
    let comparison_report = fs::read_to_string(comparison_report_path)
        .unwrap_or_else(|err| panic!("Failed to read {comparison_report_path}: {err}"));
    let not_wired_rows = markdown_table_rows(&comparison_report)
        .into_iter()
        .filter(|row| row.contains("not wired"))
        .collect::<Vec<_>>();
    assert!(
        not_wired_rows.is_empty(),
        "README-linked comparison report should have zero not wired rows: {not_wired_rows:?}"
    );

    // README documents the open-problem ledger honestly.
    assert!(
        readme.contains("P1"),
        "README should document open problem P1"
    );

    // ARCHITECTURE documents the current stack and benchmark artifacts.
    assert!(
        architecture.contains("LatticeFold+"),
        "ARCHITECTURE.md should describe LatticeFold+"
    );
    assert!(
        architecture.contains("on-chain commitment"),
        "ARCHITECTURE.md should mention on-chain commitment"
    );
    assert!(
        architecture.contains("bench/results/e2e_timings.json"),
        "ARCHITECTURE.md should mention the e2e timings artifact"
    );
    assert!(
        architecture.contains("comparison.json"),
        "ARCHITECTURE.md should mention the comparison JSON artifact"
    );
    assert!(
        architecture.contains("comparison.md"),
        "ARCHITECTURE.md should mention the rendered comparison markdown artifact"
    );
}
