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
        .filter(|line| line.starts_with('|') && !line.starts_with("|---") && !line.contains("PVTHFHE (ms)"))
        .collect()
}

#[test]
fn test_docs_truthful() {
    let readme = fs::read_to_string("README.md").expect("Failed to read README.md");
    let architecture = fs::read_to_string("ARCHITECTURE.md").expect("Failed to read ARCHITECTURE.md");
    let security = fs::read_to_string("SECURITY.md").expect("Failed to read SECURITY.md");

    let warning = fs::read_to_string("WARNING.md").expect("Failed to read WARNING.md");
    let status = fs::read_to_string("STATUS.md").expect("Failed to read STATUS.md");
    // README should NOT contain "tautological surrogates" or "reverts on all inputs"
    assert!(!readme.contains("Noir circuits are tautological surrogates"), "README still claims Noir circuits are tautological surrogates");
    assert!(!readme.contains("on-chain verifier is a Stage 0 killswitch and reverts on all inputs"), "README still claims verifier reverts on all inputs");
    assert!(!readme.contains("PvtFheVerifier reverts on all inputs"), "README still claims PvtFheVerifier reverts on all inputs");

    // README should mention Sonobe and link to benchmarks
    assert!(readme.contains("Sonobe"), "README should mention Sonobe substitution");
    assert!(readme.contains("bench/results/comparison"), "README should link to benchmark comparison");
    assert!(
        readme.contains("all 12 rows are now populated"),
        "README should note that all 12 comparison rows are populated"
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

    // README should RETAIN P1 banner
    println!("Checking P1 banner in README");
    assert!(readme.contains("Open Problem P1"), "README should retain P1 banner");
    println!("Checking Tripwire in README");
    assert!(readme.contains("Stage 0 Build-time Tripwire"), "README should retain build-time tripwire description");

    // ARCHITECTURE should mention Sonobe substitution for MicroNova
    assert!(architecture.contains("Sonobe"), "ARCHITECTURE.md should mention Sonobe");
    assert!(architecture.contains("off-chain Sonobe"), "ARCHITECTURE.md should describe off-chain Sonobe topology");
    assert!(architecture.contains("on-chain commitment"), "ARCHITECTURE.md should mention on-chain commitment");
    assert!(architecture.contains("## Benchmarking"), "ARCHITECTURE.md should document benchmarking artifacts");
    assert!(
        architecture.contains("bench/results/e2e_timings.json"),
        "ARCHITECTURE.md should mention the e2e timings artifact"
    );
    assert!(
        architecture.contains("schema_version `1.0.0`"),
        "ARCHITECTURE.md should document the timings schema version"
    );
    assert!(
        architecture.contains("12 phases"),
        "ARCHITECTURE.md should document the 12 benchmark phases"
    );
    assert!(
        architecture.contains("comparison.json"),
        "ARCHITECTURE.md should mention the comparison JSON artifact"
    );
    assert!(
        architecture.contains("comparison.md"),
        "ARCHITECTURE.md should mention the rendered comparison markdown artifact"
    );

    // SECURITY should reflect current truth
    assert!(!security.contains("verifier accepts any proof bytes"), "SECURITY.md still claims verifier accepts any proof bytes");
    assert!(!security.contains("verifier is a Stage 0 killswitch"), "SECURITY.md still claims verifier is a Stage 0 killswitch");

    // WARNING and STATUS should not contain stale claims about tautological surrogates or bypass-verifier
    assert!(!warning.contains("verifier accepts any proof bytes"), "WARNING.md still claims verifier accepts any proof bytes");
    assert!(!warning.contains("Noir circuits are tautological surrogates"), "WARNING.md still claims Noir circuits are tautological surrogates");
    assert!(!status.contains("verifier accepts any proof bytes"), "STATUS.md still claims verifier accepts any proof bytes");
    assert!(!status.contains("Noir circuits are tautological surrogates"), "STATUS.md still claims Noir circuits are tautological surrogates");
}
