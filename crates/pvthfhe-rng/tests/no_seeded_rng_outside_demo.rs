use std::process::Command;

const FORBIDDEN: &str = r"\bseed_from_u64\b|\bfrom_seed\b|\bStdRng::\w*seed|\bChaCha20Rng::\w*seed|\bChaCha8Rng::\w*seed";

fn is_allowlisted(path: &str) -> bool {
    path.contains("/tests/")
        || path.contains("/benches/")
        || path.starts_with("crates/pvthfhe-rng/")
        || path.split('/').next_back().is_some_and(|file| {
            file.starts_with("demo")
                || file.starts_with("worked_example")
                || file.starts_with("bench_")
                || file.starts_with("fhe_baseline")
                || file.starts_with("gen_goldens")
        })
}

fn line_has_annotation(content: &str) -> bool {
    content.contains("// allow-seeded-rng:")
}

fn is_comment(content: &str) -> bool {
    content.trim_start().starts_with("//")
}

fn workspace_root() -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().parent().unwrap().to_path_buf()
}

#[test]
fn no_seeded_rng_in_production() {
    let root = workspace_root();
    let out = Command::new("rg")
        .args(["-n", "--no-heading", "-t", "rust", FORBIDDEN, "crates/"])
        .current_dir(&root)
        .output()
        .expect("rg must be installed");

    assert!(
        out.status.success() || out.status.code() == Some(1),
        "rg failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let violations: Vec<_> = stdout
        .lines()
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let mut parts = line.splitn(3, ':');
            let path = parts.next()?;
            let line_no = parts.next()?;
            let content = parts.next()?;

            if is_allowlisted(path) || line_has_annotation(content) || is_comment(content) {
                None
            } else {
                Some(format!("{path}:{line_no}: {}", content.trim()))
            }
        })
        .collect();

    if !violations.is_empty() {
        panic!(
            "R0.7 violation: {} production seeded-RNG callsite(s):\n{}\n\nMigrate to OsRng via `pvthfhe_rng::ProductionRng`, or annotate with `// allow-seeded-rng: <reason>` for construction-required determinism.",
            violations.len(),
            violations.join("\n")
        );
    }
}
