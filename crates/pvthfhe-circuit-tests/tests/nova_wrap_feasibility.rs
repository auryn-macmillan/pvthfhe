//! Feasibility-doc guard for the Nova wrap spike.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn extract_front_matter(contents: &str) -> Option<&str> {
    let rest = contents.strip_prefix("---\n")?;
    let end = rest.find("\n---\n")?;
    Some(&rest[..end])
}

fn extract_verdict(front_matter: &str) -> Option<&str> {
    front_matter
        .lines()
        .find_map(|line| line.strip_prefix("verdict:").map(str::trim))
}

#[test]
fn nova_wrap_feasibility_doc_records_binary_verdict() -> Result<(), Box<dyn std::error::Error>> {
    let doc_path = repo_root().join(".sisyphus/research/nova-wrap-feasibility.md");
    let contents = fs::read_to_string(&doc_path)?;
    let front_matter = extract_front_matter(&contents).ok_or("missing YAML front matter")?;
    let verdict = extract_verdict(front_matter).ok_or("missing verdict field")?;

    assert!(
        matches!(verdict, "Go" | "NoGo"),
        "expected verdict to be Go or NoGo, got {verdict}"
    );

    Ok(())
}
