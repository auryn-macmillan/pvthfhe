//! Dependency lock integration test for pinned fhe.rs crates.

use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;

const LOCKED_REV: &str = "5f24d0b62a7329b789db07a065b68accd614a47b";
const FHE_RS_URL: &str = "https://github.com/gnosisguild/fhe.rs";

#[test]
fn metadata_contains_locked_fhe_rs_packages() {
    let repo_root = repo_root();
    let manifest_path = repo_root.join("crates/pvthfhe-fhe/Cargo.toml");
    let metadata = cargo_metadata_json(&repo_root, &manifest_path);
    validate_locked_packages(&metadata).unwrap_or_else(|err| panic!("{err}"));
}

#[test]
fn duplicate_package_sources_are_reported() {
    let metadata = r#"
    {
      "packages": [
        {"name": "fhe", "source": "git+https://github.com/gnosisguild/fhe.rs?rev=rev-a#rev-a"},
        {"name": "fhe", "source": "git+https://github.com/gnosisguild/fhe.rs?rev=rev-b#rev-b"}
      ]
    }
    "#;

    let err = validate_locked_packages(metadata).expect_err("duplicate sources must fail");
    assert!(err.contains("multiple sources"), "unexpected error: {err}");
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap_or_else(|| unreachable!("crate manifest dir must be nested under repo root"))
        .to_path_buf()
}

fn cargo_metadata_json(repo_root: &Path, manifest_path: &Path) -> String {
    let output = Command::new("cargo")
        .current_dir(repo_root)
        .args([
            "metadata",
            "--locked",
            "--format-version=1",
            "--manifest-path",
            manifest_path
                .to_str()
                .unwrap_or_else(|| unreachable!("manifest path must be valid UTF-8")),
        ])
        .output()
        .unwrap_or_else(|err| panic!("failed to execute cargo metadata: {err}"));

    assert!(
        output.status.success(),
        "cargo metadata command failed: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout)
        .unwrap_or_else(|err| panic!("cargo metadata output was not valid UTF-8: {err}"))
}

fn validate_locked_packages(metadata_json: &str) -> Result<(), String> {
    let metadata: Value = serde_json::from_str(metadata_json)
        .map_err(|err| format!("cargo metadata output was not valid JSON: {err}"))?;
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| "cargo metadata JSON missing `packages` array".to_owned())?;

    let mut sources_by_package: HashMap<String, BTreeSet<String>> = HashMap::new();

    for package in packages {
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "package entry missing `name`".to_owned())?;
        if !matches!(name, "fhe" | "fhe-traits" | "fhe-math") {
            continue;
        }
        let source = package
            .get("source")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("package `{name}` missing `source` in cargo metadata output"))?;
        sources_by_package
            .entry(name.to_owned())
            .or_default()
            .insert(source.to_owned());
    }

    for package in ["fhe", "fhe-traits", "fhe-math"] {
        let sources = sources_by_package
            .get(package)
            .ok_or_else(|| format!("missing package `{package}` in cargo metadata"))?;
        if sources.len() != 1 {
            return Err(format!(
                "package `{package}` resolved from multiple sources: {:?}",
                sources
            ));
        }
        let source = sources
            .iter()
            .next()
            .unwrap_or_else(|| unreachable!("validated non-empty set"));
        let expected = format!("git+{FHE_RS_URL}?rev={LOCKED_REV}#{LOCKED_REV}");
        if source != &expected {
            return Err(format!(
                "package `{package}` must resolve exactly to `{expected}`, got `{source}`"
            ));
        }
    }

    Ok(())
}
