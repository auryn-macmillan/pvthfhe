//! Noir execution helpers.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{HarnessError, NargoArtifacts, Result};

/// Executes a Noir package with a derived prover name inside `circuits/`.
pub fn execute(package: &str, prover_toml: &Path) -> Result<NargoArtifacts> {
    let circuits_dir = circuits_dir();
    let derived_name = prover_name(package);
    let expected_prover_path = circuits_dir
        .join(package)
        .join(format!("{derived_name}.toml"));
    let needs_temp_copy = prover_toml != expected_prover_path;

    if needs_temp_copy {
        fs::copy(prover_toml, &expected_prover_path).map_err(|error| {
            HarnessError::CommandFailed(format!(
                "failed to prepare prover file {} from {}: {error}",
                expected_prover_path.display(),
                prover_toml.display()
            ))
        })?;
    }

    let command_result = Command::new("nargo")
        .args([
            "execute",
            "--package",
            package,
            "--prover-name",
            &derived_name,
        ])
        .current_dir(&circuits_dir)
        .output();

    if needs_temp_copy {
        let _ = fs::remove_file(&expected_prover_path);
    }

    let output = command_result.map_err(|error| {
        HarnessError::CommandFailed(format!(
            "failed to spawn nargo execute for {package}: {error}"
        ))
    })?;

    if !output.status.success() {
        return Err(HarnessError::CommandFailed(format!(
            "nargo execute --package {package} --prover-name {derived_name} exited with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let artifacts = NargoArtifacts {
        witness_path: circuits_dir.join("target").join(format!("{package}.gz")),
        bytecode_path: circuits_dir.join("target").join(format!("{package}.json")),
    };

    ensure_file(&artifacts.witness_path)?;
    ensure_file(&artifacts.bytecode_path)?;

    Ok(artifacts)
}

fn circuits_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../circuits")
}

fn prover_name(package: &str) -> String {
    let mut chars = package.chars();
    match chars.next() {
        Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

fn ensure_file(path: &Path) -> Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        Err(HarnessError::MissingArtifact(path.display().to_string()))
    }
}
