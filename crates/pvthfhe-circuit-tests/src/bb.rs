//! Barretenberg execution helpers.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use crate::{BbArtifacts, HarnessError, Result};

/// Runs `bb write_vk`, `bb prove`, and `bb verify` in canonical order.
pub fn write_vk_prove_verify(package: &str, scheme: &str) -> Result<BbArtifacts> {
    let circuits_dir = circuits_dir();
    run_bb(
        &circuits_dir,
        [
            "write_vk",
            "--scheme",
            scheme,
            "-b",
            &format!("target/{package}.json"),
            "-o",
            "target",
        ],
    )?;
    run_bb(
        &circuits_dir,
        [
            "prove",
            "--scheme",
            scheme,
            "-b",
            &format!("target/{package}.json"),
            "-w",
            &format!("target/{package}.gz"),
            "-o",
            "target",
        ],
    )?;
    run_bb(
        &circuits_dir,
        [
            "verify",
            "--scheme",
            scheme,
            "-k",
            "target/vk",
            "-p",
            "target/proof",
            "-i",
            "target/public_inputs",
        ],
    )?;

    let artifacts = BbArtifacts {
        vk_path: circuits_dir.join("target/vk"),
        proof_path: circuits_dir.join("target/proof"),
        public_inputs_path: circuits_dir.join("target/public_inputs"),
    };

    ensure_file(&artifacts.vk_path)?;
    ensure_file(&artifacts.proof_path)?;
    ensure_file(&artifacts.public_inputs_path)?;

    Ok(artifacts)
}

fn circuits_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../circuits")
}

fn run_bb<const N: usize>(circuits_dir: &Path, args: [&str; N]) -> Result<()> {
    let output = Command::new("bb")
        .args(args)
        .current_dir(circuits_dir)
        .output()
        .map_err(|error| HarnessError::CommandFailed(format!("failed to spawn bb: {error}")))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(HarnessError::CommandFailed(format!(
            "bb {} exited with {}\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

fn ensure_file(path: &Path) -> Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        Err(HarnessError::MissingArtifact(path.display().to_string()))
    }
}
