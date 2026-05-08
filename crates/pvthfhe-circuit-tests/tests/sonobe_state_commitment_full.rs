//! Full-dimension harness coverage for `sonobe_state_commitment`.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use pvthfhe_circuit_tests::{bb, nargo};

const EXPECTED_PUBLIC_INPUTS: usize = 6;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn tool_in_path(tool: &str) -> bool {
    env::var_os("PATH")
        .map(|paths| env::split_paths(&paths).any(|path| path.join(tool).is_file()))
        .unwrap_or(false)
}

#[test]
fn sonobe_state_commitment_full_dim_harness_runs_canonical_bb_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    if !tool_in_path("nargo") || !tool_in_path("bb") {
        eprintln!(
            "skipping sonobe_state_commitment full-dimension test because nargo or bb is unavailable in PATH"
        );
        return Ok(());
    }

    let prover_toml = repo_root().join("circuits/sonobe_state_commitment/Prover.toml");
    let nargo_artifacts = nargo::execute("sonobe_state_commitment", &prover_toml)?;
    assert!(nargo_artifacts.witness_path.is_file());
    assert!(nargo_artifacts.bytecode_path.is_file());

    let bb_artifacts = bb::write_vk_prove_verify("sonobe_state_commitment", "ultra_honk")?;
    assert!(bb_artifacts.vk_path.is_file());
    assert!(bb_artifacts.proof_path.is_file());
    assert!(bb_artifacts.public_inputs_path.is_file());

    let public_inputs = fs::read(&bb_artifacts.public_inputs_path)?;
    assert_eq!(
        public_inputs.len() % 32,
        0,
        "bb public_inputs output must be field-aligned"
    );
    assert_eq!(
        public_inputs.len() / 32,
        EXPECTED_PUBLIC_INPUTS,
        "sonobe_state_commitment public input count should remain frozen at six fields"
    );

    Ok(())
}
