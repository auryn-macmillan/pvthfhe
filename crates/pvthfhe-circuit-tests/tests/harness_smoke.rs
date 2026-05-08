//! Smoke test for the circuit-test harness.

use std::{
    env,
    path::{Path, PathBuf},
};

use pvthfhe_circuit_tests::{bb, nargo};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn tool_in_path(tool: &str) -> bool {
    env::var_os("PATH")
        .map(|paths| env::split_paths(&paths).any(|path| path.join(tool).is_file()))
        .unwrap_or(false)
}

#[test]
fn harness_executes_aggregator_final_and_runs_canonical_bb_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    if !tool_in_path("nargo") || !tool_in_path("bb") {
        eprintln!("skipping harness smoke test because nargo or bb is unavailable in PATH");
        return Ok(());
    }

    let prover_toml = repo_root().join("circuits/aggregator_final/Prover.toml");
    let nargo_artifacts = nargo::execute("aggregator_final", &prover_toml)?;
    assert!(nargo_artifacts.witness_path.is_file());
    assert!(nargo_artifacts.bytecode_path.is_file());

    let bb_artifacts = bb::write_vk_prove_verify("aggregator_final", "ultra_honk")?;
    assert!(bb_artifacts.vk_path.is_file());
    assert!(bb_artifacts.proof_path.is_file());
    assert!(bb_artifacts.public_inputs_path.is_file());

    Ok(())
}
