//! Binary for generating `circuits/ivc_state_commitment/Prover.toml`.

use std::path::Path;

use pvthfhe_circuit_tests::witness_gen::generate_ivc_state_commitment_witness;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let prover_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/ivc_state_commitment/Prover.toml");
    let derived_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/ivc_state_commitment/Ivc_state_commitment.toml");
    let witness = generate_ivc_state_commitment_witness();
    witness.write_to_path(&prover_path)?;
    witness.write_to_path(&derived_path)?;
    println!("wrote {}", prover_path.display());
    println!("wrote {}", derived_path.display());
    Ok(())
}
