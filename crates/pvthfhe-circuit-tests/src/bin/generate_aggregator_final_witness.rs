//! Generates `circuits/aggregator_final/Prover.toml` from the shared witness logic.

use std::path::Path;

use pvthfhe_circuit_tests::witness_gen::generate_aggregator_final_witness;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../circuits/aggregator_final/Prover.toml");
    let witness = generate_aggregator_final_witness();
    witness.write_to_path(&output_path)?;
    println!("wrote {}", output_path.display());
    Ok(())
}
