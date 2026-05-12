//! Legacy compatibility binary for generating `circuits/decrypt_share/Prover.toml`.

use std::path::Path;

use pvthfhe_circuit_tests::witness_gen::generate_decrypt_share_witness;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../circuits/decrypt_share/Prover.toml");
    let witness = generate_decrypt_share_witness();
    witness.write_to_path(&output_path)?;
    println!("wrote {}", output_path.display());
    Ok(())
}
