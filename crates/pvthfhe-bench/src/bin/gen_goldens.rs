#![allow(missing_docs, clippy::unwrap_used)]

use clap::Parser;
use pvthfhe_aggregator::folding::{FoldingAccumulator, PartyProof};
use serde_json::json;
use std::path::PathBuf;

const SEED: u64 = 42;
const N_PARTIES: u32 = 4;

#[derive(Parser)]
#[command(name = "gen_goldens", about = "Generate deterministic golden proof files for T39")]
struct Args {
    #[arg(long)]
    out: PathBuf,
}

fn main() {
    let args = Args::parse();

    std::fs::create_dir_all(&args.out).expect("create output directory");

    let mut acc = FoldingAccumulator::new();
    for party_id in 0..N_PARTIES {
        let share_hash = sha2_hash(&[&SEED.to_le_bytes()[..], &party_id.to_le_bytes()[..]]);
        let nizk_bytes =
            sha2_hash(&[b"nizk", &SEED.to_le_bytes()[..], &party_id.to_le_bytes()[..]]).to_vec();

        acc.add_proof(PartyProof { party_id, share_hash, nizk_bytes }).expect("add_proof");
    }

    let snark = acc.finalize().expect("finalize");
    let honest_proof = snark.proof_bytes;
    assert_eq!(honest_proof.len(), 32, "expected 32-byte SHA256 digest");

    let honest_path = args.out.join("honest.proof");
    std::fs::write(&honest_path, &honest_proof).expect("write honest.proof");
    println!("wrote {}", honest_path.display());

    let proof_hash_hex = hex::encode(&honest_proof);
    let public_inputs = json!({
        "n": N_PARTIES,
        "seed": SEED,
        "proof_hash": format!("0x{}", proof_hash_hex)
    });
    let pi_path = args.out.join("honest.public_inputs.json");
    std::fs::write(&pi_path, serde_json::to_string_pretty(&public_inputs).unwrap())
        .expect("write honest.public_inputs.json");
    println!("wrote {}", pi_path.display());

    let mut tampered = honest_proof.clone();
    tampered[0] ^= 0x01;
    let tampered_path = args.out.join("tampered.proof");
    std::fs::write(&tampered_path, &tampered).expect("write tampered.proof");
    println!("wrote {}", tampered_path.display());

    println!("proof_hash: 0x{}", proof_hash_hex);
    println!("done");
}

fn sha2_hash(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
