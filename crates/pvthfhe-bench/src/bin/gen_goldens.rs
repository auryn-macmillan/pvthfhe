#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use clap::Parser;
use pvthfhe_aggregator::folding::{CcsPShareInstance, HashChainCycloAdapter};
use pvthfhe_types::{CcsWitnessSecret, ProtocolBytes};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::json;
use std::path::PathBuf;

const SEED: u64 = 42;
const N_PARTIES: u32 = 4;

#[derive(Parser)]
#[command(
    name = "gen_goldens",
    about = "Generate deterministic golden proof files for T39"
)]
struct Args {
    #[arg(long)]
    out: PathBuf,
}

fn main() {
    let args = Args::parse();

    std::fs::create_dir_all(&args.out).expect("create output directory");

    let adapter = HashChainCycloAdapter::new();
    let instances = (0..N_PARTIES)
        .map(|party_id| {
            let share_hash = sha2_hash(&[&SEED.to_le_bytes()[..], &party_id.to_le_bytes()[..]]);
            let nizk_bytes = sha2_hash(&[
                b"nizk",
                &SEED.to_le_bytes()[..],
                &party_id.to_le_bytes()[..],
            ])
            .to_vec();

            CcsPShareInstance {
                participant_id: (party_id + 1) as u16,
                ajtai_commitment_bytes: ProtocolBytes(share_hash.to_vec()),
                public_io_bytes: ProtocolBytes(nizk_bytes),
                ccs_witness_bytes: CcsWitnessSecret::new(vec![1u8; 32]),
                sha256_binding_bytes: ProtocolBytes(share_hash.to_vec()),
                ccs_matrix_bytes: ProtocolBytes(vec![]),
            }
        })
        .collect::<Vec<_>>();
    let mut rng = ChaCha20Rng::seed_from_u64(SEED);
    let report = adapter
        .fold_all(&instances, "gen-goldens", &mut rng)
        .expect("fold_all");
    adapter
        .verify_fold_all(&report, &instances)
        .expect("verify_fold_all");
    let honest_proof = report.accumulators()[0].acc_commitment_bytes.clone();
    assert!(!honest_proof.is_empty(), "expected non-empty proof bytes");

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
    std::fs::write(
        &pi_path,
        serde_json::to_string_pretty(&public_inputs).unwrap(),
    )
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
