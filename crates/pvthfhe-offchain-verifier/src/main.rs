//! CLI for verifying Sonobe proofs and emitting an attestation bundle.

use std::{fs, path::PathBuf};

use clap::Parser;
use pvthfhe_compressor::{
    sonobe::SonobeCompressor, CompressedProof, ProofCompressor,
};
use serde::Deserialize;
use sha3::{Digest, Keccak256};

use pvthfhe_offchain_verifier::attestation::AttestationBundle;

const DEFAULT_SEED: u64 = 7;
const DEFAULT_SIGNER: &str = "0x00000000000000000000000000000000ephemeral";
const DEFAULT_SIGNATURE: &str = "0x00placeholder";

#[derive(Debug, Deserialize)]
struct ProofEnvelope {
    proof: String,
    public_inputs: String,
    #[serde(default = "default_seed")]
    seed: u64,
}

/// Verify a serialized Sonobe proof and emit an attestation bundle.
#[derive(Debug, Parser)]
#[command(
    name = "pvthfhe-offchain-verifier",
    version,
    about = "Verify a Sonobe proof and emit an attestation bundle"
)]
struct Args {
    /// Path to the serialized Sonobe proof bytes.
    #[arg(long)]
    proof: PathBuf,
    /// Path to write the emitted attestation bundle JSON.
    #[arg(long = "emit-attestation")]
    emit_attestation: PathBuf,
}

fn main() -> Result<(), String> {
    let args = Args::parse();
    let envelope = read_proof_envelope(&args.proof)?;
    let proof_bytes = decode_hex_field(&envelope.proof)?;
    let public_inputs = decode_hex_field(&envelope.public_inputs)?;

    let proof = CompressedProof(proof_bytes.clone());
    let compressor = SonobeCompressor::new(envelope.seed)
        .map_err(|error| format!("failed to initialize verifier: {error:?}"))?;
    let vk = compressor.verifier_key();

    let is_valid = compressor
        .verify(&vk, &proof, &public_inputs)
        .map_err(|error| format!("proof verification failed: {error:?}"))?;
    if !is_valid {
        return Err("proof verification returned false".to_string());
    }

    let bundle = AttestationBundle {
        sonobe_final_state_commitment: to_hex(Keccak256::digest(&proof_bytes)),
        cyclo_aggregate_commitment: to_hex(Keccak256::digest([proof_bytes.as_slice(), b"cyclo"].concat())),
        session_id: to_hex(Keccak256::digest([proof_bytes.as_slice(), b"session"].concat())),
        signer: DEFAULT_SIGNER.to_string(),
        signature: DEFAULT_SIGNATURE.to_string(),
    };

    let bundle_json = serde_json::to_string_pretty(&bundle)
        .map_err(|error| format!("failed to serialize attestation bundle: {error}"))?;
    fs::write(&args.emit_attestation, bundle_json).map_err(|error| {
        format!(
            "failed to write attestation {}: {error}",
            args.emit_attestation.display()
        )
    })?;

    Ok(())
}

fn read_proof_envelope(path: &PathBuf) -> Result<ProofEnvelope, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("failed to read proof {}: {error}", path.display()))?;
    serde_json::from_str(&contents)
        .map_err(|error| format!("failed to parse proof envelope {}: {error}", path.display()))
}

fn decode_hex_field(value: &str) -> Result<Vec<u8>, String> {
    let normalized = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(normalized).map_err(|error| format!("invalid hex field {value}: {error}"))
}

fn default_seed() -> u64 {
    DEFAULT_SEED
}

fn to_hex(bytes: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(bytes.as_ref()))
}
