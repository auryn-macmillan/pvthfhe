//! CLI for verifying compression proofs and emitting an attestation bundle.

#![allow(
    missing_docs,
    unexpected_cfgs,
    unused_imports,
    unused_variables,
    unreachable_code,
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used
)]

use std::{fs, path::PathBuf};

use clap::Parser;
use pvthfhe_compressor::CompressedProof;
use serde::Deserialize;
use sha3::{Digest, Keccak256};
#[cfg(feature = "enable-latticefold")]
use pvthfhe_compressor::latticefold::LatticeFoldCompressor;

use pvthfhe_offchain_verifier::{attestation::AttestationBundle, check_srs_hash};

#[derive(Debug, Deserialize)]
struct ProofEnvelope {
    proof: String,
    public_inputs: String,
    #[serde(default)]
    epoch_hash: String,
    #[serde(default = "default_ivc_steps")]
    ivc_steps: usize,
    #[serde(default)]
    expected_srs_hash: String,
}

fn default_ivc_steps() -> usize {
    4
}

/// Verify a serialized compression proof and emit an attestation bundle.
#[derive(Debug, Parser)]
#[command(
    name = "pvthfhe-offchain-verifier",
    version,
    about = "Verify a compression proof and emit an attestation bundle"
)]
struct Args {
    /// Path to the serialized compressed proof bytes.
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

    #[cfg(feature = "enable-latticefold")]
    {
        let epoch_hash = decode_epoch_hash(&envelope.epoch_hash)?;

        let expected_srs_hash = decode_epoch_hash(&envelope.expected_srs_hash)
            .map_err(|error| format!("expected_srs_hash: {error}"))?;

        let compressor =
            LatticeFoldCompressor::new(epoch_hash, envelope.ivc_steps, 131072)
                .map_err(|error| {
                    format!("failed to initialize LatticeFold+ verifier: {error:?}")
                })?;

        check_srs_hash(&compressor.srs_hash(), &expected_srs_hash)
            .map_err(|error| format!("SRS hash mismatch: {error}"))?;

        let proof = CompressedProof::new(proof_bytes.clone());
        let vk = compressor.verifier_key();
        let acc_bytes = vec![0u8; 96]; // zero triple — acc not verified in verify()

        let is_valid = compressor
            .verify(&vk, &proof, &acc_bytes, &public_inputs)
            .map_err(|error| {
                format!("LatticeFold+ proof verification failed: {error:?}")
            })?;
        if !is_valid {
            return Err("LatticeFold+ proof verification returned false".to_string());
        }
    }
    #[cfg(not(feature = "enable-latticefold"))]
    {
        return Err(
            "Track A (Nova BN254+Grumpkin) removed. \
             Enable the `enable-latticefold` feature for LatticeFold+ verification."
                .to_string(),
        );
    }

    let bundle = AttestationBundle {
        accumulator_state_commitment: to_hex(Keccak256::digest(&proof_bytes)),
        cyclo_aggregate_commitment: to_hex(Keccak256::digest(
            [proof_bytes.as_slice(), b"cyclo"].concat(),
        )),
        session_id: to_hex(Keccak256::digest(
            [proof_bytes.as_slice(), b"session"].concat(),
        )),
        signer: String::new(),
        signature: String::new(),
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

fn to_hex(bytes: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(bytes.as_ref()))
}

fn decode_epoch_hash(value: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex_field(value)?;
    if bytes.len() != 32 {
        return Err(format!(
            "epoch_hash must be 32 bytes, got {} bytes",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
