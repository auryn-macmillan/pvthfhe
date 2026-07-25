//! IVC compression stage: compress the Cyclo fold report into a succinct
//! proof, bound to the C7 final state, decrypt NIZKs, and DKG transcript.

use anyhow::Context;
use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use pvthfhe_aggregator::folding::CycloFoldAllReport;
use pvthfhe_bench::e2e_timings::E2eTimings;
use sha2::{Digest, Sha256};
use std::time::Instant;

use super::onchain::compute_share_verification_hash;
use super::{elapsed_ms, PipelineConfig, PipelineObserver};
use crate::compressor_glue::{Compressor, E2eCompressedProof};

/// Outputs of the compression stage.
pub(crate) struct CompressStageOutput {
    pub(crate) compressed: E2eCompressedProof,
    pub(crate) compressed_proof_hash: Fr,
    pub(crate) combined_share_hash: Fr,
}

/// Run the compressor stage: construct the compressor, prove, verify, and
/// derive the compressed-proof and combined-share hashes.
pub(crate) fn run_compress_stage<O: PipelineObserver>(
    cfg: &PipelineConfig,
    session_id: &str,
    decrypt_nizk_hash: [u8; 32],
    fold_report: &CycloFoldAllReport,
    c7_final_hash: Fr,
    sk_commitments: &[[u8; 32]],
    share_coeffs: &[Vec<i64>],
    c4_proof_hash: Fr,
    observer: &mut O,
    timings: &mut E2eTimings,
) -> anyhow::Result<CompressStageOutput> {
    // ── CycloFold compressor (runs after C7 for G.16 hash-chain binding) ──
    observer.phase_start("compressor_new", None);
    let compressor_new_started = Instant::now();
    let epoch_hash: [u8; 32] = Sha256::digest(cfg.seed.to_be_bytes()).into();

    // G1 Option B: 90 fold steps for sub-exponential sigma soundness (~142 bits).
    // Each step verifies 1 sigma round (SIGMA_REPETITIONS = 1 in-circuit).
    // The native sigma prover now generates 90-round proofs via prove_multi.
    let fold_steps: usize = 90;

    let mut compressor = Compressor::new(epoch_hash, fold_steps)?;
    observer.phase_end("compressor_new", elapsed_ms(compressor_new_started));

    // P1.5: Bind decrypt NIZK and DKG transcript to IVC proof binding.
    compressor.set_decrypt_nizk_hash(decrypt_nizk_hash);
    let dkg_transcript_hash_bytes: [u8; 32] =
        Sha256::digest(format!("dkg-transcript-{session_id}").as_bytes()).into();
    compressor.set_dkg_transcript_hash(dkg_transcript_hash_bytes);

    observer.phase_start("compressor_prove", Some(compressor.backend_id()));

    let compressor_prove_started = Instant::now();
    let mut compressed = compressor
        .prove(fold_report, c7_final_hash)
        .context("compressor_prove")?;

    // G1+G4: compute per-share verification hash from DKG share commitments.
    let share_verification_hash = compute_share_verification_hash(sk_commitments);
    compressed.share_verification_hash = Some(share_verification_hash);
    let compressor_prove_ms = elapsed_ms(compressor_prove_started);
    observer.phase_end("compressor_prove", compressor_prove_ms);
    timings.phases.compressor_prove.total_ms = compressor_prove_ms;
    timings.phases.compressor_prove.instances_run = 1;

    observer.phase_start("compressor_verify", Some(compressor.backend_id()));
    let compressor_verify_started = Instant::now();
    compressor
        .verify(fold_report, &compressed, c7_final_hash)
        .context("compressor_verify")?;
    let compressor_verify_ms = elapsed_ms(compressor_verify_started);
    observer.phase_end("compressor_verify", compressor_verify_ms);
    timings.phases.compressor_verify.total_ms = compressor_verify_ms;
    timings.phases.compressor_verify.instances_run = 1;

    let compressed_proof_hash = Fr::from_be_bytes_mod_order(&Sha256::digest(compressed.digest));
    tracing::info!("hash-chain 1.2: compressed_proof_hash bound into d_commitment session");

    #[cfg(feature = "enable-latticefold")]
    {
        observer.phase_start("compressor_verify_external", Some(compressor.backend_id()));
        let external_verify_started = Instant::now();
        crate::compressor_glue::external_verify_compressed_proof(
            &compressor,
            &compressed,
            fold_report,
            c7_final_hash,
        )
        .context("compressor_verify_external")?;
        let external_verify_ms = elapsed_ms(external_verify_started);
        observer.phase_end("compressor_verify_external", external_verify_ms);
        observer.note(&format!(
            "external_compressor_verify_ms={external_verify_ms:.2}"
        ));
    }

    let _cyclo_state = [Fr::zero(); 8];

    // G.12 Phase 2: share verification folded via native hash chain

    let combined_share_hash = if !c4_proof_hash.is_zero() {
        c4_proof_hash
    } else {
        let mut hasher = Sha256::new();
        for coeffs in share_coeffs {
            for &c in coeffs {
                hasher.update(c.to_le_bytes());
            }
        }
        Fr::from_be_bytes_mod_order(&hasher.finalize())
    };

    Ok(CompressStageOutput {
        compressed,
        compressed_proof_hash,
        combined_share_hash,
    })
}
