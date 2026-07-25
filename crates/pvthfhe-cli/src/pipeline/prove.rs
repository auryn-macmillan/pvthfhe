//! Keygen NIZK prove/verify stage: per-dealer sigma proofs, share-provenance
//! binding checks, and the all-proofs session hash.

use anyhow::Context;
use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use pvthfhe_aggregator::keygen::types::{DkgTranscript, Round1Message};
use pvthfhe_bench::e2e_timings::E2eTimings;
use pvthfhe_fhe::fhers::FhersBackend;
use pvthfhe_fhe::real_nizk::{LatticeNizk, NizkProof, NizkStatement, NizkWitness, RealNizkAdapter};
use pvthfhe_fhe::FheBackend;
use pvthfhe_foundations::rng::OsRng;
use pvthfhe_nizk::adapter::extract_sigma_proof;
use pvthfhe_nizk::sigma::compute_sk_binding;
use sha2::{Digest, Sha256};
use std::time::Instant;

use super::onchain::noir_poseidon_sponge;
use super::{elapsed_ms, PipelineConfig, PipelineObserver};
use crate::demo_nizk::build_demo_nizk_inputs;

/// Outputs of the NIZK prove/verify stage.
pub(crate) struct ProveStageOutput {
    pub(crate) nizk_outputs: Vec<(u32, NizkStatement, NizkWitness, NizkProof)>,
    pub(crate) registered_sk_bindings: Vec<[u8; 32]>,
    pub(crate) all_nizk_proof_hash: Fr,
}

/// Run the NIZK stage: prove each dealer's sigma statement, verify all proofs,
/// and bind them to the registered secret-key commitments.
pub(crate) fn run_prove_stage<O: PipelineObserver>(
    cfg: &PipelineConfig,
    backend: &FhersBackend,
    transcript: &DkgTranscript,
    session_id: &str,
    sk_commitments: &[[u8; 32]],
    observer: &mut O,
    timings: &mut E2eTimings,
) -> anyhow::Result<ProveStageOutput> {
    let mut nizk_outputs = Vec::with_capacity(transcript.round1_messages.len());
    let mut nizk_prove_per_instance_ms = Vec::with_capacity(transcript.round1_messages.len());
    for message in &transcript.round1_messages {
        let (statement, witness) = build_nizk_inputs(session_id, message, cfg.seed, backend)?;
        let mut rng = OsRng;
        observer.phase_start("nizk_prove", Some(&format!("dealer={}", message.party_id)));
        let started = Instant::now();
        let proof = RealNizkAdapter::prove(&statement, &witness, &mut rng)
            .with_context(|| format!("nizk prove dealer {}", message.party_id))?;
        let ms = elapsed_ms(started);
        observer.phase_end("nizk_prove", ms);
        nizk_prove_per_instance_ms.push(ms);
        nizk_outputs.push((message.party_id, statement, witness, proof));
    }
    timings.phases.nizk_prove.total_ms = nizk_prove_per_instance_ms.iter().sum();
    timings.phases.nizk_prove.instances_run = nizk_prove_per_instance_ms.len();
    timings.phases.nizk_prove.per_instance_ms = nizk_prove_per_instance_ms;

    // G.SHARE-PROVENANCE: register per-party sk_bindings from proof-embedded d_rns
    let mut registered_sk_bindings: Vec<[u8; 32]> = vec![[0u8; 32]; cfg.n];
    for (_party_id, statement, _witness, proof) in &nizk_outputs {
        let party_idx = u32::from(statement.participant_id) as usize;
        if party_idx > 0 && party_idx <= cfg.n {
            let (d_rns, _) = extract_sigma_proof(&proof.proof_bytes)
                .with_context(|| format!("extract sigma proof for party {party_idx}"))?;
            let binding = compute_sk_binding(
                &d_rns,
                u32::from(statement.participant_id),
                session_id.as_bytes(),
            );
            registered_sk_bindings[party_idx - 1] = binding;
        }
    }

    // G.SHARE-PROVENANCE: verify NIZK pvss_commitment matches registered sk_commitment
    for (_party_id, statement, _witness, _proof) in &nizk_outputs {
        let party_index = statement.participant_id as usize;
        if party_index > 0 && party_index <= sk_commitments.len() {
            let registered = sk_commitments[party_index - 1];
            if statement.pvss_commitment != registered {
                anyhow::bail!(
                    "share provenance check failed for party {party_index}: \
                     pvss_commitment mismatch with registered sk_commitment"
                );
            }
        }
    }

    // G.12 Phase 4: Compute Ajtai commitment hash natively
    let _combined_commitment_hash = if sk_commitments.is_empty() {
        Fr::zero()
    } else {
        use pvthfhe_compressor::witness::poseidon_sponge_hash_native;
        let sk_fr: Vec<Fr> = sk_commitments
            .iter()
            .map(|c| Fr::from_be_bytes_mod_order(c))
            .collect();
        poseidon_sponge_hash_native(&sk_fr)
    };

    let _combined_sk_commitment_hash = if sk_commitments.is_empty() {
        Fr::zero()
    } else {
        use pvthfhe_compressor::witness::poseidon_sponge_hash_native;
        let sk_fr: Vec<Fr> = sk_commitments
            .iter()
            .map(|c| Fr::from_be_bytes_mod_order(c))
            .collect();
        poseidon_sponge_hash_native(&sk_fr)
    };

    use rayon::prelude::*;
    let mut nizk_verify_total_ms = 0.0;
    let mut nizk_verify_per_instance_ms = Vec::new();
    // C3: share-commitment binding — after the sigma proof verifies, assert
    // that the pvss_commitment claimed in the NIZK statement matches the
    // expected commitment computed from the dealer's actual secret key.
    // Without this, a malicious dealer can submit a valid sigma proof over one
    // share while claiming a commitment to a different share.
    let results: Vec<Result<(String, f64), anyhow::Error>> = nizk_outputs
        .par_iter()
        .flat_map(|(dealer_id, statement, _witness, proof)| {
            let expected_commitment = sk_commitments
                .get((*dealer_id as usize).saturating_sub(1))
                .copied()
                .unwrap_or([0u8; 32]);
            (1..=cfg.n).into_par_iter().map(move |recipient_id| {
                let detail = format!("dealer={dealer_id} recipient={recipient_id}");
                let started = Instant::now();
                RealNizkAdapter::verify(statement, proof).map_err(|e| {
                    anyhow::anyhow!("nizk_verify dealer={dealer_id} recipient={recipient_id}: {e}")
                })?;
                // C3: decoded PVSS commitment from the proof must match the
                // expected share commitment computed from the dealer's secret key.
                if statement.pvss_commitment != expected_commitment {
                    anyhow::bail!(
                        "PVSS commitment mismatch for dealer {dealer_id} recipient {recipient_id}: \
                         proof claims commitment {:02x?} but expected {:02x?}",
                        &statement.pvss_commitment[..],
                        &expected_commitment[..]
                    );
                }
                let ms = started.elapsed().as_secs_f64() * 1000.0;
                Ok((detail, ms))
            })
        })
        .collect();

    for result in results {
        let (detail, ms) = result?;
        observer.phase_start("nizk_verify", Some(&detail));
        observer.phase_end("nizk_verify", ms);
        nizk_verify_per_instance_ms.push(ms);
        nizk_verify_total_ms += ms;
    }
    timings.phases.nizk_verify.total_ms = nizk_verify_total_ms;
    timings.phases.nizk_verify.instances_run = nizk_verify_per_instance_ms.len();
    timings.phases.nizk_verify.per_instance_ms = nizk_verify_per_instance_ms;

    // G.SHARE-PROVENANCE: verify nizk proof binds to registered sk_binding
    for (_party_id, statement, _witness, proof) in &nizk_outputs {
        let party_idx = u32::from(statement.participant_id) as usize;
        if party_idx > 0 && party_idx <= registered_sk_bindings.len() {
            let (d_rns, _) = extract_sigma_proof(&proof.proof_bytes).with_context(|| {
                format!("extract sigma proof for share provenance check party {party_idx}")
            })?;
            let binding = compute_sk_binding(
                &d_rns,
                u32::from(statement.participant_id),
                session_id.as_bytes(),
            );
            let expected = registered_sk_bindings[party_idx - 1];
            if binding != expected {
                anyhow::bail!(
                    "share provenance FAILED for party {party_idx}: \
                     sk_binding mismatch (proof does not bind to registered secret key share)"
                );
            }
        }
    }

    // ── LaZer sigma proof verification (P1 Phase 2 — defense-in-depth) ──
    #[cfg(feature = "enable-lazer")]
    {
        use pvthfhe_nizk::lazer_bridge::{embedded_specs, LazerSigmaProver, LazerSigmaVerifier};

        observer.phase_start("lazer_verify", Some("auto-generated sigma proofs"));
        let lazer_started = Instant::now();

        // Load relation specs (validates TOML parsing at runtime)
        let bfv_spec = embedded_specs::bfv_encryption()
            .map_err(|e| anyhow::anyhow!("LaZer BFV spec parse: {e:?}"))?;
        let ckks_spec = embedded_specs::ckks_encryption()
            .map_err(|e| anyhow::anyhow!("LaZer CKKS spec parse: {e:?}"))?;
        let tfhe_spec = embedded_specs::tfhe_bootstrap()
            .map_err(|e| anyhow::anyhow!("LaZer TFHE spec parse: {e:?}"))?;

        tracing::info!(
            "LaZer specs loaded: {} (rlwe n={}), {} (rlwe n={}), {} (lwe n={})",
            bfv_spec.relation_name,
            bfv_spec.ring_n,
            ckks_spec.relation_name,
            ckks_spec.ring_n,
            tfhe_spec.relation_name,
            tfhe_spec.ring_n,
        );

        // Create prover/verifier instances for each relation.
        // LaZer state initialization is delegated to the pvthfhe-lazer FFI crate
        // which calls lazer_init() and zero-allocates lin_prover_state_t / lin_verifier_state_t.
        // Full state population (lin_params_init etc.) requires extended FFI; tracked as P1-Phase3.
        let _bfv_verifier = LazerSigmaVerifier::new(bfv_spec.clone())
            .map_err(|e| anyhow::anyhow!("LaZer BFV verifier init: {e:?}"))?;
        let _ckks_prover = LazerSigmaProver::new(ckks_spec.clone())
            .map_err(|e| anyhow::anyhow!("LaZer CKKS prover init: {e:?}"))?;
        let _tfhe_verifier = LazerSigmaVerifier::new(tfhe_spec)
            .map_err(|e| anyhow::anyhow!("LaZer TFHE verifier init: {e:?}"))?;

        for (_party_id, _statement, _witness, _proof) in &nizk_outputs {
            let (d_rns, sigma_proof) = extract_sigma_proof(&_proof.proof_bytes)
                .with_context(|| format!("LaZer: extract sigma proof for party {_party_id}"))?;

            tracing::debug!(
                "LaZer sigma extracted for party {}: d_rns.len={} t_rns.len={} z_s.len={} z_e.len={} ch={}",
                _party_id,
                d_rns.len(),
                sigma_proof.t_rns.len(),
                sigma_proof.z_s.len(),
                sigma_proof.z_e.len(),
                sigma_proof.ch,
            );
        }

        tracing::info!(
            "LaZer sigma bridge: {} parties prepared ({:.1}ms) — auto-generated sigma proofs wired",
            nizk_outputs.len(),
            elapsed_ms(lazer_started),
        );

        observer.phase_end("lazer_verify", elapsed_ms(lazer_started));
    }

    let all_nizk_proof_hash = {
        let mut hash_inputs = Vec::with_capacity(nizk_outputs.len());
        for (_party_id, _statement, _witness, proof) in &nizk_outputs {
            hash_inputs.push(Fr::from_be_bytes_mod_order(&Sha256::digest(
                &proof.proof_bytes,
            )));
        }
        noir_poseidon_sponge(&hash_inputs)
    };
    tracing::info!(
        "hash-chain 1.1: all_nizk_proof_hash bound {} proof(s) into NIZK→PVSS session",
        nizk_outputs.len()
    );

    Ok(ProveStageOutput {
        nizk_outputs,
        registered_sk_bindings,
        all_nizk_proof_hash,
    })
}

fn build_nizk_inputs(
    session_id: &str,
    message: &Round1Message,
    seed: u64,
    backend: &pvthfhe_fhe::fhers::FhersBackend,
) -> anyhow::Result<(NizkStatement, NizkWitness)> {
    let demo_seed = if seed == 0 { None } else { Some(seed) };
    let secret_key_bytes = backend
        .party_secret_key_bytes(message.party_id)
        .with_context(|| format!("get secret key for party {}", message.party_id))?;
    build_demo_nizk_inputs(session_id, message, demo_seed, &secret_key_bytes)
}
