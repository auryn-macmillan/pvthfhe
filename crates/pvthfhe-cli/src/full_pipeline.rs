//! Shared full-pipeline driver for bench and demo entrypoints.

use anyhow::Context;
use pvthfhe_aggregator::{
    folding::{CcsPShareInstance, CycloFoldingAdapter},
    keygen::{simulator::{KeygenResult, KeygenSimulator}, types::Round1Message},
};
use pvthfhe_bench::e2e_timings::E2eTimings;
use pvthfhe_fhe::{
    fhers::FhersBackend,
    real_nizk::{LatticeNizk, NizkStatement, NizkWitness, RealNizkAdapter},
    FheBackend, PublicKey,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use std::time::Instant;

use crate::{
    compressor_glue::Compressor,
    demo_nizk::build_demo_nizk_inputs,
    pvss_support::{run_lattice_pvss, PVSS_BACKEND_ID},
};

const DEMO_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 131072\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

/// Full pipeline configuration.
#[derive(Debug, Clone, Copy)]
pub struct PipelineConfig {
    /// Number of parties.
    pub n: usize,
    /// Threshold.
    pub t: usize,
    /// Deterministic seed.
    pub seed: u64,
}

/// Full pipeline execution report.
#[derive(Debug, Clone)]
pub struct PipelineReport {
    /// Collected phase timings.
    pub timings: E2eTimings,
    /// Whether aggregate decrypt matched the original plaintext.
    pub plaintext_roundtrip_ok: bool,
    /// Aggregate public key hash.
    pub aggregate_pk_hash_hex: String,
    /// Ciphertext hash.
    pub ciphertext_hash_hex: String,
    /// Compressed proof digest.
    pub compressed_proof_digest_hex: String,
}

/// Observer hooks for pipeline narration and metrics.
pub trait PipelineObserver {
    /// Called before a phase begins.
    fn phase_start(&mut self, _name: &str, _detail: Option<&str>) {}

    /// Called after a phase completes.
    fn phase_end(&mut self, _name: &str, _ms: f64) {}

    /// Called for extra notes.
    fn note(&mut self, _msg: &str) {}
}

/// Run the complete wired PVTHFHE pipeline.
pub fn run_full_pipeline<O: PipelineObserver>(
    cfg: &PipelineConfig,
    observer: &mut O,
) -> anyhow::Result<PipelineReport> {
    if cfg.t == 0 || cfg.t > cfg.n {
        anyhow::bail!(
            "invalid threshold: t={} must satisfy 1 <= t <= n={}",
            cfg.t,
            cfg.n
        );
    }

    let backend_threshold = cfg.t.min((cfg.n + 1) / 2);
    let backend = FhersBackend::load_params(DEMO_PARAMS_TOML).context("backend init")?;
    let mut timings = E2eTimings::new(cfg.n, cfg.t, cfg.seed, crate::compressor_glue::compressor_backend_id());

    observer.note(&format!("pvss_backend_id={PVSS_BACKEND_ID}"));

    observer.phase_start("keygen", Some(&format!("n={} t={} seed={}", cfg.n, cfg.t, cfg.seed)));
    let mut simulator = KeygenSimulator::new(cfg.n, backend_threshold, backend.clone());
    let keygen_started = Instant::now();
    let transcript = match simulator.run().context("keygen")? {
        KeygenResult::Complete(transcript) => transcript,
        KeygenResult::Blamed(blamed) => anyhow::bail!("keygen blamed: {blamed:?}"),
    };
    let keygen_ms = elapsed_ms(keygen_started);
    observer.phase_end("keygen", keygen_ms);
    timings.phases.keygen.total_ms = keygen_ms;
    timings.phases.keygen.instances_run = 1;

    let session_id = keygen_session_id(&transcript.round3_aggregate.aggregate_pk, cfg.t, cfg.seed);
    let mut proofs = Vec::with_capacity(transcript.round1_messages.len());
    let mut nizk_prove_per_instance_ms = Vec::with_capacity(transcript.round1_messages.len());
    for message in &transcript.round1_messages {
        let (statement, witness) = build_nizk_inputs(&session_id, message)?;
        let mut rng = StdRng::seed_from_u64(cfg.seed ^ (u64::from(message.party_id) << 32) ^ 0xE2E0_1001);
        observer.phase_start("nizk_prove", Some(&format!("dealer={}", message.party_id)));
        let started = Instant::now();
        let proof = RealNizkAdapter::prove(&statement, &witness, &mut rng)
            .with_context(|| format!("nizk prove dealer {}", message.party_id))?;
        let ms = elapsed_ms(started);
        observer.phase_end("nizk_prove", ms);
        nizk_prove_per_instance_ms.push(ms);
        proofs.push((message.party_id, statement, proof));
    }
    timings.phases.nizk_prove.total_ms = nizk_prove_per_instance_ms.iter().sum();
    timings.phases.nizk_prove.instances_run = nizk_prove_per_instance_ms.len();
    timings.phases.nizk_prove.per_instance_ms = nizk_prove_per_instance_ms;

    let mut nizk_verify_total_ms = 0.0;
    let mut nizk_verify_per_instance_ms = Vec::new();
    for (dealer_id, statement, proof) in &proofs {
        for recipient_id in &transcript.participant_set {
            if recipient_id == dealer_id {
                continue;
            }
            observer.phase_start(
                "nizk_verify",
                Some(&format!("dealer={} recipient={}", dealer_id, recipient_id)),
            );
            let started = Instant::now();
            RealNizkAdapter::verify(statement, proof).with_context(|| {
                format!("nizk verify dealer {} recipient {}", dealer_id, recipient_id)
            })?;
            let ms = elapsed_ms(started);
            observer.phase_end("nizk_verify", ms);
            nizk_verify_total_ms += ms;
            nizk_verify_per_instance_ms.push(ms);
        }
    }
    timings.phases.nizk_verify.total_ms = nizk_verify_total_ms;
    timings.phases.nizk_verify.instances_run = nizk_verify_per_instance_ms.len();
    timings.phases.nizk_verify.per_instance_ms = nizk_verify_per_instance_ms;

    observer.phase_start("pvss_share_encrypt", Some(PVSS_BACKEND_ID));
    let pvss_started = Instant::now();
    let pvss = run_lattice_pvss(&backend, &transcript, cfg.t, "pvthfhe-e2e/pvss", cfg.seed)?;
    observer.phase_end("pvss_share_encrypt", elapsed_ms(pvss_started));
    timings.phases.pvss_share_encrypt.deal_ms = pvss.deal_ms as f64;
    timings.phases.pvss_share_encrypt.verify_ms = pvss.verify_ms as f64;
    timings.phases.pvss_share_encrypt.recover_ms = pvss.recover_ms as f64;
    timings.phases.pvss_share_encrypt.total_ms = pvss.share_encryption_proof_ms as f64;
    timings.phases.pvss_share_encrypt.instances_run = cfg.n * (cfg.n - 1);
    timings.phases.pvss_decrypt_prove.total_ms = pvss.decrypt_prove_total_ms;
    timings.phases.pvss_decrypt_prove.instances_run = pvss.decrypt_prove_per_instance_ms.len();
    timings.phases.pvss_decrypt_prove.per_instance_ms = pvss.decrypt_prove_per_instance_ms;
    observer.note(&format!("share_encryption_proof_ms={}", pvss.share_encryption_proof_ms));

    observer.phase_start("setup_threshold", Some(&format!("backend_threshold={backend_threshold}")));
    let setup_started = Instant::now();
    backend
        .setup_threshold(cfg.n, backend_threshold)
        .context("setup_threshold")?;
    observer.phase_end("setup_threshold", elapsed_ms(setup_started));

    let aggregate_pk = transcript.round3_aggregate.aggregate_pk.clone();
    observer.phase_start("aggregate_keygen", None);
    let aggregate_keygen_started = Instant::now();
    let aggregate_keygen_shares = transcript
        .round1_messages
        .iter()
        .map(|message| pvthfhe_fhe::KeygenShare {
            party_id: message.party_id,
            bytes: message.pk_i.bytes.clone(),
        })
        .collect::<Vec<_>>();
    let _aggregate_key = backend
        .aggregate_keygen(&aggregate_keygen_shares)
        .context("aggregate_keygen")?;
    observer.phase_end("aggregate_keygen", elapsed_ms(aggregate_keygen_started));

    let plaintext = cfg.seed.to_le_bytes();
    let mut encrypt_rng = StdRng::seed_from_u64(cfg.seed ^ 0xA11C_E001);
    observer.phase_start("encrypt", None);
    let encrypt_started = Instant::now();
    let ciphertext = backend
        .encrypt(&aggregate_pk, &plaintext, &mut encrypt_rng)
        .context("encrypt")?;
    observer.phase_end("encrypt", elapsed_ms(encrypt_started));
    let ct_hash = sha256_bytes(&ciphertext.bytes);
    let aggregate_pk_hash_hex = hex::encode(sha256_bytes(&aggregate_pk.bytes));
    let ciphertext_hash_hex = hex::encode(ct_hash);

    let fold_instances = build_fold_instances(&transcript.participant_set, ct_hash, cfg.seed)?;
    let mut fold_rng = StdRng::seed_from_u64(cfg.seed ^ 0xC7C1_0000_0000_0000);
    let folding = CycloFoldingAdapter::new();
    observer.phase_start("cyclo_fold", Some(folding.backend_id()));
    let cyclo_fold_started = Instant::now();
    let fold_report = folding
        .fold_all(&fold_instances, "pvthfhe-e2e", &mut fold_rng)
        .context("cyclo_fold")?;
    let cyclo_fold_ms = elapsed_ms(cyclo_fold_started);
    observer.phase_end("cyclo_fold", cyclo_fold_ms);
    timings.phases.cyclo_fold.total_ms = cyclo_fold_ms;
    timings.phases.cyclo_fold.instances_run = 1;

    observer.phase_start("cyclo_fold_verify", None);
    let cyclo_verify_started = Instant::now();
    folding
        .verify_fold_all(&fold_report, &fold_instances)
        .context("cyclo_fold verify")?;
    observer.phase_end("cyclo_fold_verify", elapsed_ms(cyclo_verify_started));

    observer.phase_start("compressor_new", None);
    let compressor_new_started = Instant::now();
    let compressor = Compressor::new(cfg.seed)?;
    observer.phase_end("compressor_new", elapsed_ms(compressor_new_started));

    observer.phase_start("compressor_prove", Some(compressor.backend_id()));
    let compressor_prove_started = Instant::now();
    let compressed = compressor.prove(&fold_report).context("compressor_prove")?;
    let compressor_prove_ms = elapsed_ms(compressor_prove_started);
    observer.phase_end("compressor_prove", compressor_prove_ms);
    timings.phases.compressor_prove.total_ms = compressor_prove_ms;
    timings.phases.compressor_prove.instances_run = 1;

    observer.phase_start("compressor_verify", Some(compressor.backend_id()));
    let compressor_verify_started = Instant::now();
    compressor
        .verify(&fold_report, &compressed)
        .context("compressor_verify")?;
    let compressor_verify_ms = elapsed_ms(compressor_verify_started);
    observer.phase_end("compressor_verify", compressor_verify_ms);
    timings.phases.compressor_verify.total_ms = compressor_verify_ms;
    timings.phases.compressor_verify.instances_run = 1;

    let mut shares = Vec::with_capacity(cfg.t);
    let mut partial_decrypt_ms = Vec::with_capacity(cfg.t);
    for party_index in 1..=cfg.t {
        let party_id = u32::try_from(party_index).context("party id conversion")?;
        let mut rng = StdRng::seed_from_u64(cfg.seed ^ u64::from(party_id));
        observer.phase_start("partial_decrypt", Some(&format!("party_id={party_id}")));
        let started = Instant::now();
        let share = backend
            .partial_decrypt(&ciphertext, party_id, &mut rng)
            .with_context(|| format!("partial_decrypt party {party_id}"))?;
        let ms = elapsed_ms(started);
        observer.phase_end("partial_decrypt", ms);
        partial_decrypt_ms.push(ms);
        shares.push(share);
    }
    timings.phases.partial_decrypt.total_ms = partial_decrypt_ms.iter().sum();
    timings.phases.partial_decrypt.instances_run = partial_decrypt_ms.len();
    timings.phases.partial_decrypt.per_instance_ms = partial_decrypt_ms;

    observer.phase_start("aggregate_decrypt", None);
    let aggregate_decrypt_started = Instant::now();
    let aggregate_plaintext = backend
        .aggregate_decrypt(&ciphertext, &shares, backend_threshold)
        .context("aggregate_decrypt")?;
    let aggregate_decrypt_ms = elapsed_ms(aggregate_decrypt_started);
    observer.phase_end("aggregate_decrypt", aggregate_decrypt_ms);
    timings.phases.aggregate_decrypt.total_ms = aggregate_decrypt_ms;
    timings.phases.aggregate_decrypt.instances_run = 1;

    let plaintext_roundtrip_ok = aggregate_plaintext == plaintext;
    if !plaintext_roundtrip_ok {
        anyhow::bail!("aggregate_decrypt did not round-trip plaintext");
    }

    Ok(PipelineReport {
        timings,
        plaintext_roundtrip_ok,
        aggregate_pk_hash_hex,
        ciphertext_hash_hex,
        compressed_proof_digest_hex: hex::encode(compressed.digest),
    })
}

fn build_nizk_inputs(
    session_id: &str,
    message: &Round1Message,
) -> anyhow::Result<(NizkStatement, NizkWitness)> {
    build_demo_nizk_inputs(session_id, message)
}

fn keygen_session_id(aggregate_pk: &PublicKey, threshold: usize, seed: u64) -> String {
    let mut binding = Vec::new();
    binding.extend_from_slice(b"pvthfhe-e2e/keygen_nizk/v1");
    binding.extend_from_slice(&seed.to_be_bytes());
    binding.extend_from_slice(&threshold.to_be_bytes());
    binding.extend_from_slice(&sha256_bytes(&aggregate_pk.bytes));
    format!("pvthfhe-e2e-{}", hex::encode(sha256_bytes(&binding)))
}

fn build_fold_instances(
    participants: &[u32],
    ct_hash: [u8; 32],
    seed: u64,
) -> anyhow::Result<Vec<CcsPShareInstance>> {
    participants
        .iter()
        .map(|&party_id| {
            let participant_id = u16::try_from(party_id).context("participant id conversion")?;
            let mut binding_hasher = Sha256::new();
            binding_hasher.update(ct_hash);
            binding_hasher.update(seed.to_le_bytes());
            binding_hasher.update(party_id.to_le_bytes());
            let binding: [u8; 32] = binding_hasher.finalize().into();
            Ok(CcsPShareInstance {
                participant_id,
                ajtai_commitment_bytes: ct_hash.to_vec(),
                public_io_bytes: vec![participant_id as u8; 32],
                ccs_witness_bytes: vec![1u8; 32],
                sha256_binding_bytes: binding.to_vec(),
            })
        })
        .collect()
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct RecordingObserver {
        starts: Vec<String>,
        ends: Vec<(String, f64)>,
        notes: Vec<String>,
    }

    impl PipelineObserver for RecordingObserver {
        fn phase_start(&mut self, name: &str, detail: Option<&str>) {
            match detail {
                Some(detail) => self.starts.push(format!("{name}:{detail}")),
                None => self.starts.push(name.to_owned()),
            }
        }

        fn phase_end(&mut self, name: &str, ms: f64) {
            self.ends.push((name.to_owned(), ms));
        }

        fn note(&mut self, msg: &str) {
            self.notes.push(msg.to_owned());
        }
    }

    #[test]
    fn red_3_records_all_full_pipeline_phases() {
        let mut observer = RecordingObserver::default();
        let report = run_full_pipeline(
            &PipelineConfig { n: 3, t: 2, seed: 1 },
            &mut observer,
        )
        .expect("full pipeline should succeed");

        let mut counts = BTreeMap::new();
        for entry in &observer.starts {
            let name = entry.split(':').next().expect("phase entry has name");
            *counts.entry(name.to_owned()).or_insert(0usize) += 1;
        }

        assert_eq!(counts.get("keygen").copied(), Some(1));
        assert_eq!(counts.get("nizk_prove").copied(), Some(3));
        assert_eq!(counts.get("nizk_verify").copied(), Some(6));
        assert_eq!(counts.get("pvss_share_encrypt").copied(), Some(1));
        assert_eq!(counts.get("setup_threshold").copied(), Some(1));
        assert_eq!(counts.get("aggregate_keygen").copied(), Some(1));
        assert_eq!(counts.get("encrypt").copied(), Some(1));
        assert_eq!(counts.get("cyclo_fold").copied(), Some(1));
        assert_eq!(counts.get("cyclo_fold_verify").copied(), Some(1));
        assert_eq!(counts.get("compressor_new").copied(), Some(1));
        assert_eq!(counts.get("compressor_prove").copied(), Some(1));
        assert_eq!(counts.get("compressor_verify").copied(), Some(1));
        assert_eq!(counts.get("partial_decrypt").copied(), Some(2));
        assert_eq!(counts.get("aggregate_decrypt").copied(), Some(1));
        assert!(report.plaintext_roundtrip_ok);
        assert!(report.timings.phases.cyclo_fold.total_ms > 0.0);
        assert!(report.timings.phases.compressor_prove.total_ms > 0.0);
    }
}
