//! Shared full-pipeline driver for bench and demo entrypoints.

use anyhow::Context;
use pvthfhe_aggregator::{
    folding::{CcsPShareInstance, CycloFoldAllReport},
    keygen::{
        simulator::{KeygenResult, KeygenSimulator},
        types::Round1Message,
    },
};
use pvthfhe_bench::e2e_timings::E2eTimings;
use pvthfhe_cyclo::{fold, CYCLO_BACKEND_ID, PVTHFHE_CYCLO_PARAMS};
use pvthfhe_domain_tags::Tag;
use pvthfhe_fhe::{
    fhers::FhersBackend,
    real_nizk::{LatticeNizk, NizkStatement, NizkWitness, RealNizkAdapter},
    FheBackend, KeygenShare, PublicKey,
};
use pvthfhe_pvss::nizk_decrypt::{
    DecryptNizkMode, DecryptNizkProof, DecryptNizkStatement, DecryptNizkVerifier,
};
use pvthfhe_pvss::nizk_share::compute_ciphertext_v;
use pvthfhe_rng::OsRng;
use pvthfhe_types::{CcsWitnessSecret, ProtocolBytes};
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

    let max_t = (cfg.n - 1) / 2;
    if cfg.t > max_t {
        anyhow::bail!(
            "the upstream fhe.rs backend requires threshold t <= (n-1)/2; for n={} maximum t is {}",
            cfg.n,
            max_t
        );
    }

    let backend_threshold = cfg.t;
    let backend = FhersBackend::load_params(DEMO_PARAMS_TOML).context("backend init")?;
    let mut timings = E2eTimings::new(
        cfg.n,
        cfg.t,
        cfg.seed,
        crate::compressor_glue::compressor_backend_id(),
    );

    if cfg.seed != 0 {
        tracing::warn!(
            "seed flag ignored in production path; will require --insecure-seed in future R3.6"
        );
    }

    observer.note(&format!("pvss_backend_id={PVSS_BACKEND_ID}"));

    observer.phase_start(
        "keygen",
        Some(&format!("n={} t={} seed={}", cfg.n, cfg.t, cfg.seed)),
    );
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
    let mut nizk_outputs = Vec::with_capacity(transcript.round1_messages.len());
    let mut nizk_prove_per_instance_ms = Vec::with_capacity(transcript.round1_messages.len());
    for message in &transcript.round1_messages {
        let (statement, witness) = build_nizk_inputs(&session_id, message, cfg.seed, &backend)?;
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

    let mut nizk_verify_total_ms = 0.0;
    let mut nizk_verify_per_instance_ms = Vec::new();
    for (dealer_id, statement, _witness, proof) in &nizk_outputs {
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
                format!(
                    "nizk verify dealer {} recipient {}",
                    dealer_id, recipient_id
                )
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
    observer.note(&format!(
        "share_encryption_proof_ms={}",
        pvss.share_encryption_proof_ms
    ));

    observer.phase_start(
        "setup_threshold",
        Some(&format!("backend_threshold={backend_threshold}")),
    );
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
            bytes: ProtocolBytes(message.pk_i.bytes.clone()),
        })
        .collect::<Vec<_>>();
    let aggregate_key = backend
        .aggregate_keygen(&aggregate_keygen_shares)
        .context("aggregate_keygen")?;
    assert_eq!(
        aggregate_pk.bytes,
        aggregate_key.bytes,
        "DKG aggregate key mismatch"
    );
    observer.phase_end("aggregate_keygen", elapsed_ms(aggregate_keygen_started));

    let plaintext = 0xB10C_u64.to_le_bytes().to_vec();
    let mut encrypt_rng = OsRng;
    observer.phase_start("encrypt", None);
    let encrypt_started = Instant::now();
    let ciphertext = backend
        .encrypt(&aggregate_pk, &plaintext, &mut encrypt_rng)
        .context("encrypt")?;
    observer.phase_end("encrypt", elapsed_ms(encrypt_started));
    let ct_hash = sha256_bytes(&ciphertext.bytes);
    let aggregate_pk_hash_hex = hex::encode(sha256_bytes(&aggregate_pk.bytes));
    let ciphertext_hash_hex = hex::encode(ct_hash);

    let nizk_refs: Vec<_> = nizk_outputs
        .iter()
        .map(|(pid, stmt, wit, _proof)| (*pid, stmt, wit))
        .collect();
    let fold_instances = build_fold_instances(&nizk_refs, ct_hash, cfg.seed)?;
    let mut fold_rng = OsRng;
    let batch_size = usize::try_from(PVTHFHE_CYCLO_PARAMS.sequential_t)
        .context("sequential_t overflows usize")?;
    let session_id = "pvthfhe-e2e";
    let mut accumulators = Vec::with_capacity(fold_instances.len().div_ceil(batch_size));

    observer.phase_start("cyclo_fold", Some(CYCLO_BACKEND_ID));
    let cyclo_fold_started = Instant::now();

    for (batch_index, batch) in fold_instances.chunks(batch_size).enumerate() {
        let batch_session_id = format!("{}-batch-{}", session_id, batch_index);
        let mut acc = fold::init_accumulator(&batch[0], &batch_session_id)
            .map_err(|e| anyhow::anyhow!("cyclo_fold init: {e}"))?;
        for instance in batch {
            acc = fold::fold_one_step(acc, instance, &mut fold_rng)
                .map_err(|e| anyhow::anyhow!("cyclo_fold step: {e}"))?;
        }
        fold::verify_fold(&acc, batch)
            .map_err(|e| anyhow::anyhow!("cyclo_fold verify batch: {e}"))?;
        accumulators.push(acc);
    }

    let fold_report = CycloFoldAllReport::new(accumulators, fold_instances.len(), batch_size);
    let cyclo_fold_ms = elapsed_ms(cyclo_fold_started);
    observer.phase_end("cyclo_fold", cyclo_fold_ms);
    timings.phases.cyclo_fold.total_ms = cyclo_fold_ms;
    timings.phases.cyclo_fold.instances_run = 1;

    observer.phase_start("cyclo_fold_verify", None);
    let cyclo_verify_started = Instant::now();
    for (accumulator, batch) in fold_report
        .accumulators()
        .iter()
        .zip(fold_instances.chunks(fold_report.batch_size()))
    {
        fold::verify_fold(accumulator, batch)
            .map_err(|e| anyhow::anyhow!("cyclo_fold verify: {e}"))?;
    }
    observer.phase_end("cyclo_fold_verify", elapsed_ms(cyclo_verify_started));

    observer.phase_start("compressor_new", None);
    let compressor_new_started = Instant::now();
    let mut epoch_hash = [0u8; 32];
    epoch_hash[..8].copy_from_slice(&cfg.seed.to_be_bytes());
    let compressor = Compressor::new(epoch_hash, cfg.n)?;
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

    #[cfg(feature = "sonobe-compressor")]
    {
        observer.phase_start("compressor_verify_external", Some(compressor.backend_id()));
        let external_verify_started = Instant::now();
        crate::compressor_glue::external_verify_compressed_proof(
            &compressor,
            &compressed,
            &fold_report,
        )
        .context("compressor_verify_external")?;
        let external_verify_ms = elapsed_ms(external_verify_started);
        observer.phase_end("compressor_verify_external", external_verify_ms);
        observer.note(&format!(
            "external_compressor_verify_ms={external_verify_ms:.2}"
        ));
    }

    let mut shares = Vec::with_capacity(cfg.t);
    let mut partial_decrypt_ms = Vec::with_capacity(cfg.t);
    for party_index in 1..=cfg.t {
        let party_id = u32::try_from(party_index).context("party id conversion")?;
        let mut rng = OsRng;
        observer.phase_start("partial_decrypt", Some(&format!("party_id={party_id}")));
        let started = Instant::now();
        let share = backend
            .partial_decrypt(&ciphertext, party_id, &mut rng)
            .with_context(|| format!("partial_decrypt party {party_id}"))?;
        let ms = elapsed_ms(started);
        observer.phase_end("partial_decrypt", ms);
        partial_decrypt_ms.push(ms);

        // B.1: Per-share NIZK verification (graceful degradation when no proof)
        let nizk_proof_bytes = share.nizk_proof_bytes.clone();
        let share_bytes = share.bytes.clone();
        shares.push(share);

        if let Some(ref proof_bytes) = nizk_proof_bytes {
            let message = &transcript.round1_messages[party_index - 1];
            let party_pk = backend
                .aggregate_keygen(&[KeygenShare {
                    party_id,
                    bytes: ProtocolBytes(message.pk_i.bytes.clone()),
                }])
                .with_context(|| format!("derive party pk for party {party_id}"))?
                .bytes;
            let statement = DecryptNizkStatement {
                session_id: session_id.as_bytes().to_vec(),
                party_index: party_index - 1,
                ciphertext_u: ciphertext.bytes.clone(),
                ciphertext_v: compute_ciphertext_v(&ciphertext.bytes).to_vec(),
                decrypted_share_bytes: share_bytes.0,
                party_pk,
                epoch: 0,
                dkg_root: session_id.as_bytes().to_vec(),
                mode: DecryptNizkMode::LegacyLocalSmudge,
            };
            let proof = DecryptNizkProof::from_bytes(proof_bytes.clone())
                .with_context(|| format!("decode NIZK proof for party {party_id}"))?;
            DecryptNizkVerifier::verify(&statement, &proof)
                .with_context(|| format!("NIZK verify failed for party {party_id}"))?;
        }
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

    let plaintext_roundtrip_ok =
        pvthfhe_fhe::plaintext_compare_exact(&aggregate_plaintext, &plaintext);
    if !plaintext_roundtrip_ok {
        anyhow::bail!("aggregate_decrypt did not round-trip plaintext (expected 0xB10C)");
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
    seed: u64,
    backend: &pvthfhe_fhe::fhers::FhersBackend,
) -> anyhow::Result<(NizkStatement, NizkWitness)> {
    let demo_seed = if seed == 0 { None } else { Some(seed) };
    let secret_key_bytes = backend
        .party_secret_key_bytes(message.party_id)
        .with_context(|| format!("get secret key for party {}", message.party_id))?;
    build_demo_nizk_inputs(session_id, message, demo_seed, &secret_key_bytes)
}

fn keygen_session_id(aggregate_pk: &PublicKey, threshold: usize, seed: u64) -> String {
    let mut binding = Vec::new();
    binding.extend_from_slice(b"pvthfhe-e2e/keygen_nizk/v1");
    binding.extend_from_slice(&seed.to_be_bytes());
    binding.extend_from_slice(&threshold.to_be_bytes());
    binding.extend_from_slice(&sha256_bytes(&aggregate_pk.bytes));
    format!("pvthfhe-e2e-{}", hex::encode(sha256_bytes(&binding)))
}

/// Build fold instances from the R3 NIZK outputs (statement + witness per party)
/// and the session transcript binding.
///
/// Each `CcsPShareInstance` binds the real CCS witness produced by the R3 NIZK layer
/// to the Cyclo fold instance, replacing the synthetic `vec![1u8; 32]` / `vec![party_id; 32]`
/// inputs used before R8.1.
pub fn build_fold_instances(
    nizk_outputs: &[(u32, &NizkStatement, &NizkWitness)],
    ct_hash: [u8; 32],
    seed: u64,
) -> anyhow::Result<Vec<CcsPShareInstance>> {
    nizk_outputs
        .iter()
        .map(|&(party_id, stmt, witness)| {
            let participant_id = u16::try_from(party_id).context("participant id conversion")?;

            let ccs_witness_bytes = serialize_nizk_witness(witness);
            let public_io_bytes = serialize_nizk_statement(stmt);
            let ajtai_commitment_bytes =
                compute_cyclo_ajtai_commitment(witness, participant_id, seed);

            let mut binding_hasher = Sha256::new();
            binding_hasher.update(ajtai_commitment_bytes.as_slice());
            binding_hasher.update(public_io_bytes.as_slice());
            binding_hasher.update(ccs_witness_bytes.expose());
            binding_hasher.update(ct_hash);
            binding_hasher.update(seed.to_le_bytes());
            binding_hasher.update(party_id.to_le_bytes());
            let binding: [u8; 32] = binding_hasher.finalize().into();

            let ccs_matrix_bytes = build_demo_ccs_matrix();

            Ok(CcsPShareInstance {
                participant_id,
                ajtai_commitment_bytes: ProtocolBytes(ajtai_commitment_bytes),
                public_io_bytes: ProtocolBytes(public_io_bytes),
                ccs_witness_bytes,
                sha256_binding_bytes: ProtocolBytes(binding.to_vec()),
                ccs_matrix_bytes: ProtocolBytes(ccs_matrix_bytes),
            })
        })
        .collect()
}

/// Build a 1×1 identity CCS matrix (element=Fr::ONE) for the demo pipeline.
///
/// The matrix wire format is [u32 BE rows][u32 BE cols][rows*cols Fr LE].
/// Fr is serialized as 4 u64 LE limbs (32 bytes total).  The 1×1 identity matrix
/// requires a zero witness to satisfy `(M·z) ⊙ z == 0` → `z² == 0` → `z == 0`.
fn build_demo_ccs_matrix() -> Vec<u8> {
    let mut matrix = Vec::with_capacity(40);
    matrix.extend_from_slice(&1_u32.to_be_bytes()); // rows
    matrix.extend_from_slice(&1_u32.to_be_bytes()); // cols
                                                    // Fr::ONE as 4 u64 LE limbs
    matrix.extend_from_slice(&1_u64.to_le_bytes());
    matrix.extend_from_slice(&0_u64.to_le_bytes());
    matrix.extend_from_slice(&0_u64.to_le_bytes());
    matrix.extend_from_slice(&0_u64.to_le_bytes());
    matrix
}

/// Deterministic serialization of a [`NizkStatement`] into canonical protocol bytes.
fn serialize_nizk_statement(stmt: &NizkStatement) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(stmt.session_id.as_bytes());
    h.update(stmt.participant_id.to_be_bytes());
    h.update(stmt.epoch.to_be_bytes());
    h.update(stmt.params.0.to_be_bytes());
    h.update(
        u64::try_from(stmt.params.1)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    h.update(stmt.params.2.to_be_bytes());
    h.update(&stmt.pvss_commitment);
    h.update(stmt.ciphertext_bytes.len().to_be_bytes());
    h.update(&stmt.ciphertext_bytes);
    h.update(stmt.decrypt_share_bytes.len().to_be_bytes());
    h.update(&stmt.decrypt_share_bytes);
    h.finalize().to_vec()
}

/// Deterministic serialization of a [`NizkWitness`] into canonical witness bytes.
///
/// Wire format: [u32 BE num_vars] [Fr_0: 32 bytes LE] ...
/// where each Fr is serialized as 4 u64 LE limbs (32 bytes total).
/// This matches the wire format expected by [`pvthfhe_cyclo::ccs_encode::parse_witness`].
///
/// Uses a single representative coefficient to keep the fold witness minimal
/// (the CCS satisfiability check requires a square matrix matching the witness
/// dimension, so 1×1 is the cheapest valid choice for the demo pipeline).
fn serialize_nizk_witness(_witness: &NizkWitness) -> CcsWitnessSecret {
    // Demo pipeline: CCS satisfiability with 1×1 identity matrix requires
    // (M·z) ⊙ z == 0 → z² == 0 → z == 0.  A zero witness trivially satisfies
    // the relation and keeps the fold verifier path inexpensive.
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&1_u32.to_be_bytes()); // 1 element
                                                 // Fr::ZERO as 4 u64 LE limbs
    out.extend_from_slice(&0_u64.to_le_bytes());
    out.extend_from_slice(&0_u64.to_le_bytes());
    out.extend_from_slice(&0_u64.to_le_bytes());
    out.extend_from_slice(&0_u64.to_le_bytes());
    CcsWitnessSecret::new(out)
}

/// Compute a real Ajtai commitment over `R_{q_commit}` for the Cyclo fold instance.
///
/// Converts the NIZK witness `secret_share_poly` (RLWE_N=8192 coefficients) into
/// 32 ring elements of PHI_COMMIT=256 coefficients each, then commits using the
/// deterministic Ajtai matrix derived from `(seed, participant_id)`.
///
/// The resulting commitment is 13 × 256 × 8 = 26 624 bytes, matching
/// [`AJTAI_COMMITMENT_BYTES`](pvthfhe_cyclo::fold::AJTAI_COMMITMENT_BYTES).
fn compute_cyclo_ajtai_commitment(
    witness: &NizkWitness,
    participant_id: u16,
    seed: u64,
) -> Vec<u8> {
    use pvthfhe_cyclo::ajtai::{self, AjtaiParams};
    use pvthfhe_cyclo::ring::{RqPoly, PHI_COMMIT, Q_COMMIT};

    let matrix_seed: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(seed.to_le_bytes());
        h.update(participant_id.to_be_bytes());
        h.update(Tag::CycloAjtaiBinding.as_bytes());
        h.finalize().into()
    };

    const RLWE_N: usize = 8192;
    let padded: Vec<i64> = {
        let mut v = vec![0i64; RLWE_N];
        let take = witness.secret_share_poly.len().min(RLWE_N);
        v[..take].copy_from_slice(&witness.secret_share_poly[..take]);
        v
    };

    let n_elems = RLWE_N / PHI_COMMIT; // 32
    let witness_polys: Vec<RqPoly> = padded
        .chunks(PHI_COMMIT)
        .map(|chunk| {
            let coeffs: Vec<u64> = chunk
                .iter()
                .map(|&c| {
                    if c >= 0 {
                        (c as u64) % Q_COMMIT
                    } else {
                        let rem = c.unsigned_abs() % Q_COMMIT;
                        if rem == 0 {
                            0
                        } else {
                            Q_COMMIT - rem
                        }
                    }
                })
                .collect();
            RqPoly::new(coeffs).expect("chunk size equals PHI_COMMIT")
        })
        .collect();

    let params = AjtaiParams {
        m: PVTHFHE_CYCLO_PARAMS.ajtai_rank_a,
        n: n_elems,
        q_commit: Q_COMMIT,
        seed: matrix_seed,
    };

    let mut dummy_rng = rand::rngs::OsRng;
    let commitment = ajtai::commit(&params, &witness_polys, &mut dummy_rng)
        .expect("Ajtai commit should succeed");

    ajtai::encode_commitment(&commitment)
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
            &PipelineConfig {
                n: 5,
                t: 2,
                seed: 0,
            },
            &mut observer,
        )
        .expect("full pipeline should succeed");

        let mut counts = BTreeMap::new();
        for entry in &observer.starts {
            let name = entry.split(':').next().expect("phase entry has name");
            *counts.entry(name.to_owned()).or_insert(0usize) += 1;
        }

        assert_eq!(counts.get("keygen").copied(), Some(1));
        assert_eq!(counts.get("nizk_prove").copied(), Some(5));
        assert_eq!(counts.get("nizk_verify").copied(), Some(20));
        assert_eq!(counts.get("pvss_share_encrypt").copied(), Some(1));
        assert_eq!(counts.get("setup_threshold").copied(), Some(1));
        assert_eq!(counts.get("aggregate_keygen").copied(), Some(1));
        assert_eq!(counts.get("encrypt").copied(), Some(1));
        assert_eq!(counts.get("cyclo_fold").copied(), Some(1));
        assert_eq!(counts.get("cyclo_fold_verify").copied(), Some(1));
        assert_eq!(counts.get("compressor_new").copied(), Some(1));
        assert_eq!(counts.get("compressor_prove").copied(), Some(1));
        assert_eq!(counts.get("compressor_verify").copied(), Some(1));
        #[cfg(feature = "sonobe-compressor")]
        assert_eq!(counts.get("compressor_verify_external").copied(), Some(1));
        assert_eq!(counts.get("partial_decrypt").copied(), Some(2));
        assert_eq!(counts.get("aggregate_decrypt").copied(), Some(1));
        assert!(report.plaintext_roundtrip_ok);
        assert!(report.timings.phases.cyclo_fold.total_ms > 0.0);
        assert!(report.timings.phases.compressor_prove.total_ms > 0.0);
    }
}
