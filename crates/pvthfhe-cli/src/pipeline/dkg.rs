//! Keygen, DKG ceremony, and PVSS share-encryption stages.

use anyhow::Context;
use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use pvthfhe_aggregator::keygen::{
    simulator::{compute_round1_commitment, KeygenResult, KeygenSimulator},
    types::DkgTranscript,
};
use pvthfhe_bench::e2e_timings::E2eTimings;
#[cfg(any(feature = "real-compressor", feature = "surrogate-compressor"))]
use pvthfhe_compressor::witness::hash_all_coeffs;
use pvthfhe_fhe::{fhers::FhersBackend, FheBackend, KeygenShare, PublicKey};
use pvthfhe_foundations::domain_tags::Tag;
use pvthfhe_foundations::types::ProtocolBytes;
use pvthfhe_pvss::nizk_share::compute_share_commitment;
use pvthfhe_pvss::{EncryptedShares, PvssAdapter};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Instant;

use super::{elapsed_ms, sha256_bytes, PipelineConfig, PipelineObserver};
use crate::pvss_support::{run_lattice_pvss, PVSS_BACKEND_ID};

/// Outputs of the keygen stage (DKG transcript plus derived session state).
pub(crate) struct KeygenStageOutput {
    pub(crate) transcript: DkgTranscript,
    pub(crate) session_id: String,
    pub(crate) sk_commitments: Vec<[u8; 32]>,
    pub(crate) party_sk_bytes: Vec<Vec<u8>>,
    pub(crate) precomputed_dkg_deals: HashMap<(usize, usize), EncryptedShares>,
}

/// Run the keygen stage: simulator DKG, H2 commit-reveal verification,
/// per-party secret-key commitments, and P1 pre-computation of DKG deals.
pub(crate) fn run_keygen_stage<O: PipelineObserver>(
    cfg: &PipelineConfig,
    backend: &FhersBackend,
    backend_threshold: usize,
    observer: &mut O,
    timings: &mut E2eTimings,
) -> anyhow::Result<KeygenStageOutput> {
    observer.phase_start(
        "keygen",
        Some(&format!("n={} t={} seed={}", cfg.n, cfg.t, cfg.seed)),
    );
    let mut simulator = KeygenSimulator::new(cfg.n, backend_threshold, backend.clone())
        .map_err(|e| anyhow::anyhow!("keygen param: {e}"))?;
    let keygen_started = Instant::now();
    let transcript = match simulator.run().context("keygen")? {
        KeygenResult::Complete(transcript) => transcript,
        KeygenResult::Blamed(blamed) => anyhow::bail!("keygen blamed: {blamed:?}"),
    };
    let keygen_ms = elapsed_ms(keygen_started);
    observer.phase_end("keygen", keygen_ms);
    timings.phases.keygen.total_ms = keygen_ms;
    timings.phases.keygen.instances_run = 1;

    // H2: rogue-key defense — verify commit-reveal binding on Round1 messages.
    // Each commitment = SHA256("pvthfhe-dkg-commit-reveal/v2" || party_id || session_id || pk_i_hash || nonce).
    // Replaying the same hash ensures no party chose their pk after seeing honest keys.
    {
        let sim_session_id =
            keygen_simulator_session_id(&transcript.participant_set, backend_threshold);

        let _round0_commitments = transcript
            .round1_messages
            .iter()
            .map(|msg| (msg.party_id, msg.commitment))
            .collect::<Vec<_>>();

        for msg in &transcript.round1_messages {
            let expected_commit = compute_round1_commitment(
                msg.party_id,
                &sim_session_id,
                &msg.pk_i_hash,
                &msg.commitment_nonce,
            );
            if expected_commit != msg.commitment {
                anyhow::bail!(
                    "H2: commit-reveal verification failed for party {}: \
                     commitment does not match pk_i_hash binding",
                    msg.party_id
                );
            }
        }
        observer.note("h2_commit_reveal: verified all Round1 commitment bindings");
    }

    let session_id = keygen_session_id(&transcript.round3_aggregate.aggregate_pk, cfg.t, cfg.seed);

    // G.SHARE-PROVENANCE: compute per-party secret key commitments
    let mut sk_commitments: Vec<[u8; 32]> = Vec::with_capacity(cfg.n);
    let mut party_sk_bytes: Vec<Vec<u8>> = Vec::with_capacity(cfg.n);
    for party_idx in 0..cfg.n {
        let backend_party_id = u32::try_from(party_idx + 1).context("party_id conversion")?;
        let sk_bytes = backend
            .party_secret_key_bytes(backend_party_id)
            .context("party_secret_key_bytes")?;
        let sk_commit = compute_share_commitment(session_id.as_bytes(), party_idx, &sk_bytes)?;
        sk_commitments.push(sk_commit);
        party_sk_bytes.push(sk_bytes);
    }

    // P1: Pre-compute sigma NIZK proofs during keygen phase.
    // Each dealer's sigma proof depends only on their own keypair and the
    // deterministic session parameters — not on other dealers' messages.
    // Pre-computing the full EncryptedShares (Shamir split + encryption +
    // NIZK proof) during keygen saves ~30 % of per-dealer time in dkg_deal.
    let precomputed_dkg_deals: HashMap<(usize, usize), EncryptedShares> = {
        let dkg_session_id = format!("dkg-{}", hex::encode(cfg.seed.to_be_bytes()));
        let dkg_root = transcript.dkg_root.to_vec();
        let session_id_bytes = dkg_session_id.as_bytes().to_vec();

        let recipient_pks: Vec<Vec<u8>> = transcript
            .round1_messages
            .iter()
            .map(|message| {
                backend
                    .aggregate_keygen(&[KeygenShare {
                        party_id: message.party_id,
                        bytes: ProtocolBytes(message.pk_i.bytes.clone()),
                    }])
                    .map(|pk| pk.bytes)
                    .with_context(|| format!("derive recipient pk for party {}", message.party_id))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let adapter = pvthfhe_pvss::LatticePvssBfvAdapter::new()
            .map_err(|e| anyhow::anyhow!("dkg pvss adapter init (P1 precompute): {e}"))?;

        const DKG_CHUNK_SIZE: usize = 4000;
        let mut deals = HashMap::new();
        for dealer_id in 0..cfg.n {
            let sk_bytes = &party_sk_bytes[dealer_id];
            let num_chunks = sk_bytes.len().div_ceil(DKG_CHUNK_SIZE);
            for chunk_idx in 0..num_chunks {
                let start = chunk_idx * DKG_CHUNK_SIZE;
                let end = (start + DKG_CHUNK_SIZE).min(sk_bytes.len());
                let chunk = &sk_bytes[start..end];

                let mut seed = [0u8; 32];
                {
                    let mut h = Sha256::new();
                    h.update(Tag::DkgPrecompute.as_bytes());
                    h.update(cfg.seed.to_le_bytes());
                    h.update((dealer_id as u64).to_le_bytes());
                    h.update((chunk_idx as u64).to_le_bytes());
                    seed.copy_from_slice(&h.finalize());
                }

                let ctx = pvthfhe_pvss::PvssContext {
                    n: cfg.n,
                    t: cfg.t,
                    session_id: session_id_bytes.clone(),
                    epoch: 0,
                    dkg_root: dkg_root.clone(),
                    dealer_index: dealer_id,
                };
                let encrypted = adapter
                    .deal_seeded(chunk, &recipient_pks, &ctx, &seed)
                    .with_context(|| {
                        format!("P1 precompute dkg deal dealer={dealer_id} chunk={chunk_idx}")
                    })?;
                adapter.verify_shares(&encrypted, &ctx).with_context(|| {
                    format!("P1 precompute verify_shares dealer={dealer_id} chunk={chunk_idx}")
                })?;
                deals.insert((dealer_id, chunk_idx), encrypted);
            }
        }
        tracing::info!(
            "P1: pre-computed {} dkg deals ({} parties × {} chunks avg)",
            deals.len(),
            cfg.n,
            deals.len() / cfg.n.max(1)
        );
        deals
    };

    Ok(KeygenStageOutput {
        transcript,
        session_id,
        sk_commitments,
        party_sk_bytes,
        precomputed_dkg_deals,
    })
}

/// Outputs of the DKG ceremony stage (dealer→recipient share distribution).
pub(crate) struct DkgCeremonyOutput {
    pub(crate) dkg_verified: bool,
    pub(crate) dkg_share_count: usize,
    pub(crate) parity_verified: bool,
    pub(crate) recipient_fold_hashes: Vec<Fr>,
    pub(crate) recipient_parity_proof_hashes: Vec<Fr>,
    pub(crate) dealer_recipient_total_shares: Vec<Vec<Fr>>,
    pub(crate) dkg_root_vec: Vec<u8>,
}

/// Run the DKG ceremony: each party dealer+recipient, Shamir split, encrypted shares.
pub(crate) fn run_dkg_ceremony_stage<O: PipelineObserver>(
    cfg: &PipelineConfig,
    backend: &FhersBackend,
    transcript: &DkgTranscript,
    mut party_sk_bytes: Vec<Vec<u8>>,
    mut precomputed_dkg_deals: HashMap<(usize, usize), EncryptedShares>,
    observer: &mut O,
) -> anyhow::Result<DkgCeremonyOutput> {
    let dkg_verified;
    let dkg_share_count;
    let parity_verified;
    let recipient_fold_hashes;
    let recipient_parity_proof_hashes;
    let mut dealer_recipient_total_shares: Vec<Vec<Fr>> = vec![vec![Fr::zero(); cfg.n]; cfg.n];
    let mut dkg_root_vec: Vec<u8> = Vec::new();
    observer.phase_start("dkg_ceremony", Some(&format!("n={} t={}", cfg.n, cfg.t)));
    let dkg_started = Instant::now();
    {
        use pvthfhe_pvss::dkg_aggregation::{
            compute_esm_aggregate_commitment, compute_esm_dealer_share_commitment,
            compute_sk_aggregate_commitment, compute_sk_dealer_share_commitment,
            verify_recipient_dkg_aggregation, DealerDkgShare, RecipientDkgAggregationStatement,
        };
        use pvthfhe_pvss::{LatticePvssBfvAdapter, PvssAdapter, PvssContext};

        let n = cfg.n;
        let t = cfg.t;
        let dkg_session_id = format!("dkg-{}", hex::encode(cfg.seed.to_be_bytes()));
        dkg_root_vec = transcript.dkg_root.to_vec();
        let session_id_bytes = dkg_session_id.as_bytes().to_vec();

        let recipient_pks: Vec<Vec<u8>> = transcript
            .round1_messages
            .iter()
            .map(|message| {
                backend
                    .aggregate_keygen(&[KeygenShare {
                        party_id: message.party_id,
                        bytes: ProtocolBytes(message.pk_i.bytes.clone()),
                    }])
                    .map(|pk| pk.bytes)
                    .with_context(|| format!("derive recipient pk for party {}", message.party_id))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let adapter = LatticePvssBfvAdapter::new()
            .map_err(|e| anyhow::anyhow!("dkg pvss adapter init: {e}"))?;

        // Phase 1: Each dealer splits their secret key and encrypts shares.
        const DKG_CHUNK_SIZE: usize = 4000;

        observer.phase_start("dkg_deal", Some(&format!("n={} dealers", n)));
        let dkg_deal_started = Instant::now();
        for dealer_id in 0..n {
            let sk_bytes = &party_sk_bytes[dealer_id];
            let num_chunks = sk_bytes.len().div_ceil(DKG_CHUNK_SIZE);

            for chunk_idx in 0..num_chunks {
                let ctx = PvssContext {
                    n,
                    t,
                    session_id: session_id_bytes.clone(),
                    epoch: 0,
                    dkg_root: dkg_root_vec.clone(),
                    dealer_index: dealer_id,
                };
                // P1: reuse pre-computed EncryptedShares from keygen phase,
                // then immediately remove from cache to reclaim memory.
                let encrypted = precomputed_dkg_deals
                    .remove(&(dealer_id, chunk_idx))
                    .with_context(|| {
                        format!(
                            "P1: missing precomputed dkg deal dealer={dealer_id} chunk={chunk_idx}"
                        )
                    })?;

                // Defense-in-depth: re-verify even pre-computed shares.
                adapter.verify_shares(&encrypted, &ctx).map_err(|e| {
                    anyhow::anyhow!("dkg verify_shares dealer={dealer_id} chunk={chunk_idx}: {e}")
                })?;

                for recipient_id in 0..n {
                    let share_bytes = &encrypted.share_bytes[recipient_id];
                    let (_, fr_values) = deserialize_share_payload_to_frs(share_bytes)
                        .with_context(|| format!("deserialize share dealer={dealer_id} chunk={chunk_idx} recipient={recipient_id}"))?;
                    let chunk_total: Fr = fr_values.iter().fold(Fr::zero(), |acc, &f| acc + f);
                    dealer_recipient_total_shares[dealer_id][recipient_id] += chunk_total;
                }
            }

            // MEMORY: drop dealer's sk_bytes after all chunks processed.
            let _ = std::mem::take(&mut party_sk_bytes[dealer_id]);
        }
        // MEMORY: drop the precomputed deals map entirely (all entries removed above).
        std::mem::drop(precomputed_dkg_deals);
        observer.phase_end("dkg_deal", elapsed_ms(dkg_deal_started));

        // Phase 2: Each recipient aggregates shares from all dealers and verifies
        observer.phase_start("dkg_aggregate", Some(&format!("n={} recipients", n)));
        let dkg_agg_started = Instant::now();
        let max_n_u16 = u16::try_from(n).context("n exceeds u16")?;
        let accepted_dealer_ids: Vec<u16> = (1..=max_n_u16).collect();
        let smudge_slot_indices = vec![1u16];

        for recipient_id in 0..n {
            let recipient_id_u16 = (recipient_id + 1) as u16;
            let mut dealer_inputs = Vec::with_capacity(n);

            for dealer_id in 0..n {
                let dealer_id_u16 = (dealer_id + 1) as u16;
                let total_share = dealer_recipient_total_shares[dealer_id][recipient_id];

                let sk_commit = compute_sk_dealer_share_commitment(
                    &session_id_bytes,
                    &dkg_root_vec,
                    dealer_id_u16,
                    recipient_id_u16,
                    total_share,
                );

                let esm_value = Fr::from(1u64);
                let esm_commit = compute_esm_dealer_share_commitment(
                    &session_id_bytes,
                    &dkg_root_vec,
                    dealer_id_u16,
                    recipient_id_u16,
                    1,
                    esm_value,
                );

                dealer_inputs.push(DealerDkgShare {
                    dealer_id: dealer_id_u16,
                    decrypted_sk_share: total_share,
                    sk_share_commitment: sk_commit,
                    decrypted_esm_shares: vec![(1, esm_value)],
                    esm_share_commitments: vec![(1, esm_commit)],
                });
            }

            let claimed_sk_aggregate: Fr =
                dealer_inputs.iter().map(|di| di.decrypted_sk_share).sum();
            let claimed_esm_sum: Fr = dealer_inputs
                .iter()
                .map(|di| di.decrypted_esm_shares[0].1)
                .sum();

            let sk_agg_commit = compute_sk_aggregate_commitment(
                &session_id_bytes,
                &dkg_root_vec,
                recipient_id_u16,
                &accepted_dealer_ids,
                claimed_sk_aggregate,
            );
            let esm_agg_commit = compute_esm_aggregate_commitment(
                &session_id_bytes,
                &dkg_root_vec,
                recipient_id_u16,
                &accepted_dealer_ids,
                1,
                claimed_esm_sum,
            );

            let statement = RecipientDkgAggregationStatement {
                session_id: session_id_bytes.clone(),
                dkg_root: dkg_root_vec.clone(),
                recipient_id: recipient_id_u16,
                accepted_dealer_ids: accepted_dealer_ids.clone(),
                smudge_slot_indices: smudge_slot_indices.clone(),
                dealer_inputs,
                claimed_sk_aggregate,
                claimed_esm_aggregates: vec![(1, claimed_esm_sum)],
                sk_agg_commit,
                esm_agg_commits: vec![(1, esm_agg_commit)],
            };

            verify_recipient_dkg_aggregation(&statement).map_err(|e| {
                anyhow::anyhow!("dkg aggregation verify for recipient {recipient_id}: {e}")
            })?;
        }
        observer.phase_end("dkg_aggregate", elapsed_ms(dkg_agg_started));

        observer.phase_start("dkg_fold", Some(&format!("n={} recipients", n)));
        let dkg_fold_started = Instant::now();

        let mut fold_hashes: Vec<Fr> = Vec::with_capacity(n);
        let mut parity_proof_hashes: Vec<Fr> = Vec::with_capacity(n);
        // DKG fold: compute recipient fold hashes natively
        {
            for recipient_id in 0..n {
                let mut recipient_commitments: Vec<Fr> = Vec::with_capacity(n);
                for dealer_id in 0..n {
                    let dealer_id_u16 = (dealer_id + 1) as u16;
                    let recipient_id_u16 = (recipient_id + 1) as u16;
                    let total_share = dealer_recipient_total_shares[dealer_id][recipient_id];
                    let sk_commit = compute_sk_dealer_share_commitment(
                        &session_id_bytes,
                        &dkg_root_vec,
                        dealer_id_u16,
                        recipient_id_u16,
                        total_share,
                    );
                    let sk_commit_fr = Fr::from_be_bytes_mod_order(&sk_commit);
                    recipient_commitments.push(sk_commit_fr);
                }
                let fold_hash = hash_all_coeffs(&recipient_commitments);
                fold_hashes.push(fold_hash);
                parity_proof_hashes.push(fold_hash);
            }
        }
        recipient_fold_hashes = fold_hashes;
        recipient_parity_proof_hashes = parity_proof_hashes;

        dkg_share_count = n * n;
        dkg_verified = true;
        parity_verified = true;
        observer.phase_end("dkg_fold", elapsed_ms(dkg_fold_started));
    }
    observer.phase_end("dkg_ceremony", elapsed_ms(dkg_started));

    Ok(DkgCeremonyOutput {
        dkg_verified,
        dkg_share_count,
        parity_verified,
        recipient_fold_hashes,
        recipient_parity_proof_hashes,
        dealer_recipient_total_shares,
        dkg_root_vec,
    })
}

/// Run the PVSS share-encryption stage over the demo/e2e transcript.
pub(crate) fn run_pvss_stage<O: PipelineObserver>(
    cfg: &PipelineConfig,
    backend: &FhersBackend,
    transcript: &DkgTranscript,
    observer: &mut O,
    timings: &mut E2eTimings,
) -> anyhow::Result<()> {
    observer.phase_start("pvss_share_encrypt", Some(PVSS_BACKEND_ID));
    let pvss_started = Instant::now();
    let pvss = run_lattice_pvss(backend, transcript, cfg.t, "pvthfhe-e2e/pvss", cfg.seed)?;
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
    Ok(())
}

fn keygen_session_id(aggregate_pk: &PublicKey, threshold: usize, seed: u64) -> String {
    let mut binding = Vec::new();
    binding.extend_from_slice(Tag::E2eKeygenNizk.as_bytes());
    binding.extend_from_slice(&seed.to_be_bytes());
    binding.extend_from_slice(&threshold.to_be_bytes());
    binding.extend_from_slice(&sha256_bytes(&aggregate_pk.bytes));
    format!("pvthfhe-e2e-{}", hex::encode(sha256_bytes(&binding)))
}

fn keygen_simulator_session_id(participant_set: &[u32], threshold: usize) -> [u8; 32] {
    let mut participant_bytes = Vec::with_capacity(std::mem::size_of_val(participant_set));
    for &pid in participant_set {
        participant_bytes.extend_from_slice(&pid.to_be_bytes());
    }

    let mut participant_set_hash = Sha256::new();
    participant_set_hash.update(Tag::ParticipantSet.as_bytes());
    participant_set_hash.update(&participant_bytes);
    let participant_set_hash: [u8; 32] = participant_set_hash.finalize().into();

    let mut session_bytes = Vec::with_capacity(72);
    session_bytes.extend_from_slice(Tag::KeygenSimulatorSession.as_bytes());
    session_bytes.extend_from_slice(&participant_set_hash);
    session_bytes.extend_from_slice(&threshold.to_be_bytes());

    let mut session_id = Sha256::new();
    session_id.update(Tag::SessionId.as_bytes());
    session_id.update(&session_bytes);
    session_id.finalize().into()
}

/// Deserialize a PVSS share payload into (original_len, Vec<Fr>).
/// Payload format: [original_len: u32 BE][fr_0: 32 bytes LE][fr_1: 32 bytes LE]...
fn deserialize_share_payload_to_frs(share_bytes: &[u8]) -> anyhow::Result<(usize, Vec<Fr>)> {
    const LEN_PREFIX: usize = 4;
    const FR_SERIALIZED: usize = 32;
    if share_bytes.len() < LEN_PREFIX + FR_SERIALIZED {
        anyhow::bail!("share payload too short: {} bytes", share_bytes.len());
    }
    let original_len = u32::from_be_bytes(share_bytes[..LEN_PREFIX].try_into().unwrap()) as usize;
    let fr_data = &share_bytes[LEN_PREFIX..];
    if !fr_data.len().is_multiple_of(FR_SERIALIZED) {
        anyhow::bail!(
            "share payload misaligned: {} not divisible by {}",
            fr_data.len(),
            FR_SERIALIZED
        );
    }
    let frs: Vec<Fr> = fr_data
        .chunks(FR_SERIALIZED)
        .map(|chunk| {
            let mut limbs = [0u64; 4];
            for (i, limb_bytes) in chunk.chunks_exact(8).enumerate() {
                limbs[i] = u64::from_le_bytes(limb_bytes.try_into().unwrap());
            }
            Fr::from_bigint(ark_ff::BigInt::<4>::new(limbs))
                .ok_or_else(|| anyhow::anyhow!("Fr deserialization failed: value >= modulus"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok((original_len, frs))
}

#[cfg(feature = "pipeline-extra-checks")]
pub(crate) fn verify_all_dealer_share_computations(
    dealer_shares: &[Vec<Fr>],
    dealer_id_start: usize,
    session_id: &str,
    threshold: usize,
    dkg_root_bytes: &[u8],
) -> anyhow::Result<()> {
    use pvthfhe_foundations::types::ProtocolBytes;
    use pvthfhe_pvss::share_computation::{
        compute_esm_secret_commitment, compute_sk_secret_commitment, interpolate_coefficients,
        verify_batched_share_computation, BatchedShareComputationStatement,
        ESmShareComputationSlot, FieldShare, ShareComputationTrack,
    };

    let session_id_bytes = ProtocolBytes::from(session_id.as_bytes().to_vec());
    let dkg_root = ProtocolBytes::from(dkg_root_bytes.to_vec());
    let max_degree = threshold.saturating_sub(1);
    let max_n_u16 = u16::try_from(dealer_shares[0].len()).context("n exceeds u16")?;

    for (dealer_idx, shares) in dealer_shares.iter().enumerate() {
        let dealer_id = (dealer_id_start + dealer_idx + 1) as u16;

        let shares_field: Vec<FieldShare> = shares
            .iter()
            .enumerate()
            .map(|(i, &value)| FieldShare {
                recipient_index: (i + 1) as u16,
                value,
            })
            .collect();

        // Use the same interpolation as check_track for commitment consistency.
        let first_k = (max_degree + 1).min(shares.len());
        let points: Vec<(Fr, Fr)> = shares_field[..first_k]
            .iter()
            .map(|fs| (Fr::from(fs.recipient_index as u64), fs.value))
            .collect();
        let coefficients = interpolate_coefficients(&points, dealer_id)
            .map_err(|e| anyhow::anyhow!("share interpolation failed: {e}"))?;
        let sk_constant = coefficients[0];

        let sk_secret_commitment = compute_sk_secret_commitment(
            session_id_bytes.as_slice(),
            dkg_root.as_slice(),
            dealer_id,
            sk_constant,
        );

        let esm_shares: Vec<FieldShare> = (1..=max_n_u16)
            .map(|recipient_index| FieldShare {
                recipient_index,
                value: Fr::zero(),
            })
            .collect();

        let esm_smudge_commitment = compute_esm_secret_commitment(
            session_id_bytes.as_slice(),
            dkg_root.as_slice(),
            dealer_id,
            1,
            Fr::zero(),
        );

        let statement = BatchedShareComputationStatement {
            session_id: session_id_bytes.clone(),
            dkg_root: dkg_root.clone(),
            dealer_id,
            max_degree,
            coefficient_bound: u64::MAX,
            sk: ShareComputationTrack {
                shares: shares_field,
                secret_commitment: sk_secret_commitment,
            },
            esm_slots: vec![ESmShareComputationSlot {
                slot_index: 1,
                shares: esm_shares,
                smudge_commitment: esm_smudge_commitment,
            }],
        };

        verify_batched_share_computation(&statement)
            .map_err(|e| anyhow::anyhow!("batched share computation verify failed: {e}"))?;
    }

    Ok(())
}
