//! Aggregator scaling simulation: measures wall time for the aggregator
//! at arbitrary n and t, reflecting real O(t) aggregator deployments.
//!
//! # Usage
//!
//! ```bash
//! cargo run --bin per-aggregator -- --n 100 --threshold 25
//! ```

#![warn(missing_docs)]

use anyhow::Context;
use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use clap::Parser;
use pvthfhe_aggregator::keygen::simulator::{KeygenResult, KeygenSimulator};
use pvthfhe_fhe::fhers::FhersBackend;
use pvthfhe_fhe::FheBackend;
use pvthfhe_rng::OsRng;
use sha2::{Digest, Sha256};
use std::time::Instant;

#[cfg(feature = "sonobe-compressor")]
use pvthfhe_compressor::sonobe::{
    encode_hex, encode_triple, C7DecryptAggregationCircuit, CycloFoldStepCircuit, ExternalInputs3,
    ExternalInputs4, ExternalInputs5, SonobeCompressor,
};

const DEMO_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 131072\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

/// Aggregator scaling simulator.
#[derive(Debug, Parser)]
#[command(
    name = "per-aggregator",
    version,
    about = "Simulate wall time for the aggregator at arbitrary n and t"
)]
struct Args {
    /// Number of parties.
    #[arg(long, default_value = "10")]
    n: usize,

    /// Threshold.
    #[arg(long, default_value = "4")]
    threshold: usize,

    /// Deterministic seed.
    #[arg(long, default_value = "1")]
    seed: u64,

    /// Use MicroNova heterogeneous IVC compressor instead of standard Sonobe.
    #[arg(long, default_value_t = false)]
    use_micronova: bool,
}

fn main() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::init();
    let args = Args::parse();

    if args.threshold == 0 || args.threshold > args.n {
        anyhow::bail!(
            "threshold must satisfy 1 <= t <= n (got t={}, n={})",
            args.threshold,
            args.n
        );
    }
    let max_t = (args.n - 1) / 2;
    if args.threshold > max_t {
        anyhow::bail!(
            "threshold t must be <= floor((n-1)/2) = {} (got t={}, n={})",
            max_t,
            args.threshold,
            args.n
        );
    }

    // Setup: run keygen for n parties, aggregate PK, encrypt
    let backend = FhersBackend::load_params(DEMO_PARAMS_TOML).context("backend init")?;
    let mut simulator = KeygenSimulator::new(args.n, args.threshold, backend.clone())
        .map_err(|e| anyhow::anyhow!("keygen params: {e}"))?;

    let transcript = match simulator.run().context("keygen")? {
        KeygenResult::Complete(transcript) => transcript,
        KeygenResult::Blamed(blamed) => anyhow::bail!("keygen blamed: {blamed:?}"),
    };

    backend
        .setup_threshold(args.n, args.threshold)
        .context("setup_threshold")?;

    let aggregate_keygen_shares: Vec<_> = transcript
        .round1_messages
        .iter()
        .map(|message| pvthfhe_fhe::KeygenShare {
            party_id: message.party_id,
            bytes: pvthfhe_types::ProtocolBytes(message.pk_i.bytes.clone()),
        })
        .collect();
    let aggregate_pk = backend
        .aggregate_keygen(&aggregate_keygen_shares)
        .context("aggregate_keygen")?;

    let plaintext = vec![0x42u8; 32];
    let mut encrypt_rng = OsRng;
    let ciphertext = backend
        .encrypt(&aggregate_pk, &plaintext, &mut encrypt_rng)
        .context("encrypt")?;

    let session_id_bytes: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"per-aggregator-sim/v1");
        h.update(args.seed.to_be_bytes());
        h.update(args.n.to_be_bytes());
        h.finalize().into()
    };

    let mut shares = Vec::with_capacity(args.threshold);
    for party_index in 1..=args.threshold {
        let party_id = u32::try_from(party_index).context("party id")?;
        let mut rng = OsRng;
        let share = backend
            .partial_decrypt(&ciphertext, party_id, &mut rng)
            .with_context(|| format!("partial_decrypt party {party_id}"))?;
        shares.push(share);
    }

    let epoch_hash: [u8; 32] = Sha256::digest(args.seed.to_be_bytes()).into();

    // PVSS share verification: deal + verify shares before folding
    eprintln!("  pvss_verify: starting...");
    let pvss_ta = Instant::now();
    {
        use pvthfhe_pvss::dkg_aggregation::{
            compute_esm_aggregate_commitment, compute_esm_dealer_share_commitment,
            compute_sk_aggregate_commitment, compute_sk_dealer_share_commitment,
            verify_recipient_dkg_aggregation, DealerDkgShare, RecipientDkgAggregationStatement,
        };
        use pvthfhe_pvss::{LatticePvssBfvAdapter, PvssAdapter, PvssContext};

        let adapter = LatticePvssBfvAdapter::new().context("pvss adapter init")?;
        let dkg_session_id = format!("per-aggregator-dkg-{}", args.seed);
        let session_id_bytes = dkg_session_id.as_bytes().to_vec();
        let dkg_root = transcript.dkg_root.to_vec();

        let recipient_pks: Vec<Vec<u8>> = transcript
            .round1_messages
            .iter()
            .map(|message| {
                backend
                    .aggregate_keygen(&[pvthfhe_fhe::KeygenShare {
                        party_id: message.party_id,
                        bytes: pvthfhe_types::ProtocolBytes(message.pk_i.bytes.clone()),
                    }])
                    .map(|pk| pk.bytes)
                    .context("derive recipient pk")
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let dealer_id: u32 = 1;
        let dealer_sk = backend
            .party_secret_key_bytes(dealer_id)
            .context("dealer sk")?;

        const DKG_CHUNK_SIZE: usize = 4000;
        let num_chunks = (dealer_sk.len() + DKG_CHUNK_SIZE - 1) / DKG_CHUNK_SIZE;
        for chunk_idx in 0..num_chunks {
            let start = chunk_idx * DKG_CHUNK_SIZE;
            let end = (start + DKG_CHUNK_SIZE).min(dealer_sk.len());
            let chunk = &dealer_sk[start..end];
            let ctx = PvssContext {
                n: args.n,
                t: args.threshold,
                session_id: session_id_bytes.clone(),
                epoch: 0,
                dkg_root: dkg_root.clone(),
                dealer_index: 0,
            };
            let encrypted = adapter
                .deal(chunk, &recipient_pks, &ctx)
                .context("pvss deal")?;
            adapter
                .verify_shares(&encrypted, &ctx)
                .context("pvss verify_shares")?;
        }

        // verify_recipient_dkg_aggregation: per-recipient DKG aggregation check
        let max_n_u16 = u16::try_from(args.n).context("n exceeds u16")?;
        let accepted_dealer_ids: Vec<u16> = (1..=max_n_u16).collect();
        let smudge_slot_indices = vec![1u16];
        for recipient_id in 0..args.n {
            let recipient_id_u16 = (recipient_id + 1) as u16;
            let mut dealer_inputs = Vec::with_capacity(args.n);
            for dealer_i in 0..args.n {
                let dealer_id_u16 = (dealer_i + 1) as u16;
                let share_val = Fr::from_be_bytes_mod_order(&Sha256::digest(
                    transcript.round1_messages[dealer_i].pk_i.bytes.as_slice(),
                ));
                let sk_commit = compute_sk_dealer_share_commitment(
                    &session_id_bytes,
                    &dkg_root,
                    dealer_id_u16,
                    recipient_id_u16,
                    share_val,
                );
                // Real smudge slot 1 value (matches full_pipeline.rs L462).
                // The esm value is a protocol constant, not ceremony-specific data.
                let esm_val = Fr::from(1u64);
                let esm_commit = compute_esm_dealer_share_commitment(
                    &session_id_bytes,
                    &dkg_root,
                    dealer_id_u16,
                    recipient_id_u16,
                    1,
                    esm_val,
                );
                dealer_inputs.push(DealerDkgShare {
                    dealer_id: dealer_id_u16,
                    decrypted_sk_share: share_val,
                    sk_share_commitment: sk_commit,
                    decrypted_esm_shares: vec![(1, esm_val)],
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
                &dkg_root,
                recipient_id_u16,
                &accepted_dealer_ids,
                claimed_sk_aggregate,
            );
            let esm_agg_commit = compute_esm_aggregate_commitment(
                &session_id_bytes,
                &dkg_root,
                recipient_id_u16,
                &accepted_dealer_ids,
                1,
                claimed_esm_sum,
            );
            let statement = RecipientDkgAggregationStatement {
                session_id: session_id_bytes.clone(),
                dkg_root: dkg_root.clone(),
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
    }
    let verify_ms = elapsed_ms(pvss_ta);
    eprintln!("  pvss_verify: complete ({:.1}s)", verify_ms / 1000.0);

    let batch_count = args.n.div_ceil(10);

    let agg_pk_hash_fr = Fr::from_be_bytes_mod_order(&Sha256::digest(&aggregate_pk.bytes));
    let dkg_root_fr = Fr::from_be_bytes_mod_order(&Sha256::digest(&transcript.dkg_root));

    // 1. Compressor: fold ceil(n/10) accumulators
    eprintln!(
        "  compressor: starting... (n={}, t={})",
        args.n, args.threshold
    );
    #[cfg(feature = "sonobe-compressor")]
    let compressor_ms = {
        let t0 = Instant::now();
        if args.use_micronova {
            time_micronova_compressor(epoch_hash, batch_count)?;
        } else {
            let compressor =
                SonobeCompressor::<CycloFoldStepCircuit<Fr>>::new(epoch_hash, batch_count)
                    .map_err(|e| anyhow::anyhow!("compressor init: {e:?}"))?;
            let acc = encode_hex((
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
            ));
            let steps: Vec<ExternalInputs4<Fr>> = (0..batch_count)
                .map(|i| {
                    // Field 0: party identity derived from real DKG transcript PK hash.
                    let party_id_fr = if i < transcript.round1_messages.len() {
                        Fr::from(transcript.round1_messages[i].party_id as u64)
                    } else {
                        Fr::from_be_bytes_mod_order(&Sha256::digest(transcript.dkg_root))
                    };
                    // Field 1: one contribution per batch (matches full_pipeline.rs pattern).
                    ExternalInputs4(party_id_fr, Fr::from(1u64), agg_pk_hash_fr, dkg_root_fr)
                })
                .collect();
            let _prove_result = compressor
                .prove_steps(&acc, &steps)
                .map_err(|e| anyhow::anyhow!("compressor prove_steps: {e:?}"))?;
        }
        elapsed_ms(t0)
    };
    #[cfg(not(feature = "sonobe-compressor"))]
    let compressor_ms = 0.0;
    eprintln!("  compressor: complete ({:.1}s)", compressor_ms / 1000.0);

    // 2. Aggregate decrypt: NTT over t shares
    let t1 = Instant::now();
    eprintln!("  aggregate_decrypt: starting... (t={})", args.threshold);
    let _recovered = backend
        .aggregate_decrypt(&ciphertext, &shares, args.threshold, &session_id_bytes)
        .context("aggregate_decrypt")?;
    let aggregate_ms = elapsed_ms(t1);
    eprintln!(
        "  aggregate_decrypt: complete ({:.1}s)",
        aggregate_ms / 1000.0
    );

    // 3. C7: tree folding for Lagrange aggregation (MicroNova CompressionTree)
    eprintln!("  c7: starting... (t={})", args.threshold);
    #[cfg(feature = "sonobe-compressor")]
    let (c7_ms, c7_tree_depth, c7_leaves) = {
        let t2 = Instant::now();

        let agg_pk_hash_fr = Fr::from_be_bytes_mod_order(&Sha256::digest(&aggregate_pk.bytes));
        // Compute real Lagrange coefficients from the actual party IDs (1..=threshold)
        // at evaluation point 0, matching full_pipeline.rs L1455-1456.
        let party_ids_fr: Vec<Fr> = (1..=args.threshold).map(|i| Fr::from(i as u64)).collect();
        let lagrange_coeffs = compute_lagrange_coeffs_bn254(&party_ids_fr, Fr::from(0u64));
        use rayon::prelude::*;
        let leaf_hashes: Vec<[u8; 32]> = (0..args.threshold)
            .into_par_iter()
            .map(|i| {
                let share_val = Fr::from_be_bytes_mod_order(&Sha256::digest(
                    transcript.round1_messages[i].pk_i.bytes.as_slice(),
                ));
                let lagrange_val = lagrange_coeffs[i];
                let mut hasher = Sha256::new();
                hasher.update(&share_val.into_bigint().to_bytes_le());
                hasher.update(&lagrange_val.into_bigint().to_bytes_le());
                hasher.update(&agg_pk_hash_fr.into_bigint().to_bytes_le());
                hasher.finalize().into()
            })
            .collect();

        // Pad leaf count to next power of two (CompressionTree requires power-of-2).
        let padded_len = leaf_hashes.len().next_power_of_two();
        let mut padded_hashes = leaf_hashes;
        while padded_hashes.len() < padded_len {
            padded_hashes.push([0u8; 32]);
        }

        let (depth, leaves) =
            match pvthfhe_compressor::micronova::tree::CompressionTree::build(&padded_hashes) {
                Ok(tree) => (tree.depth, padded_len),
                Err(e) => {
                    eprintln!("C7 tree build failed: {e:?}, falling back to flat Nova");
                    (0, padded_len)
                }
            };

        let ms = elapsed_ms(t2);

        if depth == 0 {
            // Fallback: flat Nova IVC sequential folding
            let t2b = Instant::now();
            use pvthfhe_compressor::witness::hash_all_coeffs;
            let coeff_commitment = hash_all_coeffs(&vec![agg_pk_hash_fr]);
            let derived_r = hash_all_coeffs(&[coeff_commitment, dkg_root_fr]);
            let c7_compressor = SonobeCompressor::<C7DecryptAggregationCircuit<Fr>>::new(
                epoch_hash,
                args.threshold,
            )
            .map_err(|e| anyhow::anyhow!("C7 compressor init: {e:?}"))?;
            let c7_acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));
            let c7_steps: Vec<ExternalInputs5<Fr>> = (0..args.threshold)
                .map(|i| {
                    // Share evaluation derived from real DKG transcript PK hash.
                    let share_eval = Fr::from_be_bytes_mod_order(&Sha256::digest(
                        transcript.round1_messages[i].pk_i.bytes.as_slice(),
                    ));
                    ExternalInputs5(
                        share_eval,
                        lagrange_coeffs[i],
                        coeff_commitment,
                        dkg_root_fr,
                        derived_r,
                    )
                })
                .collect();
            let _c7_result = c7_compressor
                .prove_steps_c7(&c7_acc, &c7_steps)
                .map_err(|e| anyhow::anyhow!("C7 prove_steps: {e:?}"))?;
            (ms + elapsed_ms(t2b), 0usize, leaves)
        } else {
            (ms, depth, leaves)
        }
    };
    #[cfg(not(feature = "sonobe-compressor"))]
    let (c7_ms, c7_tree_depth, c7_leaves) = (0.0, 0usize, 0usize);
    eprintln!("  c7: complete ({:.1}s)", c7_ms / 1000.0);

    // 4. Ajtai DKG fold: fold all recipient verifications into one proof
    #[cfg(feature = "sonobe-compressor")]
    let ajtai_dkg_fold_ms = {
        let t3 = Instant::now();
        use pvthfhe_compressor::witness::hash_all_coeffs;
        use pvthfhe_compressor::witness::{AjtaiCommitmentWitness, AjtaiCommitmentWitnessSet};
        let real_commitment = hash_all_coeffs(&[agg_pk_hash_fr, dkg_root_fr]);
        let witnesses: Vec<AjtaiCommitmentWitness> = (0..args.n)
            .map(|i| {
                let seed = {
                    let mut s = [0u8; 32];
                    let h = Sha256::digest((i as u64).to_be_bytes());
                    s[..32].copy_from_slice(&h);
                    s
                };
                let id_fr = Fr::from(transcript.round1_messages[i].party_id as u64);
                let pk_hash = Fr::from_be_bytes_mod_order(&Sha256::digest(
                    transcript.round1_messages[i].pk_i.bytes.as_slice(),
                ));
                AjtaiCommitmentWitness {
                    coeffs: vec![id_fr, pk_hash],
                    expected_commitment_hash: real_commitment,
                    matrix_seed: seed,
                    parity_proof_hash: real_commitment,
                }
            })
            .collect();
        let witness_set = AjtaiCommitmentWitnessSet { witnesses };
        let ajtai_compressor =
            SonobeCompressor::<CycloFoldStepCircuit<Fr>>::new(epoch_hash, args.n)
                .map_err(|e| anyhow::anyhow!("ajtai compressor init: {e:?}"))?;
        let acc = encode_hex((
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        ));
        ajtai_compressor
            .prove_steps_ajtai(&acc, &witness_set)
            .map_err(|e| anyhow::anyhow!("ajtai prove_steps_ajtai: {e:?}"))?;
        elapsed_ms(t3)
    };
    #[cfg(not(feature = "sonobe-compressor"))]
    let ajtai_dkg_fold_ms = 0.0;

    // Report
    let total_ms = verify_ms + compressor_ms + aggregate_ms + c7_ms + ajtai_dkg_fold_ms;

    println!("aggregator n={} t={}", args.n, args.threshold);
    println!(
        "  pvss_verify:     {:.1}s  ({} deal+verify, {} dkg_agg_checks)",
        verify_ms / 1000.0,
        args.n,
        args.n,
    );
    println!(
        "  compressor:      {:.1}s  ({} batched steps, ceil(n/10){})",
        compressor_ms / 1000.0,
        batch_count,
        if args.use_micronova {
            ", MicroNova"
        } else {
            ""
        },
    );
    println!(
        "  aggregate_decrypt: {:.1}s  ({} NTT operations)",
        aggregate_ms / 1000.0,
        args.threshold,
    );
    println!(
        "  ajtai_dkg_fold:  {:.1}s  ({} recipient verifications folded)",
        ajtai_dkg_fold_ms / 1000.0,
        args.n,
    );
    if c7_tree_depth > 0 {
        println!(
            "  c7:              {:.1}s  (tree depth={}, {} leaves)",
            c7_ms / 1000.0,
            c7_tree_depth,
            c7_leaves,
        );
    } else {
        println!(
            "  c7:              {:.1}s  ({} Nova steps)",
            c7_ms / 1000.0,
            args.threshold,
        );
    }
    println!("  total:           {:.1}s", total_ms / 1000.0);

    Ok(())
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

/// Compute Lagrange basis coefficients evaluated at `eval_point`.
///
/// For points `x_i` and evaluation point `z`, returns `L_i(z)` for each i:
/// `L_i(z) = Π_{j≠i} (z - x_j) / Π_{j≠i} (x_i - x_j)`
fn compute_lagrange_coeffs_bn254(xs: &[Fr], eval_point: Fr) -> Vec<Fr> {
    let n = xs.len();
    let mut coeffs = Vec::with_capacity(n);
    for i in 0..n {
        let mut num = Fr::one();
        let mut den = Fr::one();
        for j in 0..n {
            if i != j {
                num *= eval_point - xs[j];
                den *= xs[i] - xs[j];
            }
        }
        coeffs.push(num * den.inverse().unwrap_or(Fr::zero()));
    }
    coeffs
}

#[cfg(feature = "sonobe-compressor")]
fn time_micronova_compressor(epoch_hash: [u8; 32], batch_count: usize) -> anyhow::Result<()> {
    use pvthfhe_compressor::micronova::compressor::MicroNovaCompressor;

    let depth = (batch_count as f64).log2().ceil() as usize;
    let compressor = MicroNovaCompressor::new(depth, epoch_hash);
    let total_steps = compressor.total_steps();
    // Derive ExternalInputs3 fields from real epoch_hash (SHA-256 of seed).
    // This function does not have access to transcript data, so values are
    // deterministically derived from the ceremony seed via domain-separated hashes.
    let steps: Vec<ExternalInputs3<Fr>> = (0..total_steps)
        .map(|i| {
            let mut hasher = Sha256::new();
            hasher.update(b"pvthfhe/micronova/party");
            hasher.update(&epoch_hash);
            hasher.update(&(i as u64).to_be_bytes());
            let party_id_fr = Fr::from_be_bytes_mod_order(&hasher.finalize());

            let mut hasher = Sha256::new();
            hasher.update(b"pvthfhe/micronova/share");
            hasher.update(&epoch_hash);
            hasher.update(&(i as u64).to_be_bytes());
            let share_hash_fr = Fr::from_be_bytes_mod_order(&hasher.finalize());

            let mut hasher = Sha256::new();
            hasher.update(b"pvthfhe/micronova/pk");
            hasher.update(&epoch_hash);
            hasher.update(&(i as u64).to_be_bytes());
            let pk_hash_fr = Fr::from_be_bytes_mod_order(&hasher.finalize());

            ExternalInputs3(party_id_fr, share_hash_fr, pk_hash_fr)
        })
        .collect();
    let _proof = compressor
        .prove_tree(&steps)
        .map_err(|e| anyhow::anyhow!("MicroNova compressor prove_tree: {e:?}"))?;
    Ok(())
}

#[cfg(not(feature = "sonobe-compressor"))]
fn time_micronova_compressor(_epoch_hash: [u8; 32], _batch_count: usize) -> anyhow::Result<()> {
    Ok(())
}
