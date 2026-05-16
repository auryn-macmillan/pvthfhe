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
use clap::Parser;
use pvthfhe_aggregator::keygen::simulator::{KeygenResult, KeygenSimulator};
use pvthfhe_fhe::fhers::FhersBackend;
use pvthfhe_fhe::FheBackend;
use pvthfhe_rng::OsRng;
use sha2::{Digest, Sha256};
use std::time::Instant;

#[cfg(feature = "sonobe-compressor")]
use {
    pvthfhe_compressor::sonobe::{
        encode_triple, C7DecryptAggregationCircuit, CycloFoldStepCircuit,
        ExternalInputs3, SonobeCompressor,
    },
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
}

fn main() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::init();
    let args = Args::parse();

    if args.threshold == 0 || args.threshold > args.n {
        anyhow::bail!(
            "threshold must satisfy 1 ≤ t ≤ n (got t={}, n={})",
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

    // ── Setup: run keygen for n parties, aggregate PK, encrypt ──────────
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
    let batch_count = args.n.div_ceil(10);

    // ── 1. Compressor: fold ceil(n/10) accumulators via Nova ────────────
    #[cfg(feature = "sonobe-compressor")]
    let compressor_ms = {
        let t0 = Instant::now();
        let compressor =
            SonobeCompressor::<CycloFoldStepCircuit<Fr>>::new(epoch_hash, batch_count)
                .map_err(|e| anyhow::anyhow!("compressor init: {e:?}"))?;
        let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));
        let steps: Vec<ExternalInputs3<Fr>> = (0..batch_count)
            .map(|i| {
                ExternalInputs3(
                    Fr::from((i + 1) as u64),
                    Fr::from(1u64),
                    Fr::from(1u64),
                )
            })
            .collect();
        let _prove_result = compressor
            .prove_steps(&acc, &steps)
            .map_err(|e| anyhow::anyhow!("compressor prove_steps: {e:?}"))?;
        elapsed_ms(t0)
    };
    #[cfg(not(feature = "sonobe-compressor"))]
    let compressor_ms = 0.0;

    // ── 2. Aggregate decrypt: NTT over t shares ────────────────────────
    let t1 = Instant::now();
    let _recovered = backend
        .aggregate_decrypt(
            &ciphertext,
            &shares,
            args.threshold,
            &session_id_bytes,
        )
        .context("aggregate_decrypt")?;
    let aggregate_ms = elapsed_ms(t1);

    // ── 3. C7: t Nova steps for Lagrange folding ───────────────────────
    #[cfg(feature = "sonobe-compressor")]
    let c7_ms = {
        let t2 = Instant::now();
        let c7_compressor =
            SonobeCompressor::<C7DecryptAggregationCircuit<Fr>>::new(
                epoch_hash,
                args.threshold,
            )
            .map_err(|e| anyhow::anyhow!("C7 compressor init: {e:?}"))?;
        let c7_acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));
        let c7_steps: Vec<ExternalInputs3<Fr>> = (0..args.threshold)
            .map(|i| {
                ExternalInputs3(
                    Fr::from((42 + i) as u64),
                    Fr::from(1u64),
                    Fr::from(0u64),
                )
            })
            .collect();
        let _c7_result = c7_compressor
            .prove_steps(&c7_acc, &c7_steps)
            .map_err(|e| anyhow::anyhow!("C7 prove_steps: {e:?}"))?;
        elapsed_ms(t2)
    };
    #[cfg(not(feature = "sonobe-compressor"))]
    let c7_ms = 0.0;

    // ── Report ─────────────────────────────────────────────────────────
    let total_ms = compressor_ms + aggregate_ms + c7_ms;

    println!("aggregator n={} t={}", args.n, args.threshold);
    println!(
        "  compressor:      {:.1}s  ({} batched steps, ceil(n/10))",
        compressor_ms / 1000.0,
        batch_count,
    );
    println!(
        "  aggregate_decrypt: {:.1}s  ({} NTT operations)",
        aggregate_ms / 1000.0,
        args.threshold,
    );
    println!(
        "  c7:              {:.1}s  ({} Nova steps)",
        c7_ms / 1000.0,
        args.threshold,
    );
    println!("  total:           {:.1}s", total_ms / 1000.0);

    Ok(())
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}
