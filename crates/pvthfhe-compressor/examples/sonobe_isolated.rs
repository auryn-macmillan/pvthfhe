//! Isolated Sonobe compressor reproducer for memory profiling.
//! Run: cargo run --release --example sonobe_isolated -p pvthfhe-compressor
//! Captures RSS at each stage and prints to stdout.

use std::fs;

use ark_bn254::Fr;
use pvthfhe_compressor::sonobe::{encode_triple, SonobeCompressor, ToyStepCircuit};
use pvthfhe_compressor::ProofCompressor;
use sha2::{Digest, Sha256};
use tracing_subscriber::EnvFilter;

fn rss_kb() -> u64 {
    fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|statm| statm.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map(|pages| pages * 4)
        .unwrap_or(0)
}

fn main() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("pvthfhe_compressor=info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .try_init();

    let mut peak_rss_kb = rss_kb();
    println!("rss_kb stage=before_new value={peak_rss_kb}");

    const SEED: u64 = 0x736f6e6f62655f6d;
    let seed_bytes = SEED.to_be_bytes();
    let epoch_hash: [u8; 32] = Sha256::digest(&seed_bytes).into();
    let compressor = SonobeCompressor::<ToyStepCircuit<Fr>>::new(epoch_hash, 4)
        .expect("construct sonobe compressor");
    peak_rss_kb = peak_rss_kb.max(rss_kb());
    println!("rss_kb stage=after_new value={}", peak_rss_kb);

    let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));
    let public_inputs = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));
    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove isolated sonobe");
    peak_rss_kb = peak_rss_kb.max(rss_kb());
    println!("rss_kb stage=after_prove value={}", peak_rss_kb);

    let verified = compressor
        .verify(&compressor.verifier_key(), &proof, &public_inputs)
        .expect("verify isolated sonobe");
    peak_rss_kb = peak_rss_kb.max(rss_kb());
    println!("rss_kb stage=after_verify value={}", peak_rss_kb);
    println!("verify_result={verified}");
    println!(
        "summary peak_rss_kb={} proof_bytes={}",
        peak_rss_kb,
        compressor.compressed_proof_bytes(&proof).len()
    );
}
