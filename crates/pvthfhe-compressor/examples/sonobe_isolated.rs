//! Isolated Sonobe compressor reproducer for memory profiling.
//! Run: cargo run --release --example sonobe_isolated -p pvthfhe-compressor
//! Captures RSS at each stage and prints to stdout.

use std::fs;

use pvthfhe_compressor::sonobe::{SonobeCompressor, ToyStepCircuit};
use pvthfhe_compressor::ProofCompressor;
use ark_bn254::Fr;
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

    let epoch_hash = [0u8; 32];
    let compressor =
        SonobeCompressor::<ToyStepCircuit<Fr>>::new(epoch_hash, 4).expect("construct sonobe compressor");
    peak_rss_kb = peak_rss_kb.max(rss_kb());
    println!("rss_kb stage=after_new value={}", peak_rss_kb);

    let acc = [0u8; 32];
    let public_inputs = [0u8; 32];
    let proof = compressor.prove(&acc, &public_inputs).expect("prove isolated sonobe");
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
