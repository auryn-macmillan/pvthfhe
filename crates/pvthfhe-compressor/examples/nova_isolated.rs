//! Isolated Nova compressor reproducer for memory profiling (requires legacy-nova feature).

use std::fs;

#[cfg(feature = "legacy-nova")]
use ark_bn254::Fr;
#[cfg(feature = "legacy-nova")]
use pvthfhe_compressor::nova::{encode_triple, NovaCompressor, ToyStepCircuit};
#[cfg(feature = "legacy-nova")]
use pvthfhe_compressor::ProofCompressor;
#[cfg(feature = "legacy-nova")]
use sha2::{Digest, Sha256};
#[cfg(feature = "legacy-nova")]
use tracing_subscriber::EnvFilter;

#[cfg(feature = "legacy-nova")]
fn rss_kb() -> u64 {
    fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|statm| statm.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map(|pages| pages * 4)
        .unwrap_or(0)
}

#[cfg(feature = "legacy-nova")]
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
    let compressor = NovaCompressor::<ToyStepCircuit<Fr>>::new(epoch_hash, 4)
        .expect("construct nova compressor");
    peak_rss_kb = peak_rss_kb.max(rss_kb());
    println!("rss_kb stage=after_new value={}", peak_rss_kb);

    let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));
    let public_inputs = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));
    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove isolated nova");
    peak_rss_kb = peak_rss_kb.max(rss_kb());
    println!("rss_kb stage=after_prove value={}", peak_rss_kb);

    let verified = compressor
        .verify(&compressor.verifier_key(), &proof, &public_inputs)
        .expect("verify isolated nova");
    peak_rss_kb = peak_rss_kb.max(rss_kb());
    println!("rss_kb stage=after_verify value={}", peak_rss_kb);
    println!("verify_result={verified}");
    println!(
        "summary peak_rss_kb={} proof_bytes={}",
        peak_rss_kb,
        compressor.compressed_proof_bytes(&proof).len()
    );
}
