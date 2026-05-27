//! Minimal Nova compressor reproducer for memory profiling.
//! Run: cargo run --release -p pvthfhe-cli --bin nova-min
//! Captures RSS at each stage and prints to stdout.

use std::fs;

use ark_bn254::Fr;
use pvthfhe_compressor::nova::{NovaCompressor, ToyStepCircuit};
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
    let _compressor = NovaCompressor::<ToyStepCircuit<Fr>>::new(epoch_hash, 4)
        .expect("construct nova compressor");
    peak_rss_kb = peak_rss_kb.max(rss_kb());
    println!("rss_kb stage=after_new value={peak_rss_kb}");
}
