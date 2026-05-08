//! Minimal Sonobe compressor reproducer for memory profiling.
//! Run: cargo run --release -p pvthfhe-cli --bin sonobe-min
//! Captures RSS at each stage and prints to stdout.

use std::fs;

use pvthfhe_compressor::{sonobe::SonobeCompressor, ProofCompressor};
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

    let compressor = SonobeCompressor::new(1).expect("construct sonobe compressor");
    peak_rss_kb = peak_rss_kb.max(rss_kb());
    println!("rss_kb stage=after_new value={peak_rss_kb}");

    let _vk = compressor.verifier_key();
    let _ = compressor.vk_bytes();
    peak_rss_kb = peak_rss_kb.max(rss_kb());
    println!("rss_kb stage=after_vk value={peak_rss_kb}");
}
