//! Aggregator scaling simulation — Track A (Nova) removed per P4 deprecation.
//!
//! This binary previously benchmarked Nova compressor + Cyclo fold steps.
//! With Track A removed, use `just aggregator` or the LatticeFold+ path
//! via `--features enable-latticefold` from main.rs.

use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "10")]
    n: usize,
    #[arg(long, default_value = "4")]
    threshold: usize,
    #[arg(long, default_value = "1")]
    seed: u64,
}

fn main() {
    let args = Args::parse();
    eprintln!(
        "per-aggregator: Track A (Nova BN254+Grumpkin) removed.\n\
         Use LatticeFold+ (Track B) via `just demo-e2e n={} t={} seed={}`\n\
         or `cargo run --release -p pvthfhe-cli --features enable-latticefold -- demo --n {} --threshold {} --seed {}`",
        args.n, args.threshold, args.seed,
        args.n, args.threshold, args.seed,
    );
}
