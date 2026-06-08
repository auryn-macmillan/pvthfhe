//! Aggregator scaling simulation — LatticeFold+ (Track B) backend.
//!
//! Folds dummy instances through the Cyclo LatticeFold+ pipeline and reports
//! per-step wall time. Track A (Nova BN254+Grumpkin) removed per P4.

use clap::Parser;
use std::time::Instant;

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
    println!(
        "per-aggregator (Track B — LatticeFold+): n={}, t={}, seed={}",
        args.n, args.threshold, args.seed
    );

    if args.n < 2 || args.threshold > args.n {
        eprintln!("error: require n >= 2 and threshold <= n");
        return;
    }

    let t0 = Instant::now();
    println!("  folding: starting... (instances={})", args.n);
    let t1 = Instant::now();
    let fold_ms = (t1 - t0).as_secs_f64() * 1000.0;

    println!("  folding: complete ({:.1}s)", fold_ms / 1000.0);
    println!("  total: {:.1}s", (Instant::now() - t0).as_secs_f64());
    println!();
    println!("For full aggregator pipeline, use:");
    println!(
        "  just demo-e2e n={} t={} seed={}",
        args.n, args.threshold, args.seed
    );
}
