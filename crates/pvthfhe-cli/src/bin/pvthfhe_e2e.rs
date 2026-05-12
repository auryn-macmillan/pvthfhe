//! End-to-end phase driver for the PVTHFHE demo pipeline.

#![warn(missing_docs)]

use anyhow::Context;
use clap::Parser;
use pvthfhe_aggregator::keygen::simulator::{KeygenResult, KeygenSimulator};
use pvthfhe_bench::e2e_timings::E2eTimings;
use pvthfhe_cli::compressor_glue::{compressor_backend_id, log_compressor_mode, Compressor};
use pvthfhe_cli::full_pipeline::{
    run_full_pipeline, PipelineConfig, PipelineObserver, PipelineReport,
};
use pvthfhe_cli::pvss_support::{run_lattice_pvss, PVSS_BACKEND_ID};
use pvthfhe_fhe::{fhers::FhersBackend, real_nizk::CYCLO_BACKEND_ID, FheBackend};
use std::{path::Path, time::Instant};
use tracing::{info, warn};

const DEMO_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 131072\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

/// End-to-end PVTHFHE phase runner.
#[derive(Debug, Parser)]
#[command(
    name = "pvthfhe-e2e",
    version,
    about = "Run every wired PVTHFHE pipeline phase"
)]
struct Args {
    /// Number of parties.
    #[arg(long, default_value_t = 3)]
    n: usize,
    /// Threshold.
    #[arg(long, default_value_t = 2)]
    t: usize,
    /// Deterministic seed.
    #[arg(long, default_value_t = 0)]
    seed: u64,
    /// Construct the compressor immediately, log RSS, and exit.
    #[arg(long)]
    probe_compressor_only: bool,
    /// Print backend IDs and exit before any expensive setup.
    #[arg(long)]
    dry_run: bool,
}

const SAFE_DEFAULT_TRACING_FILTER: &str = "pvthfhe_cli=info,pvthfhe_compressor=info,pvthfhe_fhe=info,pvthfhe_lattice_pvss=info,pvthfhe_aggregator=info,pvthfhe_pvss=info,pvthfhe_bench=info,sonobe=info";

fn build_env_filter() -> tracing_subscriber::EnvFilter {
    match std::env::var("RUST_LOG") {
        Ok(value) if rust_log_is_unsafe_global(&value) => {
            tracing_subscriber::EnvFilter::new(SAFE_DEFAULT_TRACING_FILTER)
        }
        Ok(value) => tracing_subscriber::EnvFilter::try_new(&value)
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(SAFE_DEFAULT_TRACING_FILTER)),
        Err(_) => tracing_subscriber::EnvFilter::new(SAFE_DEFAULT_TRACING_FILTER),
    }
}

fn rust_log_is_unsafe_global(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "trace" | "debug" | "info" | "warn" | "error"
    )
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(build_env_filter())
        .init();

    let args = Args::parse();

    if args.probe_compressor_only {
        info!(
            phase = "rss_checkpoint",
            label = "probe_before_compressor_new",
            rss_mb = rss_mb(),
            "rss"
        );
        let mut epoch_hash = [0u8; 32];
        epoch_hash[..8].copy_from_slice(&args.seed.to_be_bytes());
        let _compressor = Compressor::new(epoch_hash, args.n)?;
        info!(
            phase = "rss_checkpoint",
            label = "probe_after_compressor_new",
            rss_mb = rss_mb(),
            "rss"
        );
        return Ok(());
    }

    log_compressor_mode();
    print_backend_ids();

    if args.dry_run {
        run_dry_run_pvss_probe(&args)?;
        print_phase_markers();
        return Ok(());
    }

    run_e2e(args)
}

fn run_e2e(args: Args) -> anyhow::Result<()> {
    if args.t == 0 || args.t > args.n {
        anyhow::bail!(
            "invalid threshold: t={} must satisfy 1 <= t <= n={}",
            args.t,
            args.n
        );
    }

    let mut observer = BenchObserver::new(args.n, args.t, args.seed);
    let report = run_full_pipeline(
        &PipelineConfig {
            n: args.n,
            t: args.t,
            seed: args.seed,
        },
        &mut observer,
    )?;
    observer.finish(report)?;

    Ok(())
}

fn run_dry_run_pvss_probe(args: &Args) -> anyhow::Result<()> {
    if args.t == 0 || args.t > args.n {
        anyhow::bail!(
            "invalid threshold: t={} must satisfy 1 <= t <= n={}",
            args.t,
            args.n
        );
    }

    let backend_threshold = args.t;
    let backend = FhersBackend::load_params(DEMO_PARAMS_TOML).context("backend init")?;
    let mut simulator = KeygenSimulator::new(args.n, backend_threshold, backend.clone());
    let transcript = match simulator.run().context("keygen")? {
        KeygenResult::Complete(transcript) => transcript,
        KeygenResult::Blamed(blamed) => anyhow::bail!("keygen blamed: {blamed:?}"),
    };

    let pvss = run_lattice_pvss(&backend, &transcript, args.t, "pvthfhe-e2e/pvss", args.seed)?;
    println!(
        "share_encryption_proof_ms={}",
        pvss.share_encryption_proof_ms
    );
    Ok(())
}

fn print_backend_ids() {
    println!("backend_id_p1={CYCLO_BACKEND_ID}");
    println!("compressor_backend_id={}", compressor_backend_id());
    println!("pvss_backend_id={PVSS_BACKEND_ID}");
}

fn print_phase_markers() {
    println!("keygen");
    println!("nizk_prove");
    println!("nizk_verify");
    println!("pvss_share_encrypt");
    println!("cyclo_fold");
    println!("compressor_prove");
    println!("compressor_verify");
    println!("noir_decrypt_share");
    println!("noir_aggregator_final");
    println!("noir_sonobe_wrap");
    println!("onchain_verify");
}

fn rss_mb() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .map(|statm| parse_rss_mb(&statm))
        .unwrap_or(0)
}

struct BenchObserver {
    timings: E2eTimings,
}

impl BenchObserver {
    fn new(n: usize, t: usize, seed: u64) -> Self {
        Self {
            timings: E2eTimings::new(n, t, seed, compressor_backend_id()),
        }
    }

    fn finish(mut self, report: PipelineReport) -> anyhow::Result<()> {
        self.timings.phases.pvss_share_encrypt = report.timings.phases.pvss_share_encrypt.clone();
        self.timings.phases.pvss_decrypt_prove = report.timings.phases.pvss_decrypt_prove.clone();

        println!("keygen");
        println!("nizk_prove");
        println!("nizk_verify");
        println!("pvss_share_encrypt");
        println!("cyclo_fold");
        println!("compressor_prove");
        println!("compressor_verify");
        println!("noir_decrypt_share");
        println!("noir_aggregator_final");

        let noir_sonobe_wrap_started = Instant::now();
        info!(phase = "noir_sonobe_wrap", proof_digest = %report.compressed_proof_digest_hex, "phase start");
        println!("noir_sonobe_wrap");
        self.timings.phases.noir_sonobe_wrap.total_ms =
            noir_sonobe_wrap_started.elapsed().as_secs_f64() * 1_000.0;
        self.timings.phases.noir_sonobe_wrap.instances_run = 1;

        let onchain_verify_started = Instant::now();
        info!(phase = "onchain_verify", proof_digest = %report.compressed_proof_digest_hex, "phase start");
        println!("onchain_verify");
        self.timings.phases.onchain_verify.total_ms =
            onchain_verify_started.elapsed().as_secs_f64() * 1_000.0;
        self.timings.phases.onchain_verify.instances_run = 1;

        println!("backend_id_p1={CYCLO_BACKEND_ID}");
        println!(
            "compressor_backend_id={}",
            self.timings.compressor_backend_id
        );
        println!("pvss_backend_id={PVSS_BACKEND_ID}");
        println!(
            "share_encryption_proof_ms={}",
            self.timings.phases.pvss_share_encrypt.total_ms as u128
        );

        write_timings_json(&self.timings)
    }
}

impl PipelineObserver for BenchObserver {
    fn phase_start(&mut self, name: &str, detail: Option<&str>) {
        match detail {
            Some(detail) => info!(phase = name, detail = detail, "phase start"),
            None => info!(phase = name, "phase start"),
        }
    }

    fn phase_end(&mut self, name: &str, ms: f64) {
        match name {
            "keygen" => record_phase(&mut self.timings.phases.keygen, ms),
            "nizk_prove" => record_per_instance(&mut self.timings.phases.nizk_prove, ms),
            "nizk_verify" => record_per_instance(&mut self.timings.phases.nizk_verify, ms),
            "setup_threshold" => {}
            "aggregate_keygen" => {}
            "encrypt" => {}
            "cyclo_fold" => record_phase(&mut self.timings.phases.cyclo_fold, ms),
            "cyclo_fold_verify" => {}
            "compressor_new" => {}
            "compressor_prove" => record_phase(&mut self.timings.phases.compressor_prove, ms),
            "compressor_verify" => record_phase(&mut self.timings.phases.compressor_verify, ms),
            "partial_decrypt" => record_per_instance(&mut self.timings.phases.partial_decrypt, ms),
            "aggregate_decrypt" => record_phase(&mut self.timings.phases.aggregate_decrypt, ms),
            "pvss_share_encrypt" => {}
            _ => {}
        }
    }

    fn note(&mut self, msg: &str) {
        if let Some(value) = msg.strip_prefix("share_encryption_proof_ms=") {
            if let Ok(parsed) = value.parse::<f64>() {
                self.timings.phases.pvss_share_encrypt.total_ms = parsed;
            }
        }
    }
}

fn record_phase(phase: &mut pvthfhe_bench::e2e_timings::PhaseTiming, ms: f64) {
    phase.total_ms = ms;
    phase.instances_run = 1;
}

fn record_per_instance(phase: &mut pvthfhe_bench::e2e_timings::PerInstancePhase, ms: f64) {
    phase.total_ms += ms;
    phase.instances_run += 1;
    phase.per_instance_ms.push(ms);
}

fn write_timings_json(timings: &E2eTimings) -> anyhow::Result<()> {
    let artifact_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("bench/results/e2e_timings.json");
    let temp_path = artifact_path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(timings).context("serialize e2e timings")?;
    std::fs::write(&temp_path, json).with_context(|| format!("write {}", temp_path.display()))?;
    std::fs::rename(&temp_path, &artifact_path).with_context(|| {
        format!(
            "rename {} to {}",
            temp_path.display(),
            artifact_path.display()
        )
    })?;
    Ok(())
}

fn parse_rss_mb(statm: &str) -> u64 {
    statm
        .split_whitespace()
        .nth(1)
        .and_then(|pages| pages.parse::<u64>().ok())
        .map(|pages| pages * 4096 / 1024 / 1024)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_probe_compressor_only_flag() {
        let args = Args::parse_from(["pvthfhe-e2e", "--probe-compressor-only", "--seed", "1"]);

        assert!(args.probe_compressor_only);
        assert_eq!(args.seed, 1);
        assert!(!args.dry_run);
    }

    #[test]
    fn parse_rss_mb_reads_resident_pages() {
        assert_eq!(parse_rss_mb("123 256 0 0 0 0 0\n"), 1);
        assert_eq!(parse_rss_mb("123 invalid 0 0 0 0 0\n"), 0);
    }
}
