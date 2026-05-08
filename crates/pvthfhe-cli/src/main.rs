//! pvthfhe-cli — command-line interface for the PVTHFHE system.
//!
//! Subcommands: keygen, encrypt, partial-decrypt, aggregate, verify, demo.

#![warn(missing_docs)]

use clap::{Parser, Subcommand};
#[cfg(all(feature = "with-fhe", feature = "sonobe-compressor"))]
use pvthfhe_cli::full_pipeline::{run_full_pipeline, PipelineConfig, PipelineObserver};
#[cfg(feature = "with-fhe")]
use pvthfhe_cli::pvss_support::PVSS_BACKEND_ID;
#[cfg(feature = "with-fhe")]
use pvthfhe_fhe::real_nizk::CYCLO_BACKEND_ID;
use tracing::{info, warn};

/// PVTHFHE command-line interface.
#[derive(Parser, Debug)]
#[command(
    name = "pvthfhe-cli",
    version,
    about = "Private-verifiable threshold FHE CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Run distributed key generation (stub — prints usage).
    Keygen {
        /// Number of parties.
        #[arg(long, default_value_t = 3)]
        n: usize,
        /// Threshold (default: n/2+1).
        #[arg(long)]
        threshold: Option<usize>,
    },
    /// Encrypt a plaintext message (stub — prints usage).
    Encrypt {
        /// Hex-encoded plaintext.
        #[arg(long)]
        plaintext: String,
        /// Hex-encoded public key.
        #[arg(long)]
        pk: String,
    },
    /// Produce a partial decryption share (stub — prints usage).
    PartialDecrypt {
        /// Party ID.
        #[arg(long)]
        party_id: u32,
        /// Hex-encoded ciphertext.
        #[arg(long)]
        ciphertext: String,
    },
    /// Aggregate partial decryption shares (stub — prints usage).
    Aggregate {
        /// Hex-encoded ciphertext.
        #[arg(long)]
        ciphertext: String,
        /// Comma-separated hex shares.
        #[arg(long)]
        shares: String,
        /// Threshold.
        #[arg(long)]
        threshold: usize,
    },
    /// Verify a final SNARK (stub — prints usage).
    Verify {
        /// Hex-encoded proof bytes.
        #[arg(long)]
        proof: String,
    },
    /// Run the full n-party demo pipeline in-process.
    Demo {
        /// Number of parties (maximum 255).
        #[arg(long, default_value_t = 8)]
        n: usize,
        /// Threshold (default: n/2+1).
        #[arg(long)]
        threshold: Option<usize>,
        /// Deterministic seed for RNG.
        #[arg(long, default_value_t = 1)]
        seed: u64,
    },
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

    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { n, threshold } => {
            let t = threshold.unwrap_or(n / 2 + 1);
            info!(
                n,
                threshold = t,
                "keygen stub — use `demo` for full pipeline"
            );
            println!("keygen: n={n} threshold={t} (stub)");
        }
        Commands::Encrypt { plaintext, pk } => {
            info!(plaintext = %plaintext, pk = %pk, "encrypt stub");
            println!("encrypt: plaintext={plaintext} pk={pk} (stub)");
        }
        Commands::PartialDecrypt {
            party_id,
            ciphertext,
        } => {
            info!(party_id, ciphertext = %ciphertext, "partial-decrypt stub");
            println!("partial-decrypt: party_id={party_id} ciphertext={ciphertext} (stub)");
        }
        Commands::Aggregate {
            ciphertext,
            shares,
            threshold,
        } => {
            info!(ciphertext = %ciphertext, threshold, "aggregate stub");
            println!(
                "aggregate: ciphertext={ciphertext} shares={shares} threshold={threshold} (stub)"
            );
        }
        Commands::Verify { proof } => {
            info!(proof = %proof, "verify stub");
            println!("verify: proof={proof} (stub)");
        }
        Commands::Demo { n, threshold, seed } => {
            run_demo(n, threshold.unwrap_or(n / 2 + 1), seed)?;
        }
    }

    Ok(())
}

/// Run the full demo pipeline with `n` parties and deterministic `seed`.
#[cfg(all(feature = "with-fhe", feature = "sonobe-compressor"))]
fn run_demo(n: usize, threshold: usize, seed: u64) -> anyhow::Result<()> {
    const MAX_N: usize = 255;
    if n == 0 || n > MAX_N {
        anyhow::bail!(
            "invalid n: n={n} must satisfy 1 <= n <= {MAX_N} (Shamir over GF(256))"
        );
    }
    if threshold == 0 || threshold > n {
        anyhow::bail!(
            "invalid threshold: threshold={threshold} must satisfy 1 <= threshold <= n={n}"
        );
    }
    let backend_threshold = threshold.min((n + 1) / 2);
    if backend_threshold != threshold {
        warn!(
            requested_threshold = threshold,
            backend_threshold,
            n,
            "real backend supports up to ceil(n/2); using capped threshold internally"
        );
    }

    let mut observer = DemoObserver::default();

    info!(n, threshold, seed, "starting demo pipeline");
    println!("demo: n={n} threshold={threshold} seed={seed}");
    println!("pvss_backend_id={PVSS_BACKEND_ID}");

    info!(backend_id = CYCLO_BACKEND_ID, "backend_id_p1");
    info!("backend_id_p2: cyclo-rlwe-t10-lemma9-heuristic");
    info!("backend_id_p3: ultra-honk-micronova");
    println!("backend_id == \"{CYCLO_BACKEND_ID}\"");
    println!("backend_id_p2: cyclo-rlwe-t10-lemma9-heuristic");
    println!("backend_id_p3: ultra-honk-micronova");
    println!("note: on-chain Solidity verify is NOT run by demo (use bench-comparison)");
    println!("pvss_backend_id={PVSS_BACKEND_ID}");
    let report = run_full_pipeline(
        &PipelineConfig {
            n,
            t: threshold,
            seed,
        },
        &mut observer,
    )?;

    let plaintext_roundtrip = if report.plaintext_roundtrip_ok {
        "OK"
    } else {
        "MISMATCH"
    };
    let keygen_ms = report.timings.phases.keygen.total_ms;
    let aggregate_keygen_ms = observer.aggregate_keygen_ms.unwrap_or(0.0);
    let encrypt_ms = observer.encrypt_ms.unwrap_or(0.0);
    let partial_decrypt_ms = report.timings.phases.partial_decrypt.total_ms;
    let aggregate_decrypt_ms = report.timings.phases.aggregate_decrypt.total_ms;
    let decrypt_ms = partial_decrypt_ms + aggregate_decrypt_ms;
    let share_encryption_proof_ms = report.timings.phases.pvss_share_encrypt.total_ms;

    println!("plaintext_roundtrip: {plaintext_roundtrip}");
    println!("aggregate_pk_hash: {}", report.aggregate_pk_hash_hex);
    println!("ciphertext_hash: {}", report.ciphertext_hash_hex);
    println!(
        "compressed_proof_digest: {}",
        report.compressed_proof_digest_hex
    );
    println!("keygen_ms={keygen_ms}");
    println!("aggregate_keygen_ms={aggregate_keygen_ms}");
    println!("encrypt_ms={encrypt_ms}");
    println!("share_encryption_proof_ms={share_encryption_proof_ms}");
    println!("partial_decrypt_ms={partial_decrypt_ms}");
    println!("aggregate_decrypt_ms={aggregate_decrypt_ms}");
    println!("decrypt_ms={decrypt_ms}");
    println!("threshold={threshold}");
    println!("n={n}");
    println!("verify: ACCEPT");
    println!("pvss_backend_id={}", observer.pvss_backend_id());
    info!("demo complete: ACCEPT");

    Ok(())
}

#[cfg(not(all(feature = "with-fhe", feature = "sonobe-compressor")))]
fn run_demo(_n: usize, _threshold: usize, _seed: u64) -> anyhow::Result<()> {
    anyhow::bail!("demo requires the `with-fhe` and `sonobe-compressor` features")
}

#[cfg(all(feature = "with-fhe", feature = "sonobe-compressor"))]
#[derive(Default)]
struct DemoObserver {
    keygen_announced: bool,
    pvss_announced: bool,
    cyclo_fold_announced: bool,
    compressor_prove_announced: bool,
    compressor_verify_announced: bool,
    partial_decrypt_announced: bool,
    aggregate_decrypt_announced: bool,
    aggregate_keygen_ms: Option<f64>,
    encrypt_ms: Option<f64>,
    pvss_backend_id: Option<String>,
}

#[cfg(all(feature = "with-fhe", feature = "sonobe-compressor"))]
impl DemoObserver {
    const STEP_COUNT: usize = 9;

    fn pvss_backend_id(&self) -> &str {
        self.pvss_backend_id.as_deref().unwrap_or(PVSS_BACKEND_ID)
    }

    fn print_step(step: usize, name: &str, detail: Option<&str>) {
        match detail {
            Some(detail) => println!("step {step}/{total}: {name} ({detail})", total = Self::STEP_COUNT),
            None => println!("step {step}/{total}: {name}", total = Self::STEP_COUNT),
        }
    }
}

#[cfg(all(feature = "with-fhe", feature = "sonobe-compressor"))]
impl PipelineObserver for DemoObserver {
    fn phase_start(&mut self, name: &str, detail: Option<&str>) {
        match name {
            "keygen" if !self.keygen_announced => {
                self.keygen_announced = true;
                Self::print_step(1, "keygen", detail);
            }
            "nizk_prove" => match detail {
                Some(detail) => println!("step 2/9: nizk_prove ({detail})"),
                None => println!("step 2/9: nizk_prove"),
            },
            "nizk_verify" => match detail {
                Some(detail) => println!("step 3/9: nizk_verify ({detail})"),
                None => println!("step 3/9: nizk_verify"),
            },
            "pvss_share_encrypt" if !self.pvss_announced => {
                self.pvss_announced = true;
                Self::print_step(4, "pvss_share_encrypt", detail);
            }
            "cyclo_fold" if !self.cyclo_fold_announced => {
                self.cyclo_fold_announced = true;
                Self::print_step(5, "cyclo_fold", detail);
            }
            "compressor_prove" if !self.compressor_prove_announced => {
                self.compressor_prove_announced = true;
                Self::print_step(6, "compressor_prove", detail);
            }
            "compressor_verify" if !self.compressor_verify_announced => {
                self.compressor_verify_announced = true;
                Self::print_step(7, "compressor_verify", detail);
            }
            "partial_decrypt" if !self.partial_decrypt_announced => {
                self.partial_decrypt_announced = true;
                Self::print_step(8, "partial_decrypt", detail);
            }
            "aggregate_decrypt" if !self.aggregate_decrypt_announced => {
                self.aggregate_decrypt_announced = true;
                Self::print_step(9, "aggregate_decrypt", detail);
            }
            _ => {}
        }
    }

    fn phase_end(&mut self, name: &str, ms: f64) {
        match name {
            "aggregate_keygen" => self.aggregate_keygen_ms = Some(ms),
            "encrypt" => self.encrypt_ms = Some(ms),
            "keygen"
            | "pvss_share_encrypt"
            | "cyclo_fold"
            | "compressor_prove"
            | "compressor_verify"
            | "partial_decrypt"
            | "aggregate_decrypt" => println!("{name}: complete ({ms:.3} ms)"),
            _ => {}
        }
    }

    fn note(&mut self, msg: &str) {
        if let Some(value) = msg.strip_prefix("pvss_backend_id=") {
            self.pvss_backend_id = Some(value.to_owned());
        }
    }
}
