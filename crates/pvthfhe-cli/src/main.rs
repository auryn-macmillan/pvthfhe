//! pvthfhe-cli — command-line interface for the PVTHFHE system.
//!
//! Subcommands: keygen, encrypt, partial-decrypt, aggregate, verify, demo.

#![warn(missing_docs)]

use anyhow::Context;
use clap::{Parser, Subcommand};
#[cfg(all(feature = "with-fhe", feature = "sonobe-compressor"))]
use pvthfhe_cli::compressor_glue::compressor_backend_id;
#[cfg(all(feature = "with-fhe", feature = "sonobe-compressor"))]
use pvthfhe_cli::full_pipeline::{run_full_pipeline, PipelineConfig, PipelineObserver};
#[cfg(feature = "with-fhe")]
use pvthfhe_cli::pvss_support::PVSS_BACKEND_ID;
#[cfg(feature = "with-fhe")]
use pvthfhe_cyclo::CYCLO_BACKEND_ID as CYCLO_P2_BACKEND_ID;
#[cfg(feature = "with-fhe")]
use pvthfhe_fhe::real_nizk::CYCLO_BACKEND_ID;
use tracing::info;
#[cfg(feature = "with-fhe")]
use {
    pvthfhe_fhe::{fhers::FhersBackend, FheBackend, PublicKey},
    pvthfhe_keygen::dkg::{DkgCeremony, DkgParams},
    pvthfhe_rng::OsRng,
    rand_core::RngCore,
};

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
        /// Number of parties (tested up to 230, soft cap for noise budget).
        #[arg(long, default_value_t = 8)]
        n: usize,
        /// Threshold (default: n/2+1).
        #[arg(long)]
        threshold: Option<usize>,
        /// Deterministic seed for RNG.
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Bypass the n ≤ 230 soft cap (large parties may exceed noise budget).
        #[arg(long, default_value_t = false)]
        force_large_n: bool,
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
            r8_keygen(n, t)?;
        }
        Commands::Encrypt { plaintext, pk } => {
            r8_encrypt(&plaintext, &pk)?;
        }
        Commands::PartialDecrypt {
            party_id,
            ciphertext,
        } => {
            r8_partial_decrypt(party_id, &ciphertext)?;
        }
        Commands::Aggregate {
            ciphertext,
            shares,
            threshold,
        } => {
            r8_aggregate(&ciphertext, &shares, threshold)?;
        }
        Commands::Verify { proof } => {
            // Planned: --verify-only mode will read public artifacts (aggregate_pk,
            // ciphertext, compressed_proof, dkg transcript) from disk and run all
            // NIZK verifications + fold verification + compressor verification
            // without requiring secret key material, then print verify: ACCEPT/REJECT.
            // This enables a third-party verifier role with only public data.
            // Dependencies: share_computation verifier (batch D.2), dkg_aggregation
            // verifier (batch D.2), and artifact serialization (TBD).
            info!(proof = %proof, "verify stub — real HonkVerifier not yet integrated");
            println!("verify: proof={proof} (stub)");
        }
        Commands::Demo { n, threshold, seed, force_large_n } => {
            run_demo(n, threshold.unwrap_or(n / 2 + 1), seed, force_large_n)?;
        }
    }

    Ok(())
}

/// Real keygen subcommand — runs a DKG ceremony and prints the public key.
#[cfg(feature = "with-fhe")]
fn r8_keygen(n: usize, threshold: usize) -> anyhow::Result<()> {
    info!(n, threshold, "keygen: running DKG ceremony");
    let mut dkg = DkgCeremony::new(DkgParams { n, t: threshold })?;
    dkg.run()?;
    let pk = dkg.public_key()?;
    let pk_hex = hex::encode(&pk.bytes);
    println!("keygen: public_key_hex={pk_hex}");
    println!("keygen: n={n} threshold={threshold} ok");
    Ok(())
}

/// Real encrypt subcommand — encrypts plaintext with the given public key.
#[cfg(feature = "with-fhe")]
fn r8_encrypt(plaintext_hex: &str, pk_hex: &str) -> anyhow::Result<()> {
    let plaintext = hex::decode(plaintext_hex).context("invalid plaintext hex")?;
    let pk_bytes = hex::decode(pk_hex).context("invalid pk hex")?;

    let backend = FhersBackend::load_params(
        "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n"
    ).context("backend init")?;

    let pk = PublicKey { bytes: pk_bytes };
    let mut rng = OsRng;
    let ct = backend
        .encrypt(&pk, &plaintext, &mut rng)
        .context("encrypt")?;
    let ct_hex = hex::encode(&ct.bytes);
    println!("encrypt: ciphertext_hex={ct_hex}");
    Ok(())
}

/// Real partial-decrypt subcommand — runs a self-contained mini-keygen
/// and produces a partial decryption share for the given party.
#[cfg(feature = "with-fhe")]
fn r8_partial_decrypt(party_id: u32, ciphertext_hex: &str) -> anyhow::Result<()> {
    let ct_bytes = hex::decode(ciphertext_hex).context("invalid ciphertext hex")?;

    let backend = FhersBackend::load_params(
        "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n"
    ).context("backend init")?;

    let n: usize = 3;
    let t: usize = 2;
    let mut session_id = [0u8; 32];
    OsRng.fill_bytes(&mut session_id);

    let mut keygen_shares = Vec::with_capacity(n);
    for pid in 1u32..=n as u32 {
        let share = backend
            .keygen_share_with_session(&session_id, pid, &mut OsRng)
            .context("keygen share")?;
        keygen_shares.push(share);
    }
    backend.setup_threshold(n, t).context("setup_threshold")?;

    let ct = pvthfhe_fhe::Ciphertext { bytes: ct_bytes };
    let mut rng = OsRng;
    let share = backend
        .partial_decrypt(&ct, party_id, &mut rng)
        .with_context(|| format!("partial_decrypt party {party_id}"))?;
    let share_hex = hex::encode(share.bytes.as_slice());
    println!("partial-decrypt: party_id={party_id} share_hex={share_hex}");
    Ok(())
}

/// Real aggregate subcommand — runs a self-contained mini-keygen
/// and aggregates partial decryption shares.
#[cfg(feature = "with-fhe")]
fn r8_aggregate(ciphertext_hex: &str, shares_hex: &str, threshold: usize) -> anyhow::Result<()> {
    let ct_bytes = hex::decode(ciphertext_hex).context("invalid ciphertext hex")?;
    let share_hex_list: Vec<&str> = shares_hex.split(',').collect();

    let backend = FhersBackend::load_params(
        "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n"
    ).context("backend init")?;

    let n: usize = 3;
    let t: usize = 2;
    let mut session_id = [0u8; 32];
    OsRng.fill_bytes(&mut session_id);

    let mut keygen_shares = Vec::with_capacity(n);
    for pid in 1u32..=n as u32 {
        let share = backend
            .keygen_share_with_session(&session_id, pid, &mut OsRng)
            .context("keygen share")?;
        keygen_shares.push(share);
    }
    backend.setup_threshold(n, t).context("setup_threshold")?;

    let mut shares = Vec::with_capacity(share_hex_list.len());
    for (i, hex_str) in share_hex_list.iter().enumerate() {
        let share_bytes = hex::decode(hex_str.trim())
            .with_context(|| format!("invalid share hex at index {i}"))?;
        shares.push(pvthfhe_fhe::DecryptShare {
            party_id: (i + 1) as u32,
            bytes: pvthfhe_types::ProtocolBytes(share_bytes),
            nizk_proof_bytes: None,
        });
    }

    let ct = pvthfhe_fhe::Ciphertext { bytes: ct_bytes };
    let plaintext = backend
        .aggregate_decrypt(&ct, &shares, threshold)
        .context("aggregate_decrypt")?;
    let plaintext_hex = hex::encode(&plaintext);
    println!("aggregate: plaintext_hex={plaintext_hex}");
    Ok(())
}

/// Run the full demo pipeline with `n` parties and deterministic `seed`.
#[cfg(all(feature = "with-fhe", feature = "sonobe-compressor"))]
fn run_demo(n: usize, threshold: usize, seed: u64, force_large_n: bool) -> anyhow::Result<()> {
    const MAX_N: usize = 255;
    const SOFT_CAP_N: usize = 230;
    if n == 0 || n > MAX_N {
        anyhow::bail!("invalid n: n={n} must satisfy 1 <= n <= {MAX_N} (Shamir over GF(256))");
    }
    if n > SOFT_CAP_N && !force_large_n {
        anyhow::bail!(
            "soft cap: n={n} > {SOFT_CAP_N} — untested, may exceed BFV noise budget for decryption. Re-run with --force-large-n to proceed at your own risk."
        );
    }
    if threshold == 0 || threshold > n {
        anyhow::bail!(
            "invalid threshold: threshold={threshold} must satisfy 1 <= threshold <= n={n}"
        );
    }
    let max_t = (n - 1) / 2;
    if threshold > max_t {
        anyhow::bail!(
            "the upstream fhe.rs backend requires threshold t <= (n-1)/2; for n={} maximum t is {}",
            n,
            max_t
        );
    }
    let mut observer = DemoObserver::default();

    info!(n, threshold, seed, "starting demo pipeline");
    println!("demo: n={n} threshold={threshold} seed={seed}");
    println!("pvss_backend_id={PVSS_BACKEND_ID}");

    info!(backend_id = CYCLO_BACKEND_ID, "backend_id_p1");
    info!(backend_id_p2 = CYCLO_P2_BACKEND_ID, "backend_id_p2");
    info!(backend_id_p3 = compressor_backend_id(), "backend_id_p3");
    println!("backend_id == \"{CYCLO_BACKEND_ID}\"");
    println!("backend_id_p2: {CYCLO_P2_BACKEND_ID}");
    println!("backend_id_p3: {}", compressor_backend_id());
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
    if report.all_verifications_passed {
        println!("verify: ACCEPT");
        info!("demo complete: ACCEPT");
    } else {
        println!("verify: REJECT");
        info!("demo complete: REJECT");
    }
    println!("pvss_backend_id={}", observer.pvss_backend_id());

    Ok(())
}

#[cfg(not(all(feature = "with-fhe", feature = "sonobe-compressor")))]
fn run_demo(_n: usize, _threshold: usize, _seed: u64, _force_large_n: bool) -> anyhow::Result<()> {
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
            Some(detail) => println!(
                "step {step}/{total}: {name} ({detail})",
                total = Self::STEP_COUNT
            ),
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
            "c7_decrypt_aggregation" => {
                Self::print_step(10, "c7_decrypt_aggregation", detail);
            }
            _ => {}
        }
    }

    fn phase_end(&mut self, name: &str, ms: f64) {
        match name {
            "aggregate_keygen" => self.aggregate_keygen_ms = Some(ms),
            "encrypt" => self.encrypt_ms = Some(ms),
            "keygen" | "pvss_share_encrypt" | "cyclo_fold" | "compressor_prove"
            | "compressor_verify" | "partial_decrypt" | "aggregate_decrypt"
            | "c7_decrypt_aggregation" => {
                println!("{name}: complete ({ms:.3} ms)")
            }
            _ => {}
        }
    }

    fn note(&mut self, msg: &str) {
        if let Some(value) = msg.strip_prefix("pvss_backend_id=") {
            self.pvss_backend_id = Some(value.to_owned());
        }
    }
}
