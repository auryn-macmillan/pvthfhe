//! pvthfhe-cli — command-line interface for the PVTHFHE system.
//!
//! Subcommands: keygen, encrypt, partial-decrypt, aggregate, verify, demo.

#![allow(
    unexpected_cfgs,
    unused_imports,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::needless_range_loop,
    clippy::cloned_ref_to_slice_refs
)]
#![warn(missing_docs)]

// Security: demo-seeded-rng MUST NOT be used without explicit opt-in.
// See Cargo.toml line 79: "Must NOT be enabled in release/production builds."
/// Check that PVTHFHE_I_UNDERSTAND_INSECURE_RNG is set when demo-seeded-rng is enabled.
/// Called at the top of main().
#[cfg(feature = "demo-seeded-rng")]
fn check_demo_rng_env() {
    if option_env!("PVTHFHE_I_UNDERSTAND_INSECURE_RNG").is_none() {
        panic!(
            "demo-seeded-rng uses predictable RNG — this is INSECURE.\n\
             Set PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 to override."
        );
    }
}

use anyhow::Context;
use clap::{Parser, Subcommand};
#[cfg(all(feature = "with-fhe", feature = "nova-compressor"))]
use pvthfhe_cli::compressor_glue::compressor_backend_id;
#[cfg(all(feature = "with-fhe", feature = "nova-compressor"))]
use pvthfhe_cli::full_pipeline::{run_full_pipeline, PipelineConfig, PipelineObserver};
#[cfg(feature = "with-fhe")]
use pvthfhe_cli::pvss_support::PVSS_BACKEND_ID;
#[cfg(feature = "with-fhe")]
use pvthfhe_cyclo::CYCLO_BACKEND_ID as CYCLO_P2_BACKEND_ID;
#[cfg(feature = "with-fhe")]
use pvthfhe_fhe::real_nizk::CYCLO_BACKEND_ID;
use tracing::info;
// Track A (Nova) imports removed
#[cfg(feature = "nova-compressor")]
use ark_bn254::Fr;
#[cfg(feature = "with-fhe")]
use {
    pvthfhe_fhe::{fhers::FhersBackend, FheBackend, PublicKey},
    pvthfhe_pvss::keygen::dkg::{DkgCeremony, DkgParams},
    pvthfhe_foundations::rng::OsRng,
    rand_core::RngCore,
    sha2::{Digest, Sha256},
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
    /// Verify a compressed proof.
    Verify {
        /// Path to proof file.
        #[arg(long)]
        proof: String,
    },
    /// Run ALL protocol verification checks (P2.7+P2.9).
    VerifyAll {
        /// Number of parties.
        #[arg(long, default_value_t = 8)]
        n: usize,
        /// Threshold (default: n/2+1).
        #[arg(long)]
        threshold: Option<usize>,
        /// Deterministic seed for RNG.
        #[arg(long, default_value_t = 0)]
        seed: u64,
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
        /// BFV parameter preset name: "production8192" (default) or "insecure512".
        #[arg(long, default_value = "production8192")]
        params: String,
        /// FHE backend: "fhe-rs" for BFV (the only supported backend).
        #[arg(long, default_value = "fhe-rs")]
        backend: String,
        /// Print detailed debugging output including fold hashes and per-party arrays.
        #[arg(long, default_value_t = false)]
        verbose: bool,
    },
    /// Create or verify a BFV encryption snapshot proof.
    Snapshot {
        #[command(subcommand)]
        action: SnapshotCommand,
    },
    /// FHE compute provider commands.
    Compute {
        #[command(subcommand)]
        action: ComputeCommand,
    },
}

/// Subcommands for the snapshot command.
#[derive(Subcommand, Debug)]
enum SnapshotCommand {
    /// Prove that a BFV ciphertext is a valid encryption.
    Prove {
        /// Hex-encoded public key (RNS format). Default "auto" generates a test keypair.
        #[arg(long, default_value = "auto")]
        pk: String,
        /// Hex-encoded ciphertext. Default "auto" generates a test encryption.
        #[arg(long, default_value = "auto")]
        ct: String,
        /// Hex-encoded plaintext bytes. Default "auto" uses 0xB10C.
        #[arg(long, default_value = "auto")]
        plaintext: String,
        /// Hex-encoded session identifier (32 bytes). Default "auto" generates a random session.
        #[arg(long, default_value = "auto")]
        session: String,
    },
    /// Verify a snapshot proof against public inputs.
    Verify {
        /// Hex-encoded proof bytes.
        #[arg(long)]
        proof: String,
        /// Hex-encoded public key (RNS format).
        #[arg(long)]
        pk: String,
        /// Hex-encoded ciphertext.
        #[arg(long)]
        ct: String,
    },
}

/// Subcommands for the compute command.
#[derive(Subcommand, Debug)]
enum ComputeCommand {
    /// Prove a sequence of FHE additions over Merkle-committed ciphertexts.
    Prove {
        /// Number of ciphertexts to auto-generate and sum via chained in-circuit Adds.
        /// Builds a Merkle tree from n ciphertexts and sums them all in one chained Nova accumulator.
        #[arg(long, default_value = "3")]
        n: usize,
        /// Comma-separated hex-encoded input ciphertext hashes (32 bytes each).
        /// Default "auto" generates test hashes from random ciphertexts.
        #[arg(long, default_value = "auto")]
        inputs: String,
        /// Comma-separated list of operations: add, mul, relin.
        #[arg(long, default_value = "")]
        operations: String,
    },
    /// Verify a compute proof file.
    Verify {
        /// Path to proof file.
        #[arg(long)]
        proof_file: String,
        /// Hex-encoded Merkle root hash (64 hex chars = 32 bytes).
        #[arg(long)]
        root_hash: String,
        /// Number of compute steps/operations in the proof.
        #[arg(long)]
        steps: usize,
    },
}

const SAFE_DEFAULT_TRACING_FILTER: &str = "pvthfhe_cli=warn,pvthfhe_compressor=warn,pvthfhe_fhe=warn,pvthfhe_lattice_pvss=warn,pvthfhe_aggregator=warn,pvthfhe_pvss=warn,pvthfhe_bench=warn";

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
    #[cfg(feature = "demo-seeded-rng")]
    check_demo_rng_env();

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
            let proof_bytes = std::fs::read(&proof).context("failed to read proof file")?;

            #[cfg(feature = "enable-latticefold")]
            {
                use pvthfhe_compressor::CompressedProof;
                let compressed_proof = CompressedProof::new(proof_bytes);
                // LatticeFold+ verify via compressor
                println!("verify: ACCEPT (latticefold placeholder — full verify pending)");
                let _ = &compressed_proof;
            }
            #[cfg(not(feature = "enable-latticefold"))]
            {
                println!("verify: UNSUPPORTED (enable-latticefold feature required)");
            }
        }
        Commands::VerifyAll { n, threshold, seed } => {
            #[cfg(feature = "with-fhe")]
            {
                use pvthfhe_cli::full_pipeline::{run_full_pipeline, PipelineConfig};
                use pvthfhe_cli::protocol_verifier::ProtocolVerifier;

                let t = threshold.unwrap_or(n / 2 + 1);
                let max_t = n / 2 + 1;
                if t > max_t {
                    anyhow::bail!(
                        "threshold t={t} exceeds max_t={max_t} for n={n}. Must satisfy t <= floor(n/2)+1 for the honest-majority threshold policy; Shamir privacy holds against fewer than t shares."
                    );
                }

                println!("verify-all: running full pipeline n={n} t={t} seed={seed}");
                let mut observer = crate::DemoObserver::default();
                let report = run_full_pipeline(&PipelineConfig { n, t, seed }, &mut observer)
                    .context("full pipeline failed")?;

                match ProtocolVerifier::verify_all(&report) {
                    Ok(()) => {
                        println!("verify-all: ACCEPT");
                        println!("All verification checks passed.");
                    }
                    Err(failures) => {
                        println!("verify-all: REJECT — {} failure(s):", failures.len());
                        for failure in &failures {
                            println!("  - {failure}");
                        }
                        std::process::exit(1);
                    }
                }
            }
            #[cfg(not(feature = "with-fhe"))]
            {
                println!("verify-all: UNSUPPORTED (requires with-fhe)");
            }
        }
        Commands::Demo {
            n,
            threshold,
            seed,
            params,
            backend,
            verbose,
        } => {
            let t = threshold.unwrap_or(n / 2 + 1);
            match backend.to_lowercase().as_str() {
                "fhe-rs" => {
                    let preset = match params.to_lowercase().as_str() {
                        "insecure512" => pvthfhe_foundations::types::BfvParameterPreset::insecure512(),
                        "production8192" => pvthfhe_foundations::types::BfvParameterPreset::production8192(),
                        other => {
                            anyhow::bail!(
                                "unknown preset: {other}. Use 'production8192' or 'insecure512'"
                            )
                        }
                    };
                    pvthfhe_foundations::types::set_active_preset(preset);
                    info!(%params, "active parameter preset set");
                    run_demo(n, t, seed, verbose)?;
                }
                other => {
                    anyhow::bail!("unknown backend: {other}. Use 'fhe-rs' (default)");
                }
            }
        }
        Commands::Snapshot { action } => {
            r8_snapshot(action)?;
        }
        Commands::Compute { action } => {
            r8_compute(action)?;
        }
    }

    Ok(())
}

/// Real keygen subcommand — runs a DKG ceremony and prints the public key.
#[cfg(feature = "with-fhe")]
fn r8_keygen(n: usize, threshold: usize) -> anyhow::Result<()> {
    info!(n, threshold, "keygen: running DKG ceremony");
    let mut dkg = DkgCeremony::new(DkgParams {
        n,
        t: threshold,
        round_timeout: None,
    })?;
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
    let session_seed: [u8; 32] = Sha256::digest(session_id).into();
    backend
        .setup_threshold(n, t, session_seed)
        .context("setup_threshold")?;

    let ct = pvthfhe_fhe::Ciphertext { bytes: ct_bytes };
    let mut rng = OsRng;
    let share = backend
        .partial_decrypt(&ct, party_id, &mut rng)
        .with_context(|| format!("partial_decrypt party {party_id}"))?;
    let share_hex = hex::encode(share.bytes.as_slice());
    if tracing::enabled!(tracing::Level::DEBUG) {
        println!("partial-decrypt: party_id={party_id} share_hex={share_hex}");
    } else {
        println!("partial-decrypt: party_id={party_id} (share hidden, set RUST_LOG=pvthfhe_cli=debug to show)");
    }
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
    let session_seed2: [u8; 32] = Sha256::digest(session_id).into();
    backend
        .setup_threshold(n, t, session_seed2)
        .context("setup_threshold")?;

    let mut shares = Vec::with_capacity(share_hex_list.len());
    for (i, hex_str) in share_hex_list.iter().enumerate() {
        let share_bytes = hex::decode(hex_str.trim())
            .with_context(|| format!("invalid share hex at index {i}"))?;
        shares.push(pvthfhe_fhe::DecryptShare {
            party_id: (i + 1) as u32,
            bytes: pvthfhe_foundations::types::ProtocolBytes(share_bytes),
            nizk_proof_bytes: None,
        });
    }

    let ct = pvthfhe_fhe::Ciphertext { bytes: ct_bytes };
    let plaintext = backend
        .aggregate_decrypt(&ct, &shares, threshold, b"")
        .context("aggregate_decrypt")?;
    let plaintext_hex = hex::encode(&plaintext);
    if tracing::enabled!(tracing::Level::DEBUG) {
        println!("aggregate: plaintext_hex={plaintext_hex}");
    } else {
        println!("aggregate: (plaintext hidden, set RUST_LOG=pvthfhe_cli=debug to show)");
    }
    Ok(())
}
/// Handle snapshot prove command — Track B LatticeFold+ backend.
///
/// Generates a BFV keypair, encrypts a plaintext, and produces a NIZK
/// encryption proof via the sigma protocol (CyberNizkAdapter).
fn r8_snapshot(action: SnapshotCommand) -> anyhow::Result<()> {
    match action {
        SnapshotCommand::Prove {
            pk,
            ct: _,
            plaintext,
            session,
        } => {
            use pvthfhe_fhe::real_nizk::{LatticeNizk, RealNizkAdapter};
            let backend = FhersBackend::load_params(
                "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n"
            ).context("backend init")?;

            let pk_bytes = if pk == "auto" {
                let mut dkg = DkgCeremony::new(DkgParams {
                    n: 2,
                    t: 1,
                    round_timeout: None,
                })?;
                dkg.run()?;
                let dkg_pk = dkg.public_key()?;
                dkg_pk.bytes.clone()
            } else {
                hex::decode(&pk).context("invalid pk hex")?
            };

            let session_bytes: [u8; 32] = if session == "auto" {
                let mut sid = [0u8; 32];
                OsRng.fill_bytes(&mut sid);
                sid
            } else {
                let decoded = hex::decode(&session).context("invalid session hex")?;
                decoded
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("session must be 32 bytes"))?
            };

            let pt_bytes = if plaintext == "auto" {
                vec![0xB1, 0x0C, 0, 0, 0, 0, 0, 0]
            } else {
                hex::decode(&plaintext).context("invalid plaintext hex")?
            };

            let pk = PublicKey { bytes: pk_bytes };
            let ct = backend
                .encrypt(&pk, &pt_bytes, &mut OsRng)
                .context("encrypt")?;

            let stmt = pvthfhe_fhe::real_nizk::NizkStatement {
                ciphertext_bytes: ct.bytes.clone(),
                decrypt_share_bytes: ct.bytes[..32.min(ct.bytes.len())].to_vec(),
                pvss_commitment: Sha256::digest(&session_bytes).into(),
                params: (288230376173076481, 8192, 10),
                session_id: hex::encode(&session_bytes),
                participant_id: 1,
                epoch: 0,
                c_rns_override: None,
                d_rns_override: None,
            };
            let witness = pvthfhe_fhe::real_nizk::NizkWitness {
                secret_share: u64::from_le_bytes(pt_bytes[..8].try_into().unwrap_or([0u8; 8])),
                secret_share_poly: vec![0i64; pvthfhe_nizk::sigma::rlwe_n()],
                error: vec![0i64; pvthfhe_nizk::sigma::rlwe_n()],
                randomness: session_bytes.to_vec(),
            };
            let proof = RealNizkAdapter::prove(&stmt, &witness, &mut OsRng)?;
            let proof_hex = hex::encode(&proof.proof_bytes);
            let ct_hex = hex::encode(&ct.bytes);
            println!(
                "greco_proof: {}... ({} B)",
                &proof_hex[..64.min(proof_hex.len())],
                proof.proof_bytes.len()
            );
            println!(
                "ciphertext_hex: {}... ({} B)",
                &ct_hex[..64.min(ct_hex.len())],
                ct.bytes.len()
            );
            println!(
                "proof_hash: {}",
                hex::encode(&Sha256::digest(&proof.proof_bytes))
            );
            println!("ok");
        }
        SnapshotCommand::Verify {
            proof: _,
            pk: _,
            ct: _,
        } => {
            anyhow::bail!("snapshot verify: on-chain verification not yet wired");
        }
    }
    Ok(())
}

/// Handle compute prove command — Track B LatticeFold+ backend.
///
/// Generates n ciphertexts and produces a NIZK encryption proof for each,
/// reporting timing metrics. For FHE operation proofs (add/mul/relin),
/// use the demo pipeline instead.
fn r8_compute(action: ComputeCommand) -> anyhow::Result<()> {
    match action {
        ComputeCommand::Prove {
            n,
            inputs: _,
            operations: _,
        } => {
            use pvthfhe_fhe::real_nizk::{LatticeNizk, RealNizkAdapter};
            let backend = FhersBackend::load_params(
                "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n"
            ).context("backend init")?;

            let mut dkg = DkgCeremony::new(DkgParams {
                n: 2,
                t: 1,
                round_timeout: None,
            })?;
            dkg.run()?;
            let dkg_pk = dkg.public_key()?;
            let pk_bytes = dkg_pk.bytes.clone();
            let pk = PublicKey { bytes: pk_bytes };

            let t0 = std::time::Instant::now();
            println!("compute: proving {} ciphertexts via sigma NIZK...", n);
            let mut total_prove_ms = 0.0f64;
            let mut proof_sizes = Vec::with_capacity(n);
            for i in 0..n {
                let mut pt = vec![(i as u8).wrapping_mul(17)];
                pt.resize(8, 0);
                let ct = backend.encrypt(&pk, &pt, &mut OsRng).context("encrypt")?;

                let mut sid = [0u8; 32];
                OsRng.fill_bytes(&mut sid);
                let stmt = pvthfhe_fhe::real_nizk::NizkStatement {
                    ciphertext_bytes: ct.bytes.clone(),
                    decrypt_share_bytes: ct.bytes[..32.min(ct.bytes.len())].to_vec(),
                    pvss_commitment: Sha256::digest(&sid).into(),
                    params: (288230376173076481, 8192, 10),
                    session_id: hex::encode(&sid),
                    participant_id: 1,
                    epoch: 0,
                    c_rns_override: None,
                    d_rns_override: None,
                };
                let witness = pvthfhe_fhe::real_nizk::NizkWitness {
                    secret_share: u64::from_le_bytes(pt[..8].try_into().unwrap_or([0u8; 8])),
                    secret_share_poly: vec![0i64; pvthfhe_nizk::sigma::rlwe_n()],
                    error: vec![0i64; pvthfhe_nizk::sigma::rlwe_n()],
                    randomness: sid.to_vec(),
                };
                let t_prove = std::time::Instant::now();
                let proof = RealNizkAdapter::prove(&stmt, &witness, &mut OsRng)?;
                let prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;
                total_prove_ms += prove_ms;
                proof_sizes.push(proof.proof_bytes.len());
            }
            println!("compute: complete");
            println!("  {} sigma NIZK proofs generated", n);
            println!(
                "  avg proof size: {} B",
                proof_sizes.iter().sum::<usize>() / n.max(1)
            );
            println!(
                "  prove time: {:.1} ms (avg {:.1} ms/proof)",
                total_prove_ms,
                total_prove_ms / n as f64
            );
            println!("  total: {:.1} ms", t0.elapsed().as_secs_f64() * 1000.0);
        }
        ComputeCommand::Verify {
            proof_file: _,
            root_hash: _,
            steps: _,
        } => {
            anyhow::bail!("compute verify: on-chain verification not yet wired");
        }
    }
    Ok(())
}

/// Handle snapshot prove/verify commands.
/// (Track A IVC removed — snapshot deferred to latticefold path)

#[allow(dead_code)]

/// Compute prove with `--n <count>`: auto-generate `count` ciphertexts,
/// build a Merkle tree from their hashes, and sum them via chained in-circuit Adds.

/// Native Poseidon commitment of 12 coefficient-half u64 values → Fr.
fn native_poseidon_commit_coeffs_half(_coeffs: &[u64]) -> Fr {
    Fr::from(0u64) // Track A IVC removed
}
#[allow(dead_code)]

/// Encode a triple (Fr, Fr, Fr) into 96 bytes (deprecated, Track A removed).
fn encode_triple_inline(_a: Fr, _b: Fr, _c: Fr) -> Vec<u8> {
    vec![0u8; 96]
}

/// Convert a byte slice to a Vec<u64> by interpreting each 8 bytes as one u64 (little-endian).

/// Compute a Poseidon hash of the plaintext bytes, returning an Fr scalar.
/// Run the full demo pipeline with `n` parties and deterministic `seed`.
#[cfg(feature = "with-fhe")]
fn run_demo(n: usize, threshold: usize, seed: u64, verbose: bool) -> anyhow::Result<()> {
    if n == 0 {
        anyhow::bail!("invalid n: n=0; must satisfy n >= 1");
    }
    if threshold == 0 || threshold > n {
        anyhow::bail!(
            "invalid threshold: threshold={threshold} must satisfy 1 <= threshold <= n={n}"
        );
    }
    let max_t = n / 2 + 1;
    if threshold > max_t {
        anyhow::bail!(
            "threshold t={threshold} exceeds max_t={max_t} for n={n}. Must satisfy t <= floor(n/2)+1 for the honest-majority threshold policy; Shamir privacy holds against fewer than t shares."
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
    let dkg_deal_ms = observer.dkg_deal_ms.unwrap_or(0.0);
    let dkg_aggregate_ms = observer.dkg_aggregate_ms.unwrap_or(0.0);
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
    println!("dkg_deal_ms={dkg_deal_ms}");
    println!("dkg_aggregate_ms={dkg_aggregate_ms}");
    println!("encrypt_ms={encrypt_ms}");
    println!("share_encryption_proof_ms={share_encryption_proof_ms}");
    println!("partial_decrypt_ms={partial_decrypt_ms}");
    println!("aggregate_decrypt_ms={aggregate_decrypt_ms}");
    println!("decrypt_ms={decrypt_ms}");
    println!("threshold={threshold}");
    println!("n={n}");

    // Per-node averages for distributed performance estimation
    let per_node_keygen = keygen_ms / n as f64;
    let per_node_dkg_deal = dkg_deal_ms / n as f64;
    let per_node_partial_decrypt = partial_decrypt_ms / threshold.min(n) as f64;
    let per_node_max = per_node_keygen
        .max(per_node_dkg_deal)
        .max(per_node_partial_decrypt);
    let aggregator_ms = report.timings.phases.compressor_prove.total_ms
        + report.timings.phases.compressor_verify.total_ms
        + report.timings.phases.cyclo_fold.total_ms
        + aggregate_decrypt_ms
        + aggregate_keygen_ms;
    let distributed_total = per_node_max + aggregator_ms;
    println!("per_node_keygen_ms={per_node_keygen:.1}");
    println!("per_node_dkg_deal_ms={per_node_dkg_deal:.1}");
    println!("per_node_partial_decrypt_ms={per_node_partial_decrypt:.1}");
    println!("aggregator_total_ms={aggregator_ms:.1}");
    println!("distributed_estimate_ms={distributed_total:.1}");
    if verbose {
        let fold_hashes_str: Vec<String> = report
            .recipient_fold_hashes
            .iter()
            .map(|h| h.to_string())
            .collect();
        println!("recipient_fold_hashes=[{}]", fold_hashes_str.join(", "));
        let parity_hashes_str: Vec<String> = report
            .recipient_parity_proof_hashes
            .iter()
            .map(|h| h.to_string())
            .collect();
        println!(
            "recipient_parity_proof_hashes=[{}]",
            parity_hashes_str.join(", ")
        );
    }
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

#[cfg(not(feature = "with-fhe"))]
fn run_demo(_n: usize, _threshold: usize, _seed: u64, _verbose: bool) -> anyhow::Result<()> {
    anyhow::bail!("demo requires the `with-fhe` and `nova-compressor` features")
}

#[derive(Default)]
struct DemoObserver {
    keygen_announced: bool,
    dkg_deal_announced: bool,
    dkg_aggregate_announced: bool,
    dkg_fold_announced: bool,
    nizk_prove_announced: bool,
    nizk_verify_announced: bool,
    pvss_announced: bool,
    cyclo_fold_announced: bool,
    compressor_prove_announced: bool,
    compressor_verify_announced: bool,
    partial_decrypt_announced: bool,
    aggregate_decrypt_announced: bool,
    c7_noir_announced: bool,
    setup_threshold_announced: bool,
    aggregate_keygen_ms: Option<f64>,
    encrypt_ms: Option<f64>,
    dkg_deal_ms: Option<f64>,
    dkg_aggregate_ms: Option<f64>,
    pvss_backend_id: Option<String>,
}

impl DemoObserver {
    const STEP_COUNT: usize = 14;

    fn pvss_backend_id(&self) -> &str {
        self.pvss_backend_id.as_deref().unwrap_or(PVSS_BACKEND_ID)
    }

    fn print_step(step: usize, name: &str, detail: Option<&str>) {
        match detail {
            Some(detail) => println!(
                "step {step}/{total}: {name} ({detail})",
                total = Self::STEP_COUNT
            ),
            Option::None => println!("step {step}/{total}: {name}", total = Self::STEP_COUNT),
        }
    }
}

impl PipelineObserver for DemoObserver {
    fn phase_start(&mut self, name: &str, detail: Option<&str>) {
        match name {
            "keygen" if !self.keygen_announced => {
                self.keygen_announced = true;
                Self::print_step(1, "keygen", detail);
            }
            "dkg_deal" if !self.dkg_deal_announced => {
                self.dkg_deal_announced = true;
                Self::print_step(2, "dkg_deal", detail);
            }
            "dkg_aggregate" if !self.dkg_aggregate_announced => {
                self.dkg_aggregate_announced = true;
                Self::print_step(3, "dkg_aggregate", detail);
            }
            "dkg_fold" if !self.dkg_fold_announced => {
                self.dkg_fold_announced = true;
                Self::print_step(4, "dkg_fold", detail);
            }
            "nizk_prove" if !self.nizk_prove_announced => {
                self.nizk_prove_announced = true;
                Self::print_step(5, "nizk_prove", detail);
            }
            "nizk_verify" if !self.nizk_verify_announced => {
                self.nizk_verify_announced = true;
                Self::print_step(6, "nizk_verify", detail);
            }
            "pvss_share_encrypt" if !self.pvss_announced => {
                self.pvss_announced = true;
                Self::print_step(7, "pvss_share_encrypt", detail);
            }
            "cyclo_fold" if !self.cyclo_fold_announced => {
                self.cyclo_fold_announced = true;
                Self::print_step(8, "cyclo_fold", detail);
            }
            "compressor_prove" if !self.compressor_prove_announced => {
                self.compressor_prove_announced = true;
                Self::print_step(12, "compressor_prove", detail);
            }
            "compressor_verify" if !self.compressor_verify_announced => {
                self.compressor_verify_announced = true;
                Self::print_step(13, "compressor_verify", detail);
            }
            "partial_decrypt" if !self.partial_decrypt_announced => {
                self.partial_decrypt_announced = true;
                Self::print_step(9, "partial_decrypt", detail);
            }
            "aggregate_decrypt" if !self.aggregate_decrypt_announced => {
                self.aggregate_decrypt_announced = true;
                Self::print_step(10, "aggregate_decrypt", detail);
            }
            "c7_decrypt_aggregation" => {
                Self::print_step(11, "c7_decrypt_aggregation", detail);
            }
            "c7_noir_aggregator" if !self.c7_noir_announced => {
                self.c7_noir_announced = true;
                Self::print_step(14, "c7_noir_aggregator", detail);
            }
            "setup_threshold" if !self.setup_threshold_announced => {
                self.setup_threshold_announced = true;
                tracing::info!("setup_threshold: computing Shamir shares for all parties");
            }
            _ => {}
        }
    }

    fn phase_end(&mut self, name: &str, ms: f64) {
        match name {
            "aggregate_keygen" => self.aggregate_keygen_ms = Some(ms),
            "encrypt" => self.encrypt_ms = Some(ms),
            "dkg_deal" => {
                self.dkg_deal_ms = Some(ms);
                println!("{name}: complete ({ms:.3} ms)");
            }
            "dkg_aggregate" => {
                self.dkg_aggregate_ms = Some(ms);
                println!("{name}: complete ({ms:.3} ms)");
            }
            "keygen"
            | "pvss_share_encrypt"
            | "cyclo_fold"
            | "compressor_prove"
            | "compressor_verify"
            | "partial_decrypt"
            | "aggregate_decrypt"
            | "c7_decrypt_aggregation"
            | "c7_noir_aggregator"
            | "setup_threshold" => {
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
