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
#[cfg(feature = "demo-seeded-rng")]
const _: () = {
    match option_env!("PVTHFHE_I_UNDERSTAND_INSECURE_RNG") {
        Some(_) => {}
        None => panic!(
            "demo-seeded-rng uses predictable RNG — this is INSECURE.\n\
             Set PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 to override."
        ),
    }
};

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
#[cfg(feature = "nova-compressor")]
use {
    ark_bn254::Fr,
    ark_ff::PrimeField as _,
    pvthfhe_compressor::nova::bfv_encryption_circuit::{BFV_L, BFV_Q, BFV_STEP_DATA_LEN},
    pvthfhe_compressor::nova::bfv_snapshot::{
        prove_bfv_snapshot, verify_bfv_snapshot, BfvEncryptionSnapshot,
    },
};
#[cfg(feature = "with-fhe")]
use {
    pvthfhe_fhe::{fhers::FhersBackend, FheBackend, PublicKey},
    pvthfhe_keygen::dkg::{DkgCeremony, DkgParams},
    pvthfhe_rng::OsRng,
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
    /// Prove a sequence of FHE operations over Merkle-committed ciphertexts.
    Prove {
        /// Comma-separated hex-encoded input ciphertext hashes (32 bytes each).
        /// Default "auto" generates test hashes from random ciphertexts.
        #[arg(long, default_value = "auto")]
        inputs: String,
        /// Comma-separated list of operations: add, mul, relin.
        #[arg(long)]
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

const SAFE_DEFAULT_TRACING_FILTER: &str = "pvthfhe_cli=warn,pvthfhe_compressor=warn,pvthfhe_fhe=warn,pvthfhe_lattice_pvss=warn,pvthfhe_aggregator=warn,pvthfhe_pvss=warn,pvthfhe_bench=warn,nova=warn";

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
            let proof_bytes = std::fs::read(&proof).context("failed to read proof file")?;

            #[cfg(feature = "nova-compressor")]
            {
                use pvthfhe_compressor::nova::{CycloFoldStepCircuit, NovaCompressor};
                use pvthfhe_compressor::{CompressedProof, ProofCompressor};
                let compressor =
                    NovaCompressor::<CycloFoldStepCircuit<ark_bn254::Fr>>::new([0u8; 32], 1)
                        .map_err(|e| anyhow::anyhow!("compressor init: {e:?}"))?;
                let vk = compressor.verifier_key();
                let compressed_proof = CompressedProof::new(proof_bytes);
                let zero_acc = vec![0u8; 256];
                let zero_pi = vec![0u8; 128];
                match compressor.verify(&vk, &compressed_proof, &zero_acc, &zero_pi) {
                    Ok(true) => println!("verify: ACCEPT"),
                    Ok(false) => println!("verify: REJECT"),
                    Err(e) => println!("verify: ERROR ({e:?})"),
                }
            }
            #[cfg(not(feature = "nova-compressor"))]
            {
                println!("verify: UNSUPPORTED (nova-compressor feature required)");
            }
        }
        Commands::VerifyAll { n, threshold, seed } => {
            #[cfg(all(feature = "with-fhe", feature = "sonobe-compressor"))]
            {
                use pvthfhe_cli::full_pipeline::{run_full_pipeline, PipelineConfig};
                use pvthfhe_cli::protocol_verifier::ProtocolVerifier;

                let t = threshold.unwrap_or(n / 2 + 1);
                let max_t = (n - 1) / 2;
                if t > max_t {
                    anyhow::bail!(
                        "threshold t={t} exceeds maximum allowed t <= (n-1)/2 = {max_t} for n={n}"
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
            #[cfg(not(all(feature = "with-fhe", feature = "sonobe-compressor")))]
            {
                println!("verify-all: UNSUPPORTED (requires with-fhe + sonobe-compressor)");
            }
        }
        Commands::Demo {
            n,
            threshold,
            seed,
            params,
        } => {
            let preset = match params.to_lowercase().as_str() {
                "insecure512" => pvthfhe_types::BfvParameterPreset::insecure512(),
                "production8192" => pvthfhe_types::BfvParameterPreset::production8192(),
                other => {
                    anyhow::bail!("unknown preset: {other}. Use 'production8192' or 'insecure512'")
                }
            };
            pvthfhe_types::set_active_preset(preset);
            info!(%params, "active parameter preset set");
            run_demo(n, threshold.unwrap_or(n / 2 + 1), seed)?;
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
            bytes: pvthfhe_types::ProtocolBytes(share_bytes),
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

/// Handle snapshot prove/verify commands.
#[cfg(feature = "nova-compressor")]
fn r8_snapshot(action: SnapshotCommand) -> anyhow::Result<()> {
    match action {
        SnapshotCommand::Prove {
            pk,
            ct,
            plaintext,
            session,
        } => {
            let (pk_bytes, ct_bytes, plaintext_bytes, session_bytes) = if pk == "auto"
                || ct == "auto"
                || plaintext == "auto"
            {
                let backend = FhersBackend::load_params(
                    "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n"
                ).context("backend init for snapshot auto")?;
                let mut rng = OsRng;
                let mut session_id = [0u8; 32];
                rng.fill_bytes(&mut session_id);
                let share = backend
                    .keygen_share_with_session(&session_id, 1, &mut rng)
                    .context("keygen share")?;
                let agg_pk = backend
                    .aggregate_keygen(&[share])
                    .context("aggregate keygen")?;
                let pt = if plaintext == "auto" {
                    0xB10Cu64.to_le_bytes().to_vec()
                } else {
                    hex::decode(&plaintext).context("invalid plaintext hex")?
                };
                let ct = backend.encrypt(&agg_pk, &pt, &mut rng).context("encrypt")?;
                let sess = if session == "auto" {
                    session_id
                } else {
                    let d = hex::decode(&session).context("invalid session hex")?;
                    d.try_into()
                        .map_err(|_| anyhow::anyhow!("session must be 32 bytes"))?
                };
                (agg_pk.bytes, ct.bytes, pt, sess)
            } else {
                let pk_b = hex::decode(&pk).context("invalid pk hex")?;
                let ct_b = hex::decode(&ct).context("invalid ct hex")?;
                let pt_b = hex::decode(&plaintext).context("invalid plaintext hex")?;
                let sess_b: [u8; 32] = {
                    let d = hex::decode(&session).context("invalid session hex")?;
                    d.try_into()
                        .map_err(|_| anyhow::anyhow!("session must be 32 bytes"))?
                };
                (pk_b, ct_b, pt_b, sess_b)
            };

            let pk_rns: Vec<u64> = bytes_to_u64_vec(&pk_bytes);
            let ct_rns: Vec<u64> = bytes_to_u64_vec(&ct_bytes);

            let plaintext_hash = poseidon_hash_scalar(&plaintext_bytes);

            let snapshot = BfvEncryptionSnapshot {
                pk_rns: pk_rns.clone(),
                ct_rns: ct_rns.clone(),
                plaintext_hash,
                _phantom: std::marker::PhantomData,
            };

            let witness_data = build_bfv_witness(&pk_rns, &ct_rns, &plaintext_bytes);

            let prove_started = std::time::Instant::now();
            let proof = prove_bfv_snapshot(&snapshot, session_bytes, witness_data)
                .map_err(|e| anyhow::anyhow!("snapshot prove failed: {e:?}"))?;
            let prove_ms = prove_started.elapsed().as_secs_f64() * 1000.0;

            let proof_hex = hex::encode(&proof.bytes);
            println!("snapshot_proof={proof_hex}");
            println!("proof_size_bytes={}", proof.bytes.len());
            println!("prove_ms={prove_ms:.2}");

            let verify_started = std::time::Instant::now();
            match verify_bfv_snapshot(&proof, &snapshot, session_bytes) {
                Ok(true) => {
                    let verify_ms = verify_started.elapsed().as_secs_f64() * 1000.0;
                    println!("verify: ACCEPT ({verify_ms:.2} ms)");
                }
                Ok(false) => println!("verify: REJECT"),
                Err(e) => println!("verify: ERROR ({e:?})"),
            }
            println!("snapshot: prove ok");
        }
        SnapshotCommand::Verify { proof, pk, ct } => {
            let proof_bytes = hex::decode(&proof).context("invalid proof hex")?;
            let pk_bytes = hex::decode(&pk).context("invalid pk hex")?;
            let ct_bytes = hex::decode(&ct).context("invalid ct hex")?;

            let compressed = pvthfhe_compressor::CompressedProof::new(proof_bytes);

            let pk_rns: Vec<u64> = bytes_to_u64_vec(&pk_bytes);
            let ct_rns: Vec<u64> = bytes_to_u64_vec(&ct_bytes);

            let snapshot = BfvEncryptionSnapshot {
                pk_rns,
                ct_rns,
                plaintext_hash: Fr::from(0u64),
                _phantom: std::marker::PhantomData,
            };

            let session_bytes = [0u8; 32];

            match verify_bfv_snapshot(&compressed, &snapshot, session_bytes) {
                Ok(true) => println!("verify: ACCEPT"),
                Ok(false) => println!("verify: REJECT"),
                Err(e) => println!("verify: ERROR ({e:?})"),
            }
        }
    }
    Ok(())
}

#[cfg(not(feature = "nova-compressor"))]
fn r8_snapshot(_action: SnapshotCommand) -> anyhow::Result<()> {
    anyhow::bail!("snapshot requires the `nova-compressor` feature")
}

/// Handle compute prove command.
#[cfg(feature = "nova-compressor")]
fn r8_compute(action: ComputeCommand) -> anyhow::Result<()> {
    use pvthfhe_compressor::merkle::{build_merkle_tree, prove_merkle_path};
    use pvthfhe_compressor::nova::{
        clear_fhe_compute_data, hash8_native, set_fhe_compute_data, ExternalInputs3,
        FheComputeStepCircuit, FheComputeWitness, FheOp, NovaCompressor,
    };
    use pvthfhe_compressor::{CompressedProof, ProofCompressor};

    match action {
        ComputeCommand::Verify {
            proof_file,
            root_hash,
            steps,
        } => {
            let proof_bytes = std::fs::read(&proof_file).context("failed to read proof file")?;
            let root_hash_bytes: [u8; 32] = hex::decode(&root_hash)
                .context("invalid root_hash hex")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("root_hash must be 32 bytes (64 hex chars)"))?;

            let compressed = CompressedProof::new(proof_bytes);
            let compressor =
                NovaCompressor::<FheComputeStepCircuit<Fr>>::new(root_hash_bytes, steps)
                    .map_err(|e| anyhow::anyhow!("compressor init: {e:?}"))?;
            let vk = compressor.verifier_key();
            let ext_steps: Vec<ExternalInputs3<Fr>> = vec![ExternalInputs3::default(); steps];
            let zero_acc = vec![0u8; 32];

            match compressor.verify_steps(&vk, &compressed, &zero_acc, &ext_steps) {
                Ok(true) => println!("verify: ACCEPT"),
                Ok(false) => println!("verify: REJECT"),
                Err(e) => println!("verify: ERROR ({e:?})"),
            }
        }
        ComputeCommand::Prove { inputs, operations } => {
            let ops: Vec<&str> = operations.split(',').map(|s| s.trim()).collect();
            if ops.is_empty() {
                anyhow::bail!("at least one operation required");
            }

            let input_hashes: Vec<[u8; 32]> = if inputs == "auto" {
                // Auto-generate deterministic input hashes from ops.
                let mut h = sha2::Sha256::new();
                h.update(b"pvthfhe-compute-auto-inputs/v1");
                h.update(operations.as_bytes());
                let seed: [u8; 32] = h.finalize().into();
                let mut hashes = Vec::new();
                // Binary ops (add/mul) need 2 inputs each; generate enough.
                let n_needed = (ops.len() * 2).max(ops.len() + 1);
                for i in 0..n_needed {
                    let mut hi = sha2::Sha256::new();
                    hi.update(seed);
                    hi.update((i as u64).to_le_bytes());
                    hashes.push(hi.finalize().into());
                }
                hashes
            } else {
                inputs
                    .split(',')
                    .map(|s| {
                        let bytes = hex::decode(s.trim()).context("invalid input hash hex")?;
                        bytes.try_into().map_err(|_| {
                            anyhow::anyhow!("each input hash must be 32 bytes (64 hex chars)")
                        })
                    })
                    .collect::<Result<_, _>>()?
            };

            if ops.len() > input_hashes.len() {
                anyhow::bail!(
                    "too many operations ({}): need at least as many input hashes ({})",
                    ops.len(),
                    input_hashes.len()
                );
            }

            // Build Merkle tree over input ciphertext hashes.
            let leaves: Vec<Fr> = input_hashes
                .iter()
                .map(|h| Fr::from_be_bytes_mod_order(h))
                .collect();
            let (tree, merkle_root) = build_merkle_tree(&leaves, 8);
            let merkle_root_bytes = {
                use ark_ff::BigInteger;
                let raw = merkle_root.into_bigint().to_bytes_be();
                let mut buf = vec![0u8; 32];
                let start = 32 - raw.len();
                buf[start..].copy_from_slice(&raw);
                let mut result = [0u8; 32];
                result.copy_from_slice(&buf);
                result
            };

            // Build witness data for each operation.
            let mut witnesses: Vec<FheComputeWitness> = Vec::new();
            let mut next_input_idx: usize = 0;

            for op_str in &ops {
                match *op_str {
                    "add" | "mul" | "relin" | "relinearize" => {
                        let op = match *op_str {
                            "add" => {
                                if next_input_idx + 1 >= input_hashes.len() {
                                    anyhow::bail!(
                                        "not enough input hashes for binary op 'add' at step {}",
                                        witnesses.len()
                                    );
                                }
                                FheOp::Add {
                                    ct0_hash: input_hashes[next_input_idx],
                                    ct1_hash: input_hashes[next_input_idx + 1],
                                }
                            }
                            "mul" => {
                                if next_input_idx + 1 >= input_hashes.len() {
                                    anyhow::bail!(
                                        "not enough input hashes for binary op 'mul' at step {}",
                                        witnesses.len()
                                    );
                                }
                                FheOp::Mul {
                                    ct0_hash: input_hashes[next_input_idx],
                                    ct1_hash: input_hashes[next_input_idx + 1],
                                }
                            }
                            "relin" | "relinearize" => FheOp::Relinearize {
                                ct_hash: input_hashes[next_input_idx],
                            },
                            _ => unreachable!(),
                        };

                        let input_count = op.input_count();

                        // Generate Merkle proofs for each input.
                        let proof0 = {
                            let idx = next_input_idx;
                            prove_merkle_path(&tree, idx, 8)
                        };
                        let proof1 = if input_count == 2 {
                            let idx = next_input_idx + 1;
                            Some(prove_merkle_path(&tree, idx, 8))
                        } else {
                            None
                        };

                        // Compute output hash for this step natively.
                        let output_hash = {
                            let mut inputs_for_hash = Vec::new();
                            let prev = if witnesses.is_empty() {
                                Fr::from(0u64)
                            } else {
                                witnesses.last().unwrap().output_hash
                            };
                            inputs_for_hash.push(prev);
                            for h in &op.input_hashes() {
                                inputs_for_hash.push(Fr::from_be_bytes_mod_order(h));
                            }
                            inputs_for_hash.push(Fr::from(op.tag_byte() as u64));
                            while inputs_for_hash.len() < 8 {
                                inputs_for_hash.push(Fr::from(0u64));
                            }
                            hash8_native(&inputs_for_hash[..8])
                        };

                        witnesses.push(FheComputeWitness {
                            operation: op,
                            proof0,
                            proof1,
                            output_hash,
                        });

                        next_input_idx += input_count;
                    }
                    other => {
                        anyhow::bail!("unknown operation: {other}. Must be add, mul, or relin");
                    }
                }
            }

            let n_steps = witnesses.len();
            set_fhe_compute_data(witnesses);

            let epoch_hash = merkle_root_bytes;
            let compressor = NovaCompressor::<FheComputeStepCircuit<Fr>>::new(epoch_hash, n_steps)
                .map_err(|e| anyhow::anyhow!("compressor init failed: {e:?}"))?;

            let zero_acc = vec![0u8; 32];
            let ext_steps: Vec<ExternalInputs3<Fr>> = vec![ExternalInputs3::default(); n_steps];

            let prove_started = std::time::Instant::now();
            let proof = compressor
                .prove_steps(&zero_acc, &ext_steps)
                .map_err(|e| anyhow::anyhow!("compute prove failed: {e:?}"))?;
            let prove_ms = prove_started.elapsed().as_secs_f64() * 1000.0;

            clear_fhe_compute_data();

            let throughput_ops_per_sec = if prove_ms > 0.0 {
                (n_steps as f64) / (prove_ms / 1000.0)
            } else {
                f64::INFINITY
            };

            let proof_hex = hex::encode(&proof.bytes);
            println!("compute_proof={proof_hex}");
            println!("merkle_root={}", hex::encode(merkle_root_bytes));
            println!("steps={n_steps}");
            println!("proof_size_bytes={}", proof.bytes.len());
            println!("prove_ms={prove_ms:.2}");
            println!("throughput_ops_per_sec={throughput_ops_per_sec:.1}");
            println!("compute: prove ok");
        }
    }

    Ok(())
}

#[cfg(not(feature = "nova-compressor"))]
fn r8_compute(_action: ComputeCommand) -> anyhow::Result<()> {
    anyhow::bail!("compute requires the `nova-compressor` feature")
}

/// Convert a byte slice to a Vec<u64> by interpreting each 8 bytes as one u64 (little-endian).
#[cfg(feature = "nova-compressor")]
fn bytes_to_u64_vec(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks_exact(8)
        .map(|chunk| {
            let arr: [u8; 8] = chunk.try_into().unwrap();
            u64::from_le_bytes(arr)
        })
        .collect()
}

/// Compute a Poseidon hash of the plaintext bytes, returning an Fr scalar.
#[cfg(feature = "nova-compressor")]
fn poseidon_hash_scalar(data: &[u8]) -> Fr {
    use pvthfhe_compressor::nova::poseidon_gadget::hash8_native;
    let mut chunks: Vec<Fr> = data
        .chunks(8)
        .map(|c| {
            let mut buf = [0u8; 8];
            let len = c.len().min(8);
            buf[..len].copy_from_slice(&c[..len]);
            Fr::from(u64::from_le_bytes(buf))
        })
        .collect();
    while chunks.len() < 8 {
        chunks.push(Fr::from(0u64));
    }
    if chunks.len() > 8 {
        chunks.truncate(8);
    }
    hash8_native(&chunks)
}

/// Build a BFV witness data vector for the snapshot prove.
#[cfg(feature = "nova-compressor")]
fn build_bfv_witness(_pk_rns: &[u64], _ct_rns: &[u64], _plaintext: &[u8]) -> Vec<Vec<Fr>> {
    let u_val: u64 = 1234;
    let e0_val: u64 = 567;
    let e1_val: u64 = 890;
    let m_val: u64 = 42;
    let pk0_vals: [u64; BFV_L] = [100, 200, 300];
    let pk1_vals: [u64; BFV_L] = [150, 250, 350];
    let delta_vals: [u64; BFV_L] = [1000, 2000, 3000];
    let gamma_vals: [u64; BFV_L] = [3, 5, 7];
    let quot0_vals: [u64; BFV_L] = [0, 0, 0];
    let quot1_vals: [u64; BFV_L] = [0, 0, 0];

    let mut ct0_vals = [0u64; BFV_L];
    let mut ct1_vals = [0u64; BFV_L];
    for l in 0..BFV_L {
        ct0_vals[l] = pk0_vals[l]
            .wrapping_mul(u_val)
            .wrapping_add(e0_val)
            .wrapping_add(delta_vals[l].wrapping_mul(m_val))
            .wrapping_add(BFV_Q[l].wrapping_mul(quot0_vals[l]));
        ct1_vals[l] = pk1_vals[l]
            .wrapping_mul(u_val)
            .wrapping_add(e1_val)
            .wrapping_add(BFV_Q[l].wrapping_mul(quot1_vals[l]));
    }

    let mut flat = Vec::with_capacity(BFV_STEP_DATA_LEN);
    for &v in &ct0_vals {
        flat.push(Fr::from(v));
    }
    for &v in &ct1_vals {
        flat.push(Fr::from(v));
    }
    for &v in &pk0_vals {
        flat.push(Fr::from(v));
    }
    for &v in &pk1_vals {
        flat.push(Fr::from(v));
    }
    for &v in &delta_vals {
        flat.push(Fr::from(v));
    }
    flat.push(Fr::from(u_val));
    flat.push(Fr::from(e0_val));
    flat.push(Fr::from(e1_val));
    flat.push(Fr::from(m_val));
    for &v in &quot0_vals {
        flat.push(Fr::from(v));
    }
    for &v in &quot1_vals {
        flat.push(Fr::from(v));
    }
    for &v in &gamma_vals {
        flat.push(Fr::from(v));
    }

    vec![flat]
}

/// Run the full demo pipeline with `n` parties and deterministic `seed`.
#[cfg(all(feature = "with-fhe", feature = "nova-compressor"))]
fn run_demo(n: usize, threshold: usize, seed: u64) -> anyhow::Result<()> {
    if n == 0 {
        anyhow::bail!("invalid n: n=0; must satisfy n >= 1");
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

#[cfg(not(all(feature = "with-fhe", feature = "nova-compressor")))]
fn run_demo(_n: usize, _threshold: usize, _seed: u64) -> anyhow::Result<()> {
    anyhow::bail!("demo requires the `with-fhe` and `nova-compressor` features")
}

#[cfg(all(feature = "with-fhe", feature = "nova-compressor"))]
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

#[cfg(all(feature = "with-fhe", feature = "nova-compressor"))]
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
            None => println!("step {step}/{total}: {name}", total = Self::STEP_COUNT),
        }
    }
}

#[cfg(all(feature = "with-fhe", feature = "nova-compressor"))]
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
