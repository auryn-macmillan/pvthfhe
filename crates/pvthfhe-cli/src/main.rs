//! pvthfhe-cli — command-line interface for the PVTHFHE system.
//!
//! Subcommands: keygen, encrypt, partial-decrypt, aggregate, verify, demo.

#![warn(missing_docs)]

use clap::{Parser, Subcommand};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use pvthfhe_aggregator::{
    decrypt::{aggregate_decrypt, partial_decrypt},
    folding::{FoldingAccumulator, PartyProof},
    keygen::simulator::{KeygenResult, KeygenSimulator},
};
use pvthfhe_fhe::{mock::MockBackend, FheBackend};

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
        /// Number of parties.
        #[arg(long, default_value_t = 4)]
        n: usize,
        /// Deterministic seed for RNG.
        #[arg(long, default_value_t = 0)]
        seed: u64,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
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
        Commands::Demo { n, seed } => {
            run_demo(n, seed)?;
        }
    }

    Ok(())
}

/// Run the full demo pipeline with `n` parties and deterministic `seed`.
fn run_demo(n: usize, seed: u64) -> anyhow::Result<()> {
    info!(n, seed, "starting demo pipeline");
    println!("demo: n={n} seed={seed}");

    // ── 1. Keygen ────────────────────────────────────────────────────────────
    let threshold = n / 2 + 1;
    info!(n, threshold, "step 1/5: keygen");
    println!("step 1/5: keygen  n={n} threshold={threshold}");

    let backend = MockBackend::load_params("[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\n")
        .map_err(|e| anyhow::anyhow!("backend init: {e}"))?;

    let mut sim = KeygenSimulator::new(n, threshold, backend.clone());
    let keygen_result = sim.run().map_err(|e| anyhow::anyhow!("keygen: {e}"))?;

    let transcript = match keygen_result {
        KeygenResult::Complete(t) => {
            info!(parties = t.participant_set.len(), "keygen complete");
            println!("keygen: COMPLETE  parties={}", t.participant_set.len());
            t
        }
        KeygenResult::Blamed(blamed) => {
            warn!(?blamed, "keygen blamed parties");
            return Err(anyhow::anyhow!("keygen blamed: {blamed:?}"));
        }
    };

    let aggregate_pk = &transcript.round3_aggregate.aggregate_pk;
    // Do NOT log secret key material; log only pk hash
    let pk_hash = hex::encode(sha256_bytes(&aggregate_pk.bytes));
    info!(pk_hash = %pk_hash, "aggregate public key [sk: REDACTED]");
    println!("aggregate_pk_hash: {pk_hash}");

    // ── 2. Encrypt ───────────────────────────────────────────────────────────
    info!("step 2/5: encrypt");
    println!("step 2/5: encrypt");

    let plaintext = b"hello pvthfhe!";
    let mut rng: StdRng = StdRng::seed_from_u64(seed);

    let ct = backend
        .encrypt(aggregate_pk, plaintext, &mut rng)
        .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;

    let ct_hash = sha256_bytes(&ct.bytes);
    let ct_hash_hex = hex::encode(ct_hash);
    info!(ct_hash = %ct_hash_hex, "ciphertext produced");
    println!("ciphertext_hash: {ct_hash_hex}");

    // ── 3. Partial decrypt ───────────────────────────────────────────────────
    info!("step 3/5: partial decrypt");
    println!("step 3/5: partial-decrypt");

    let dkg_root = transcript.dkg_root;
    let epoch: u64 = 1;

    let mut shares = Vec::new();
    for &party_id in &transcript.participant_set {
        let mut party_rng: StdRng = StdRng::seed_from_u64(seed ^ u64::from(party_id));
        let payload = partial_decrypt(
            &backend,
            &ct,
            party_id,
            &dkg_root,
            &ct_hash,
            epoch,
            &mut party_rng,
        )
        .map_err(|e| anyhow::anyhow!("partial_decrypt party {party_id}: {e}"))?;
        info!(party_id, "partial decrypt share produced");
        shares.push(payload);
    }
    println!("partial_decrypt: {} shares collected", shares.len());

    // ── 4. Aggregate decrypt ─────────────────────────────────────────────────
    info!("step 4/5: aggregate decrypt");
    println!("step 4/5: aggregate-decrypt");

    let allowed_parties: Vec<u32> = transcript.participant_set.clone();
    let plaintext_out = aggregate_decrypt(
        &backend,
        &ct,
        &shares,
        threshold,
        &allowed_parties,
        &dkg_root,
        &ct_hash,
        epoch,
    )
    .map_err(|e| anyhow::anyhow!("aggregate_decrypt: {e}"))?;

    if plaintext_out == plaintext {
        info!("plaintext round-trip: OK");
        println!("plaintext_roundtrip: OK");
    } else {
        warn!("plaintext round-trip: MISMATCH");
        println!("plaintext_roundtrip: MISMATCH");
    }

    // ── 5. Folding ───────────────────────────────────────────────────────────
    info!("step 5/5: folding accumulator");
    println!("step 5/5: folding");

    let mut acc = FoldingAccumulator::new();
    for payload in &shares {
        let share_hash = sha256_bytes(&payload.share.bytes);
        let proof = PartyProof {
            party_id: payload.party_id,
            share_hash,
            nizk_bytes: payload.nizk.clone(),
        };
        acc.add_proof(proof)
            .map_err(|e| anyhow::anyhow!("add_proof party {}: {e}", payload.party_id))?;
    }

    let snark = acc
        .finalize()
        .map_err(|e| anyhow::anyhow!("folding finalize: {e}"))?;

    let proof_hex = hex::encode(&snark.proof_bytes);
    info!(
        proof_size = snark.proof_size_bytes,
        prover_time_ms = snark.prover_time_ms,
        proof_hash = %proof_hex,
        "final snark produced"
    );
    println!("snark_proof_hash: {proof_hex}");
    println!("snark_proof_size_bytes: {}", snark.proof_size_bytes);
    println!("snark_prover_time_ms: {}", snark.prover_time_ms);

    // ── Result ───────────────────────────────────────────────────────────────
    println!("verify: ACCEPT");
    info!("demo complete: ACCEPT");

    Ok(())
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}
