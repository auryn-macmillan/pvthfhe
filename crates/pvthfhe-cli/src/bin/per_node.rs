//! Per-node scaling simulation: measures wall time for ONE party
//! at arbitrary n and t, reflecting real O(n) per-party deployments.
//!
//! # Usage
//!
//! ```bash
//! cargo run --bin per-node -- --n 100 --threshold 25
//! ```

#![warn(missing_docs)]

use anyhow::Context;
use clap::Parser;
use pvthfhe_fhe::fhers::FhersBackend;
use pvthfhe_fhe::real_nizk::{LatticeNizk, NizkStatement, NizkWitness, RealNizkAdapter};
use pvthfhe_fhe::FheBackend;
use pvthfhe_rng::OsRng;
use rand::rngs::StdRng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Track {
    A,
    B,
}

const DEMO_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 131072\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

/// Per-node scaling simulator.
#[derive(Debug, Parser)]
#[command(
    name = "per-node",
    version,
    about = "Simulate wall time for ONE party at arbitrary n and t"
)]
struct Args {
    /// Number of parties.
    #[arg(long, default_value = "10")]
    n: usize,

    /// Threshold.
    #[arg(long, default_value = "4")]
    threshold: usize,

    /// Deterministic seed.
    #[arg(long, default_value = "1")]
    seed: u64,

    /// Pipeline track: A = Cyclo (default), B = AjtaiMatrix.
    #[arg(long, default_value = "A")]
    track: String,

    /// Enable C7 Merkle tree folding (requires sonobe-compressor feature).
    #[arg(long, default_value_t = false)]
    use_c7_tree: bool,
}

fn main() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::init();
    let args = Args::parse();

    // Parse track
    let track = match args.track.to_uppercase().as_str() {
        "A" => Track::A,
        "B" => Track::B,
        other => anyhow::bail!("invalid track: {}. Use A or B.", other),
    };

    // Validate
    if args.threshold == 0 || args.threshold > args.n {
        anyhow::bail!(
            "threshold must satisfy 1 ≤ t ≤ n (got t={}, n={})",
            args.threshold,
            args.n
        );
    }
    let max_t = (args.n - 1) / 2;
    if args.threshold > max_t {
        anyhow::bail!(
            "threshold t must be <= floor((n-1)/2) = {} (got t={}, n={})",
            max_t,
            args.threshold,
            args.n
        );
    }

    let n_recipients = args.n.saturating_sub(1);

    // 1. Backend init + keygen for ONE party
    let t0 = Instant::now();
    let backend = FhersBackend::load_params(DEMO_PARAMS_TOML).context("backend init")?;

    let session_id: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"per-node-sim/v1");
        h.update(args.seed.to_be_bytes());
        h.update(args.n.to_be_bytes());
        h.finalize().into()
    };

    let party_id: u32 = 1;
    let mut keygen_rng = StdRng::seed_from_u64(args.seed);
    let keygen_share = backend
        .keygen_share_with_session(&session_id, party_id, &mut keygen_rng)
        .context("keygen share")?;
    let keygen_ms = elapsed_ms(t0);

    // 2. Shamir split: one party splits own key into n-1 shares
    let t1 = Instant::now();
    let sk_bytes = backend
        .party_secret_key_bytes(party_id)
        .context("get secret key")?;
    let sk_coeffs: Vec<i64> = sk_bytes
        .chunks_exact(8)
        .map(|c| i64::from_le_bytes(c.try_into().unwrap()))
        .collect();

    let bfv_params = backend.bfv_params().clone();
    let shamir_threshold = args.threshold.saturating_sub(1);
    let mut sm = fhe::trbfv::ShareManager::new(args.n, shamir_threshold, bfv_params.clone());
    let sk_poly = sm
        .coeffs_to_poly_level0(&sk_coeffs)
        .map_err(|e| anyhow::anyhow!("coeffs_to_poly: {e}"))?;
    let mut shamir_rng = StdRng::seed_from_u64(args.seed ^ party_id as u64);
    let _shares = sm
        .generate_secret_shares_from_poly(sk_poly, &mut shamir_rng)
        .map_err(|e| anyhow::anyhow!("generate shares: {e}"))?;
    let shamir_ms = elapsed_ms(t1);

    // 3. Encrypt ONE share, extrapolate x(n-1)
    let t2 = Instant::now();
    let plaintext = vec![0x42u8; 32];
    let pk = backend
        .aggregate_keygen(&[pvthfhe_fhe::KeygenShare {
            party_id,
            bytes: keygen_share.bytes.clone(),
        }])
        .context("aggregate keygen for single party")?;
    let mut encrypt_rng = StdRng::seed_from_u64(args.seed ^ 0xABCD_EF01);
    let encrypted = backend
        .encrypt(&pk, &plaintext, &mut encrypt_rng)
        .context("encrypt one share")?;
    let encrypt_one_ms = elapsed_ms(t2);
    let encrypt_total_ms = encrypt_one_ms * (n_recipients as f64);

    // 4. NIZK prove ONE proof, extrapolate x(n-1)
    let t3 = Instant::now();
    let nizk_stmt = NizkStatement {
        ciphertext_bytes: encrypted.bytes.clone(),
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment: {
            let mut h = Sha256::new();
            h.update(b"per-node-pvss/v1");
            h.update(args.seed.to_be_bytes());
            h.finalize().into()
        },
        params: (
            65_537,
            pvthfhe_nizk::sigma::RLWE_N,
            pvthfhe_nizk::sigma::SIGMA_B_E as u64,
        ),
        session_id: "per-node-sim".to_string(),
        participant_id: 1,
        epoch: 0,
    };
    let secret_key_poly_witness = secret_key_to_ternary_poly(&sk_bytes, args.seed);
    let error_poly = derive_nizk_error(&sk_bytes, args.seed);
    let nizk_witness = NizkWitness {
        secret_share: u64::from_le_bytes(
            plaintext[..8].try_into().unwrap_or([0u8; 8]),
        ),
        secret_share_poly: secret_key_poly_witness,
        error: error_poly,
        randomness: vec![0u8; 32],
    };
    let mut prove_rng = OsRng;
    let nizk_proof = RealNizkAdapter::prove(&nizk_stmt, &nizk_witness, &mut prove_rng)
        .context("nizk prove")?;
    let nizk_one_ms = elapsed_ms(t3);
    let nizk_total_ms = nizk_one_ms * (n_recipients as f64);

    // 4b. Track B: AjtaiMatrix commitment timing (one commit)
    let ajtai_ms = if track == Track::B {
        let ta = Instant::now();
        let epoch_hash: [u8; 32] = Sha256::digest(args.seed.to_be_bytes()).into();
        let _ajtai_commitment = compute_ajtai_matrix_commitment(&sk_bytes, &epoch_hash)?;
        tracing::debug!("Ajtai commitment: {:?}", hex::encode(&_ajtai_commitment[..8]));
        elapsed_ms(ta)
    } else {
        0.0
    };

    // 5. NIZK verify t-1 proofs (full measurement)
    let t4 = Instant::now();
    for _ in 0..args.threshold.saturating_sub(1) {
        RealNizkAdapter::verify(&nizk_stmt, &nizk_proof)
            .context("nizk verify")?;
    }
    let nizk_verify_ms = elapsed_ms(t4);

    // 6. C7: tree vs flat folding timing
    #[cfg(feature = "sonobe-compressor")]
    let c7_ms = {
        let t5 = Instant::now();
        if args.use_c7_tree {
            time_c7_tree_folding(args.threshold, args.seed, &sha256_bytes(&sk_bytes))?;
        } else {
            time_c7_flat_folding(args.threshold, args.seed)?;
        }
        elapsed_ms(t5)
    };
    #[cfg(not(feature = "sonobe-compressor"))]
    let c7_ms = 0.0;

    // Report
    let total_ms = keygen_ms + shamir_ms + encrypt_total_ms + nizk_total_ms + nizk_verify_ms
        + ajtai_ms + c7_ms;
    let per_share_ms = if n_recipients > 0 {
        shamir_ms / (n_recipients as f64)
    } else {
        0.0
    };
    let per_verify_ms = if args.threshold > 1 {
        nizk_verify_ms / (args.threshold as f64 - 1.0)
    } else {
        0.0
    };

    println!("per_node n={} t={}", args.n, args.threshold);
    println!(
        "  keygen:         {:.1}s  (one key pair, degree={})",
        keygen_ms / 1000.0,
        backend.bfv_params().degree(),
    );
    println!(
        "  shamir_split:   {:.1}s  ({:.1}ms per share x {})",
        shamir_ms / 1000.0,
        per_share_ms,
        n_recipients,
    );
    println!(
        "  encrypt:        {:.1}s  ({:.1}ms per share x {})",
        encrypt_total_ms / 1000.0,
        encrypt_one_ms,
        n_recipients,
    );
    println!(
        "  nizk_prove:     {:.1}s  ({:.1}ms per proof x {})",
        nizk_total_ms / 1000.0,
        nizk_one_ms,
        n_recipients,
    );
    println!(
        "  nizk_verify:    {:.1}s  ({} proofs at {:.1}ms each)",
        nizk_verify_ms / 1000.0,
        args.threshold.saturating_sub(1),
        per_verify_ms,
    );
    if track == Track::B {
        println!(
            "  ajtai_commit:   {:.1}s  (Track B AjtaiMatrix)",
            ajtai_ms / 1000.0,
        );
    }
    if args.use_c7_tree {
        println!(
            "  c7_tree_fold:   {:.1}s  (MicroNova tree, t={})",
            c7_ms / 1000.0,
            args.threshold,
        );
    } else {
        println!(
            "  c7_flat_fold:   {:.1}s  (Nova flat, t={})",
            c7_ms / 1000.0,
            args.threshold,
        );
    }
    println!("  total:          {:.1}s", total_ms / 1000.0);

    Ok(())
}

// Helpers

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn compute_ajtai_matrix_commitment(
    sk_bytes: &[u8],
    epoch_hash: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    use pvthfhe_cyclo::ajtai::{self, AjtaiCommitment};
    use pvthfhe_cyclo::ring::{ntt_mul, ring_add_poly, RqPoly, PHI_COMMIT, Q_COMMIT};

    const RLWE_N: usize = 8192;
    let sk_coeffs: Vec<i64> = sk_bytes
        .chunks_exact(8)
        .map(|c| i64::from_le_bytes(c.try_into().unwrap()))
        .collect();
    let padded: Vec<i64> = {
        let mut v = vec![0i64; RLWE_N];
        let take = sk_coeffs.len().min(RLWE_N);
        v[..take].copy_from_slice(&sk_coeffs[..take]);
        v
    };
    let n_elems = RLWE_N / PHI_COMMIT;
    let witness_polys: Vec<RqPoly> = padded
        .chunks(PHI_COMMIT)
        .map(|chunk| {
            let coeffs: Vec<u64> = chunk
                .iter()
                .map(|&c| {
                    if c >= 0 {
                        (c as u64) % Q_COMMIT
                    } else {
                        let rem = c.unsigned_abs() % Q_COMMIT;
                        if rem == 0 { 0 } else { Q_COMMIT - rem }
                    }
                })
                .collect();
            RqPoly::new(coeffs).map_err(|e| anyhow::anyhow!("Ajtai commit: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let m = pvthfhe_cyclo::PVTHFHE_CYCLO_PARAMS.ajtai_rank_a;
    let n = n_elems;
    let mut matrix: Vec<Vec<RqPoly>> = Vec::with_capacity(m);
    for row in 0..m {
        let mut matrix_row = Vec::with_capacity(n);
        for col in 0..n {
            let mut coeffs = Vec::with_capacity(PHI_COMMIT);
            for coeff_idx in 0..PHI_COMMIT {
                let mut hasher = Sha256::new();
                hasher.update(epoch_hash);
                hasher.update(&(row as u64).to_be_bytes());
                hasher.update(&(col as u64).to_be_bytes());
                hasher.update(&(coeff_idx as u64).to_be_bytes());
                let hash = hasher.finalize();
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&hash[..8]);
                coeffs.push(u64::from_le_bytes(arr) % Q_COMMIT);
            }
            matrix_row.push(
                RqPoly::new(coeffs)
                    .map_err(|e| anyhow::anyhow!("Ajtai commit matrix entry: {e}"))?,
            );
        }
        matrix.push(matrix_row);
    }

    let mut commitment: Vec<RqPoly> = Vec::with_capacity(m);
    for row in &matrix {
        let mut acc = RqPoly::zero();
        for (j, wj) in witness_polys.iter().enumerate() {
            let prod = ntt_mul(&row[j], wj)
                .map_err(|e| anyhow::anyhow!("Ajtai commit ntt_mul: {e}"))?;
            acc = ring_add_poly(&acc, &prod);
        }
        commitment.push(acc);
    }
    Ok(ajtai::encode_commitment(&AjtaiCommitment { commitment }))
}

#[cfg(feature = "sonobe-compressor")]
fn time_c7_tree_folding(t: usize, seed: u64, _pk_hash: &[u8; 32]) -> anyhow::Result<()> {
    use pvthfhe_compressor::micronova::tree::CompressionTree;

    let leaf_count = t.next_power_of_two().max(2);
    let leaf_hashes: Vec<[u8; 32]> = (0..leaf_count)
        .map(|i| {
            let mut h = Sha256::new();
            h.update(b"per-node-c7-leaf/v1");
            h.update(seed.to_be_bytes());
            h.update((i as u64).to_be_bytes());
            h.finalize().into()
        })
        .collect();

    let _tree = CompressionTree::build(&leaf_hashes)
        .map_err(|e| anyhow::anyhow!("C7 tree build failed: {e:?}"))?;
    Ok(())
}

#[cfg(feature = "sonobe-compressor")]
fn time_c7_flat_folding(t: usize, seed: u64) -> anyhow::Result<()> {
    use ark_bn254::Fr;
    use ark_ff::Zero;
    use pvthfhe_compressor::sonobe::{encode_triple, C7DecryptAggregationCircuit, ExternalInputs5, SonobeCompressor};
    use pvthfhe_compressor::witness::hash_all_coeffs;

    let epoch: [u8; 32] = Sha256::digest(seed.to_be_bytes()).into();
    let compressor = SonobeCompressor::<C7DecryptAggregationCircuit<Fr>>::new(epoch, t)
        .map_err(|e| anyhow::anyhow!("C7 compressor init: {e:?}"))?;
    let acc = encode_triple((Fr::zero(), Fr::zero(), Fr::zero()));
    // Compute valid commitment for the default all-zero coefficients
    let coeff_commitment = hash_all_coeffs(&vec![Fr::zero(); 8192]);
    let derived_r = hash_all_coeffs(&[coeff_commitment, Fr::zero()]);
    let steps: Vec<ExternalInputs5<Fr>> = (0..t)
        .map(|i| ExternalInputs5(Fr::from((42 + i) as u64), Fr::from(1u64), coeff_commitment, Fr::zero(), derived_r))
        .collect();
    let _proof = compressor
        .prove_steps_c7(&acc, &steps)
        .map_err(|e| anyhow::anyhow!("C7 prove_steps: {e:?}"))?;
    Ok(())
}

#[cfg(not(feature = "sonobe-compressor"))]
fn time_c7_tree_folding(_t: usize, _seed: u64, _pk_hash: &[u8; 32]) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(feature = "sonobe-compressor"))]
fn time_c7_flat_folding(_t: usize, _seed: u64) -> anyhow::Result<()> {
    Ok(())
}

/// Derive a ternary witness polynomial (-1, 0, 1) from secret key bytes.
fn secret_key_to_ternary_poly(bytes: &[u8], seed: u64) -> Vec<i64> {
    let mut hasher = Sha256::new();
    hasher.update(b"per-node-witness-poly/v1");
    hasher.update(bytes);
    hasher.update(seed.to_be_bytes());
    let derive_seed: [u8; 32] = hasher.finalize().into();
    let mut rng = StdRng::from_seed(derive_seed);
    let n = pvthfhe_nizk::sigma::RLWE_N;
    let mut poly = Vec::with_capacity(n);
    for _ in 0..n {
        let v = rng.next_u64();
        poly.push((v % 3) as i64 - 1);
    }
    poly
}

/// Derive a small-norm error polynomial for NIZK witness.
fn derive_nizk_error(bytes: &[u8], seed: u64) -> Vec<i64> {
    let mut hasher = Sha256::new();
    hasher.update(b"per-node-nizk-error/v1");
    hasher.update(bytes);
    hasher.update(seed.to_be_bytes());
    let derive_seed: [u8; 32] = hasher.finalize().into();
    let mut rng = StdRng::from_seed(derive_seed);
    let n = pvthfhe_nizk::sigma::RLWE_N;
    let b = pvthfhe_nizk::sigma::SIGMA_B_E as u64;
    let range = 2 * b + 1;
    let max_multiple = (u64::MAX / range) * range;
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let r = rng.next_u64();
        if r < max_multiple {
            out.push((r % range) as i64 - b as i64);
        }
    }
    out
}
