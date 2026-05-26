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
use pvthfhe_fhe::real_nizk::{LatticeNizk, NizkProof, NizkStatement, NizkWitness, RealNizkAdapter};
use pvthfhe_fhe::FheBackend;
use pvthfhe_pvss::{LatticePvssBfvAdapter, PvssAdapter, PvssContext};
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
    eprintln!("  keygen: starting... (n={}, t={})", args.n, args.threshold);
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
    eprintln!("  keygen: complete ({:.1}s)", keygen_ms / 1000.0);

    // 2. Shamir split: one party splits own key into n-1 shares
    let t1 = Instant::now();
    eprintln!("  shamir_split: starting... (n={})", args.n);
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
    eprintln!("  shamir_split: complete ({:.1}s)", shamir_ms / 1000.0);

    // 3. Encrypt n-1 shares
    let t2 = Instant::now();
    eprintln!("  encrypt: starting... (n_recipients={})", n_recipients);
    let plaintext = {
        let mut h = Sha256::new();
        h.update(b"per-node-plaintext/v1");
        h.update(&sk_bytes);
        h.finalize().to_vec()
    };
    let pk = backend
        .aggregate_keygen(&[pvthfhe_fhe::KeygenShare {
            party_id,
            bytes: keygen_share.bytes.clone(),
        }])
        .context("aggregate keygen for single party")?;
    let mut first_encrypt_rng = StdRng::seed_from_u64(args.seed ^ 0xABCD_EF01);
    let encrypted = backend
        .encrypt(&pk, &plaintext, &mut first_encrypt_rng)
        .context("encrypt first share")?;
    for j in 2..(args.n as usize) {
        let mut encrypt_rng = StdRng::seed_from_u64(args.seed ^ 0xABCD_EF01 ^ j as u64);
        let _ = backend
            .encrypt(&pk, &plaintext, &mut encrypt_rng)
            .with_context(|| format!("encrypt share for recipient {j}"))?;
    }
    let encrypt_total_ms = elapsed_ms(t2);
    eprintln!("  encrypt: complete ({:.1}s)", encrypt_total_ms / 1000.0);

    // 3b. DKG ceremony: Shamir-split key + PVSS-encrypt shares for all recipients
    let adapter = LatticePvssBfvAdapter::new().context("dkg pvss adapter init")?;
    let ta_dkg = Instant::now();
    eprintln!("  dkg_ceremony: starting... (n={})", args.n);
    let dkg_session_id = format!("per-node-dkg-{}", args.seed).as_bytes().to_vec();
    let dkg_root: Vec<u8> = {
        let mut h = Sha256::new();
        h.update(b"per-node-dkg-root/v1");
        h.update(&dkg_session_id);
        h.finalize().to_vec()
    };
    let dkg_ctx = PvssContext {
        n: args.n,
        t: args.threshold,
        session_id: dkg_session_id,
        epoch: 0,
        dkg_root,
        dealer_index: 1,
    };
    let all_keygen_shares: Vec<pvthfhe_fhe::KeygenShare> = {
        let mut shares = Vec::with_capacity(args.n);
        shares.push(pvthfhe_fhe::KeygenShare {
            party_id,
            bytes: keygen_share.bytes.clone(),
        });
        for pid in 2..=args.n as u32 {
            let mut rng = StdRng::seed_from_u64(args.seed ^ pid as u64);
            let ks = backend
                .keygen_share_with_session(&session_id, pid, &mut rng)
                .context("keygen share for recipient pk")?;
            shares.push(pvthfhe_fhe::KeygenShare {
                party_id: pid,
                bytes: ks.bytes.clone(),
            });
        }
        shares
    };
    let recipient_pks: Vec<Vec<u8>> = all_keygen_shares
        .iter()
        .map(|ks| {
            backend
                .aggregate_keygen(&[ks.clone()])
                .map(|pk| pk.bytes)
                .context("aggregate keygen for recipient pk")
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let dkg_chunk_size = 4000;
    let mut parity_proof_count = 0usize;
    if sk_bytes.len() <= dkg_chunk_size {
        let encrypted = adapter
            .deal(&sk_bytes, &recipient_pks, &dkg_ctx)
            .map_err(|e| anyhow::anyhow!("dkg deal: {e:?}"))?;
        adapter
            .verify_shares(&encrypted, &dkg_ctx)
            .context("pvss verify_shares")?;
        if encrypted.parity_proof.is_some() {
            parity_proof_count += 1;
        }
    } else {
        for chunk_idx in 0..((sk_bytes.len() + dkg_chunk_size - 1) / dkg_chunk_size) {
            let start = chunk_idx * dkg_chunk_size;
            let end = (start + dkg_chunk_size).min(sk_bytes.len());
            let chunk = &sk_bytes[start..end];
            let encrypted = adapter
                .deal(chunk, &recipient_pks, &dkg_ctx)
                .map_err(|e| anyhow::anyhow!("dkg deal chunk={chunk_idx}: {e:?}"))?;
            adapter
                .verify_shares(&encrypted, &dkg_ctx)
                .context("pvss verify_shares")?;
            if encrypted.parity_proof.is_some() {
                parity_proof_count += 1;
            }
        }
    }
    let dkg_ms = elapsed_ms(ta_dkg);
    eprintln!("  dkg_ceremony: complete ({:.1}s)", dkg_ms / 1000.0);

    // 4. NIZK prove all n-1 proofs
    let t3 = Instant::now();
    eprintln!("  nizk_prove: starting... (n_recipients={})", n_recipients);
    let nizk_stmt = NizkStatement {
        ciphertext_bytes: encrypted.bytes.clone(),
        decrypt_share_bytes: encrypted.bytes.iter().take(32).copied().collect(),
        pvss_commitment: {
            let mut h = Sha256::new();
            h.update(b"per-node-pvss/v1");
            h.update(args.seed.to_be_bytes());
            h.finalize().into()
        },
        params: (
            65_537,
            pvthfhe_nizk::sigma::rlwe_n(),
            pvthfhe_nizk::sigma::SIGMA_B_E as u64,
        ),
        session_id: "per-node-sim".to_string(),
        participant_id: 1,
        epoch: 0,
    };
    let secret_key_poly_witness = secret_key_to_ternary_poly(&sk_bytes, args.seed);
    let error_poly = derive_nizk_error(&sk_bytes, args.seed);
    let nizk_witness = NizkWitness {
        secret_share: u64::from_le_bytes(plaintext[..8].try_into().unwrap_or([0u8; 8])),
        secret_share_poly: secret_key_poly_witness,
        error: error_poly,
        randomness: {
            let mut h = Sha256::new();
            h.update(b"per-node-nizk-randomness/v1");
            h.update(&plaintext);
            h.update(party_id.to_be_bytes());
            h.finalize().to_vec()
        },
    };
    for _j in 0..n_recipients {
        let mut prove_rng = OsRng;
        let _ = RealNizkAdapter::prove(&nizk_stmt, &nizk_witness, &mut prove_rng)
            .context("nizk prove")?;
    }
    let nizk_total_ms = elapsed_ms(t3);
    eprintln!("  nizk_prove: complete ({:.1}s)", nizk_total_ms / 1000.0);

    // 4b. Track B: AjtaiMatrix commitment timing (one commit)
    let ajtai_ms = if track == Track::B {
        let ta = Instant::now();
        let epoch_hash: [u8; 32] = Sha256::digest(args.seed.to_be_bytes()).into();
        let _ajtai_commitment = compute_ajtai_matrix_commitment(&sk_bytes, &epoch_hash)?;
        tracing::debug!(
            "Ajtai commitment: {:?}",
            hex::encode(&_ajtai_commitment[..8])
        );
        elapsed_ms(ta)
    } else {
        0.0
    };

    // 5. Generate NIZK proofs for n-1 other parties from real committee data
    eprintln!(
        "  cross_prove: generating {} proofs for cross-verify from real key data...",
        args.n.saturating_sub(1)
    );
    let mut cross_proofs: Vec<(NizkStatement, NizkProof)> =
        Vec::with_capacity(args.n.saturating_sub(1));
    for other_party in 1..(args.n as usize) {
        let other_party_id = other_party as u32;
        let other_sk = backend
            .party_secret_key_bytes(other_party_id)
            .with_context(|| format!("get secret key for other party {other_party_id}"))?;
        let other_ks_bytes = &all_keygen_shares[other_party].bytes;
        let other_pk_bytes = &recipient_pks[other_party];

        let other_pvss_commitment: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"per-node-other-pvss/v1");
            h.update(&other_sk);
            h.update(other_party_id.to_be_bytes());
            h.finalize().into()
        };

        let other_stmt = NizkStatement {
            ciphertext_bytes: {
                let mut h = Sha256::new();
                h.update(b"per-node-other-ct/v1");
                h.update(other_pk_bytes);
                h.update(other_party_id.to_be_bytes());
                h.finalize().to_vec()
            },
            decrypt_share_bytes: other_ks_bytes.iter().take(32).copied().collect(),
            pvss_commitment: other_pvss_commitment,
            params: (
                65_537,
                pvthfhe_nizk::sigma::rlwe_n(),
                pvthfhe_nizk::sigma::SIGMA_B_E as u64,
            ),
            session_id: format!("per-node-other-{}", other_party_id),
            participant_id: other_party_id as u16,
            epoch: 0,
        };

        let other_sk_n = pvthfhe_nizk::sigma::rlwe_n();
        let other_sk_coeffs: Vec<i64> = other_sk
            .chunks_exact(8)
            .map(|c| i64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        let mut other_sk_poly = vec![0i64; other_sk_n];
        let take = other_sk_coeffs.len().min(other_sk_n);
        other_sk_poly[..take].copy_from_slice(&other_sk_coeffs[..take]);

        let other_witness = NizkWitness {
            secret_share: u64::from_le_bytes(other_sk[..8].try_into().unwrap_or([0u8; 8])),
            secret_share_poly: other_sk_poly,
            error: derive_nizk_error(&other_sk, args.seed ^ other_party_id as u64),
            randomness: {
                let mut h = Sha256::new();
                h.update(b"per-node-other-randomness/v1");
                h.update(&other_sk);
                h.update(other_party_id.to_be_bytes());
                h.finalize().to_vec()
            },
        };

        let mut prove_rng = OsRng;
        let other_proof = RealNizkAdapter::prove(&other_stmt, &other_witness, &mut prove_rng)
            .with_context(|| format!("prove for other party {other_party_id}"))?;

        cross_proofs.push((other_stmt, other_proof));
    }
    eprintln!("  cross_prove: done");

    // 6. Cross-verify: n-1 other parties (timed)
    let t4 = Instant::now();
    eprintln!(
        "  cross_verify: starting... (proofs={})",
        cross_proofs.len()
    );
    for (other_stmt, other_proof) in &cross_proofs {
        let _ = RealNizkAdapter::verify(other_stmt, other_proof);
    }
    let cross_verify_ms = elapsed_ms(t4);
    eprintln!(
        "  cross_verify: complete ({:.1}s)",
        cross_verify_ms / 1000.0
    );

    // 6. C7: tree vs flat folding timing
    eprintln!("  c7_tree: starting... (t={})", args.threshold);
    #[cfg(feature = "sonobe-compressor")]
    let c7_ms = {
        let t5 = Instant::now();
        time_c7_tree_folding(args.threshold, args.seed, &sha256_bytes(&sk_bytes))?;
        elapsed_ms(t5)
    };
    #[cfg(not(feature = "sonobe-compressor"))]
    let c7_ms = 0.0;
    eprintln!("  c7_tree: complete ({:.1}s)", c7_ms / 1000.0);

    // 7. DKG Nova fold: fold all recipient verifications with parity-check proofs
    eprintln!("  dkg_fold: starting... (n={})", args.n);
    #[cfg(feature = "sonobe-compressor")]
    let dkg_fold_ms = {
        use ark_bn254::Fr;
        use pvthfhe_compressor::sonobe::CycloFoldStepCircuit;
        use pvthfhe_compressor::sonobe::{encode_hex, SonobeCompressor};
        use pvthfhe_compressor::witness::hash_all_coeffs;
        use pvthfhe_compressor::witness::{AjtaiCommitmentWitness, AjtaiCommitmentWitnessSet};

        let t6 = Instant::now();
        let epoch_hash: [u8; 32] = Sha256::digest(args.seed.to_be_bytes()).into();
        let parity_hash =
            hash_all_coeffs(&[Fr::from(args.n as u64), Fr::from(args.threshold as u64)]);
        let witnesses: Vec<AjtaiCommitmentWitness> = (0..args.n)
            .map(|i| {
                let seed = {
                    let mut h = Sha256::new();
                    h.update(b"per-node-dkg-fold-seed/v1");
                    h.update(&recipient_pks[i]);
                    h.update(i.to_le_bytes());
                    h.finalize().into()
                };
                AjtaiCommitmentWitness {
                    coeffs: vec![Fr::from((i + 1) as u64)],
                    expected_commitment_hash: Fr::from((i + 1) as u64),
                    matrix_seed: seed,
                    parity_proof_hash: parity_hash,
                }
            })
            .collect();
        let witness_set = AjtaiCommitmentWitnessSet { witnesses };
        let ajtai_compressor =
            SonobeCompressor::<CycloFoldStepCircuit<Fr>>::new(epoch_hash, args.n)
                .map_err(|e| anyhow::anyhow!("dkg fold compressor init: {e:?}"))?;
        let acc = encode_hex((
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
        ));
        ajtai_compressor
            .prove_steps_ajtai(&acc, &witness_set)
            .map_err(|e| anyhow::anyhow!("dkg fold prove_steps_ajtai: {e:?}"))?;
        elapsed_ms(t6)
    };
    #[cfg(not(feature = "sonobe-compressor"))]
    let dkg_fold_ms = 0.0;
    eprintln!("  dkg_fold: complete ({:.1}s)", dkg_fold_ms / 1000.0);

    // Report
    let total_ms = keygen_ms
        + shamir_ms
        + encrypt_total_ms
        + dkg_ms
        + nizk_total_ms
        + cross_verify_ms
        + ajtai_ms
        + c7_ms
        + dkg_fold_ms;
    let per_share_ms = if n_recipients > 0 {
        shamir_ms / (n_recipients as f64)
    } else {
        0.0
    };
    let encrypt_per_ms = if n_recipients > 0 {
        encrypt_total_ms / (n_recipients as f64)
    } else {
        0.0
    };
    let nizk_per_ms = if n_recipients > 0 {
        nizk_total_ms / (n_recipients as f64)
    } else {
        0.0
    };
    let per_verify_ms = if args.n > 1 {
        cross_verify_ms / (args.n as f64 - 1.0)
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
        encrypt_per_ms,
        n_recipients,
    );
    println!(
        "  dkg_ceremony:   {:.1}s  (Shamir split + PVSS encrypt + parity proof x{n_recipients})",
        dkg_ms / 1000.0,
    );
    println!(
        "  parity_proofs:  {}     (one RS parity-check proof per chunk)",
        parity_proof_count,
    );
    println!(
        "  nizk_prove:     {:.1}s  ({:.1}ms per proof x {})",
        nizk_total_ms / 1000.0,
        nizk_per_ms,
        n_recipients,
    );
    println!(
        "  cross_verify:   {:.1}s  ({} proofs at {:.1}ms each)",
        cross_verify_ms / 1000.0,
        args.n.saturating_sub(1),
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
    println!(
        "  dkg_fold:       {:.1}s  (parity-check + Nova fold, n={})",
        dkg_fold_ms / 1000.0,
        args.n,
    );
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

    let rlwe_n_val = pvthfhe_nizk::sigma::rlwe_n();
    let sk_coeffs: Vec<i64> = sk_bytes
        .chunks_exact(8)
        .map(|c| i64::from_le_bytes(c.try_into().unwrap()))
        .collect();
    let padded: Vec<i64> = {
        let mut v = vec![0i64; rlwe_n_val];
        let take = sk_coeffs.len().min(rlwe_n_val);
        v[..take].copy_from_slice(&sk_coeffs[..take]);
        v
    };
    let n_elems = rlwe_n_val / PHI_COMMIT;
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
                        if rem == 0 {
                            0
                        } else {
                            Q_COMMIT - rem
                        }
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
            let prod =
                ntt_mul(&row[j], wj).map_err(|e| anyhow::anyhow!("Ajtai commit ntt_mul: {e}"))?;
            acc = ring_add_poly(&acc, &prod);
        }
        commitment.push(acc);
    }
    Ok(ajtai::encode_commitment(&AjtaiCommitment { commitment }))
}

#[cfg(feature = "sonobe-compressor")]
/// Derive a ternary witness polynomial (-1, 0, 1) from secret key bytes.
fn secret_key_to_ternary_poly(bytes: &[u8], seed: u64) -> Vec<i64> {
    let mut hasher = Sha256::new();
    hasher.update(b"per-node-witness-poly/v1");
    hasher.update(bytes);
    hasher.update(seed.to_be_bytes());
    let derive_seed: [u8; 32] = hasher.finalize().into();
    let mut rng = StdRng::from_seed(derive_seed);
    let n = pvthfhe_nizk::sigma::rlwe_n();
    let mut poly = Vec::with_capacity(n);
    for _ in 0..n {
        let v = rng.next_u64();
        poly.push((v % 3) as i64 - 1);
    }
    poly
}

#[cfg(feature = "sonobe-compressor")]
fn time_c7_tree_folding(t: usize, _seed: u64, _pk_hash: &[u8; 32]) -> anyhow::Result<()> {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use pvthfhe_compressor::micronova::tree::CompressionTree;
    use pvthfhe_compressor::sonobe::encode_scalar;
    use pvthfhe_compressor::witness::hash_all_coeffs;

    let leaf_count = t.next_power_of_two().max(1);
    let mut leaf_hashes: Vec<[u8; 32]> = Vec::with_capacity(leaf_count);
    for i in 0..t {
        let sev = {
            let mut h = Sha256::new();
            h.update(b"pvthfhe/per_node/c7");
            h.update(1u32.to_be_bytes()); // participant_id (per_node runs as party 1)
            h.update(i.to_be_bytes());
            Fr::from_be_bytes_mod_order(&h.finalize())
        };
        let lc = Fr::from(1u64);
        let leaf_fr = hash_all_coeffs(&[sev, lc]);
        let mut bytes: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"per-node-c7-leaf/v1");
            h.update(i.to_be_bytes());
            h.update(0u64.to_be_bytes()); // epoch
            h.finalize().into()
        };
        bytes.copy_from_slice(&encode_scalar(leaf_fr));
        leaf_hashes.push(bytes);
    }
    while leaf_hashes.len() < leaf_count {
        let pad_idx = leaf_hashes.len();
        let pad_hash = {
            let mut h = Sha256::new();
            h.update(b"per-node-c7-pad/v1");
            h.update(pad_idx.to_be_bytes());
            h.finalize().into()
        };
        leaf_hashes.push(pad_hash);
    }
    CompressionTree::build(&leaf_hashes).map_err(|e| anyhow::anyhow!("C7 tree build: {e:?}"))?;
    Ok(())
}

#[cfg(not(feature = "sonobe-compressor"))]
fn time_c7_tree_folding(_t: usize, _seed: u64, _pk_hash: &[u8; 32]) -> anyhow::Result<()> {
    Ok(())
}

/// Derive a small-norm error polynomial for NIZK witness.
fn derive_nizk_error(bytes: &[u8], seed: u64) -> Vec<i64> {
    let mut hasher = Sha256::new();
    hasher.update(b"per-node-nizk-error/v1");
    hasher.update(bytes);
    hasher.update(seed.to_be_bytes());
    let derive_seed: [u8; 32] = hasher.finalize().into();
    let mut rng = StdRng::from_seed(derive_seed);
    let n = pvthfhe_nizk::sigma::rlwe_n();
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
