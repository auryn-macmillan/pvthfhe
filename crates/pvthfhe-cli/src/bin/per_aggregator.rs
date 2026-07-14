//! Aggregator node — LatticeFold+ (Track B) backend.
//!
//! Runs the aggregator-specific work from the demo pipeline:
//!  1. DKG key generation
//!  2. NIZK prove (encryption proof per party)
//!  3. NIZK verify (cross-verify all proofs)
//!  4. Cyclo fold session binding (LatticeFold+ accumulation hash)

use anyhow::Context;
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

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!(
        "aggregator (Track B — LatticeFold+): n={}, t={}, seed={}",
        args.n, args.threshold, args.seed
    );
    if args.n < 2 || args.threshold > args.n {
        anyhow::bail!("require n >= 2 and threshold <= n");
    }

    let overall_t0 = Instant::now();

    // ── DKG keygen ──
    let t0 = Instant::now();
    println!("  keygen: starting... (n={}, t={})", args.n, args.threshold);
    let mut dkg = pvthfhe_keygen::dkg::DkgCeremony::new(pvthfhe_keygen::dkg::DkgParams {
        n: args.n,
        t: args.threshold,
        round_timeout: None,
    })?;
    dkg.run()?;
    let pk = dkg.public_key()?;
    println!(
        "  keygen: ok ({:.1} ms)",
        t0.elapsed().as_secs_f64() * 1000.0
    );

    // ── NIZK prove (one sigma proof per party) ──
    let t1 = Instant::now();
    println!("  nizk_prove: generating {} proofs...", args.n);
    use pvthfhe_fhe::fhers::FhersBackend;
    use pvthfhe_fhe::real_nizk::{
        LatticeNizk, NizkProof, NizkStatement, NizkWitness, RealNizkAdapter,
    };
    use pvthfhe_fhe::{FheBackend, PublicKey};
    use rand_core::RngCore;
    use sha2::{Digest, Sha256};

    let backend = FhersBackend::load_params(
        "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n"
    ).context("backend init")?;

    let mut proofs: Vec<(u16, NizkStatement, NizkProof)> = Vec::with_capacity(args.n);
    for party_id in 1..=args.n as u16 {
        let mut pt = vec![(party_id as u8).wrapping_mul(17)];
        pt.resize(8, 0);
        let mut sid = [0u8; 32];
        pvthfhe_rng::OsRng.fill_bytes(&mut sid);
        let pk = PublicKey {
            bytes: pk.bytes.clone(),
        };
        let ct = backend.encrypt(&pk, &pt, &mut pvthfhe_rng::OsRng)?;

        let stmt = NizkStatement {
            ciphertext_bytes: ct.bytes.clone(),
            decrypt_share_bytes: ct.bytes[..32.min(ct.bytes.len())].to_vec(),
            pvss_commitment: Sha256::digest(&sid).into(),
            params: (288230376173076481, 8192, 10),
            session_id: hex::encode(&sid),
            participant_id: party_id,
            epoch: 0,
            c_rns_override: None,
            d_rns_override: None,
        };
        let witness = NizkWitness {
            secret_share: u64::from_le_bytes(pt[..8].try_into().unwrap_or([0u8; 8])),
            secret_share_poly: {
                let mut v = vec![0i64; 8192];
                v[0] = 1; // minimal non-zero witness
                v
            },
            error: vec![0i64; 8192],
            randomness: sid.to_vec(),
        };
        let proof = RealNizkAdapter::prove(&stmt, &witness, &mut pvthfhe_rng::OsRng)?;
        proofs.push((party_id, stmt, proof));
    }
    let prove_ms = t1.elapsed().as_secs_f64() * 1000.0;
    println!("  nizk_prove: ok ({:.1} ms)", prove_ms);

    // ── NIZK verify (cross-verify) ──
    let t2 = Instant::now();
    println!("  nizk_verify: cross-verifying {} proofs...", proofs.len());
    for (party_id, stmt, proof) in &proofs {
        RealNizkAdapter::verify(stmt, proof)
            .with_context(|| format!("nizk_verify party {party_id}"))?;
    }
    let verify_ms = t2.elapsed().as_secs_f64() * 1000.0;
    println!("  nizk_verify: ok ({:.1} ms)", verify_ms);

    // ── Cyclo fold — real LatticeFold NIFS ──
    let t3 = Instant::now();
    println!("  cyclo_fold: real folding {} instances...", proofs.len());

    use pvthfhe_cyclo::{
        ajtai::{self, AjtaiParams},
        fold as cyclo_fold,
        ring::{RqPoly, PHI_COMMIT, Q_COMMIT},
        CcsPShareInstance,
    };
    use pvthfhe_types::{CcsWitnessSecret, ProtocolBytes};

    // Deterministic Ajtai parameters matching the production locked params.
    let ajtai_params = AjtaiParams {
        m: 13,
        n: 1,
        q_commit: Q_COMMIT,
        seed: [0x42u8; 32],
    };

    // Build a CCS witness in Fr-LE wire format: [u32 BE len][Fr LE element]
    let make_ccs_witness = |val: u64| -> CcsWitnessSecret {
        let len_be = 1u32.to_be_bytes();
        let mut fr = [0u8; 32];
        fr[..8].copy_from_slice(&val.to_le_bytes());
        let mut bytes = Vec::with_capacity(36);
        bytes.extend_from_slice(&len_be);
        bytes.extend_from_slice(&fr);
        CcsWitnessSecret::new(bytes)
    };

    // Build an all-zero 1×1 CCS matrix for trivially-satisfiable satisfiability check.
    // Format: [rows:u32 BE][cols:u32 BE][data: rows*cols * 32-byte Fr LE]
    let ccs_matrix: Vec<u8> = {
        let rows: u32 = 1;
        let cols: u32 = 1;
        let mut m = Vec::with_capacity(8 + 32);
        m.extend_from_slice(&rows.to_be_bytes());
        m.extend_from_slice(&cols.to_be_bytes());
        m.extend_from_slice(&[0u8; 32]);
        m
    };

    let mut fold_instances: Vec<CcsPShareInstance> = Vec::with_capacity(proofs.len());
    for (party_id, stmt, _proof) in &proofs {
        // Build a distinct RqPoly per party
        let coeffs = vec![(*party_id as u64) % Q_COMMIT; PHI_COMMIT];
        let witness = RqPoly(coeffs);
        let commitment = ajtai::commit(&ajtai_params, &[witness], &mut pvthfhe_rng::OsRng)
            .context("ajtai commit")?;
        let commitment_bytes = ajtai::encode_commitment(&commitment);

        let ccs_witness = make_ccs_witness(*party_id as u64);
        let public_io = {
            let mut h = Sha256::new();
            h.update(stmt.session_id.as_bytes());
            h.update(stmt.participant_id.to_be_bytes());
            h.update(ccs_witness.expose());
            h.finalize().to_vec()
        };

        let binding = {
            let mut h = Sha256::new();
            h.update(&commitment_bytes);
            h.update(&public_io);
            h.update(ccs_witness.expose());
            let hash: [u8; 32] = h.finalize().into();
            hash
        };

        fold_instances.push(CcsPShareInstance {
            participant_id: *party_id,
            ajtai_commitment_bytes: ProtocolBytes(commitment_bytes),
            public_io_bytes: ProtocolBytes(public_io),
            ccs_witness_bytes: ccs_witness,
            sha256_binding_bytes: ProtocolBytes(binding.to_vec()),
            ccs_matrix_bytes: ProtocolBytes(ccs_matrix.clone()),
        });
    }

    // Sequential T=10 folding (init with first instance, then fold ALL including the first)
    let session_id = "per-aggregator-bench";
    let mut acc = cyclo_fold::init_accumulator(&fold_instances[0], session_id)
        .context("fold init")?;
    for instance in &fold_instances {
        acc = cyclo_fold::fold_one_step(acc, instance, &mut pvthfhe_rng::OsRng)
            .context("fold step")?;
    }
    cyclo_fold::verify_fold(&acc, &fold_instances)
        .context("fold verify")?;

    let fold_ms = t3.elapsed().as_secs_f64() * 1000.0;
    println!("  cyclo_fold: ok ({:.1} ms)", fold_ms);

    let total_ms = overall_t0.elapsed().as_secs_f64() * 1000.0;
    println!();
    println!("  ── Summary ──");
    println!("  parties:       {:>8}", args.n);
    println!("  threshold:     {:>8}", args.threshold);
    println!(
        "  keygen:        {:>8.1} ms",
        (t1 - t0).as_secs_f64() * 1000.0
    );
    println!("  nizk_prove:    {:>8.1} ms  ({} proofs)", prove_ms, args.n);
    println!(
        "  nizk_verify:   {:>8.1} ms  ({} proofs)",
        verify_ms, args.n
    );
    println!("  cyclo_fold:    {:>8.1} ms", fold_ms);
    println!("  ───────────────");
    println!("  total:         {:>8.1} ms", total_ms);
    println!(
        "  fold_depth:    {} ({} instances in 1 accumulator)",
        acc.fold_depth,
        fold_instances.len()
    );

    Ok(())
}
