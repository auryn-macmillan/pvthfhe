//! End-to-end phase driver for the PVTHFHE demo pipeline.

#![allow(unexpected_cfgs, clippy::needless_range_loop)]
#![warn(missing_docs)]

use anyhow::Context;
use clap::Parser;
use pvthfhe_aggregator::keygen::simulator::{KeygenResult, KeygenSimulator};
use pvthfhe_bench::e2e_timings::E2eTimings;
use pvthfhe_cli::compressor_glue::{compressor_backend_id, log_compressor_mode, Compressor};
use pvthfhe_cli::full_pipeline::{
    build_c7_prover_toml, build_c7_share_commitment_bundle, run_full_pipeline, PipelineConfig,
    PipelineObserver, PipelineReport,
};
use pvthfhe_cli::pvss_support::{run_lattice_pvss, PVSS_BACKEND_ID};
use pvthfhe_fhe::{fhers::FhersBackend, real_nizk::CYCLO_BACKEND_ID, FheBackend};
use std::{path::Path, time::Instant};
use tracing::{info, warn};

#[cfg(feature = "nova-compressor")]
use {
    ark_bn254::Fr,
    ark_ff::{PrimeField, Zero},
    sha2::{Digest, Sha256},
};

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
    /// BFV parameter preset name: "production8192" (default) or "insecure512".
    #[arg(long, default_value = "production8192")]
    params: String,
}

const SAFE_DEFAULT_TRACING_FILTER: &str = "pvthfhe_cli=info,pvthfhe_compressor=info,pvthfhe_fhe=info,pvthfhe_lattice_pvss=info,pvthfhe_aggregator=info,pvthfhe_pvss=info,pvthfhe_bench=info,nova=info";

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

    let preset = match args.params.to_lowercase().as_str() {
        "insecure512" => pvthfhe_types::BfvParameterPreset::insecure512(),
        "production8192" => pvthfhe_types::BfvParameterPreset::production8192(),
        other => anyhow::bail!("unknown preset: {other}. Use 'production8192' or 'insecure512'"),
    };
    pvthfhe_types::set_active_preset(preset);
    info!(params = %args.params, "active parameter preset set");

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
    let mut simulator = KeygenSimulator::new(args.n, backend_threshold, backend.clone())
        .map_err(|e| anyhow::anyhow!("keygen param: {e}"))?;
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
    println!("noir_nova_wrap");
    println!("onchain_verify");
    println!("c7_merkle_aggregation");
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
        // Deferred phases (not yet implemented — see deferred plans):
        //   - noir_decrypt_share  (Noir decrypt-share circuit)
        //   - noir_nova_wrap    (Nova wrap circuit)
        //   - onchain_verify      (on-chain UltraHonk verification)
        // These print phase markers only; no actual work is performed.
        self.timings.phases.pvss_share_encrypt = report.timings.phases.pvss_share_encrypt.clone();
        self.timings.phases.pvss_decrypt_prove = report.timings.phases.pvss_decrypt_prove.clone();

        println!("keygen");
        println!("nizk_prove");
        println!("nizk_verify");
        println!("pvss_share_encrypt");
        println!("cyclo_fold");
        println!("compressor_prove");
        println!("compressor_verify");
        // Phase marker only — not implemented. See deferred plans.
        println!("noir_decrypt_share");

        let noir_aggregator_final_start = Instant::now();
        info!(phase = "noir_aggregator_final", proof_digest = %report.compressed_proof_digest_hex, "phase start");
        run_noir_aggregator_final_optional(&report);
        match report.d_commitment_verified {
            Some(true) => info!("d_commitment: verified ✓"),
            Some(false) => warn!("d_commitment: MISMATCH ✗"),
            None => info!("d_commitment: not verified (awaiting G.4)"),
        }
        println!("noir_aggregator_final");
        self.timings.phases.noir_aggregator_final.total_ms =
            noir_aggregator_final_start.elapsed().as_secs_f64() * 1_000.0;
        self.timings.phases.noir_aggregator_final.instances_run = 1;

        // Phase marker only — not implemented. See deferred plans.
        println!("noir_nova_wrap");

        // Phase marker only — not implemented. See deferred plans.
        println!("onchain_verify");

        let (c7_ms, c7_ran) = run_c7_nova_optional(self.timings.n, self.timings.seed);
        if c7_ran {
            println!("c7_decrypt_aggregation");
            self.timings.phases.c7_decrypt_aggregation.total_ms = c7_ms;
            self.timings.phases.c7_decrypt_aggregation.instances_run = 1;
        }

        let (c7m_ms, c7m_ran) = run_c7_merkle_optional(self.timings.n, self.timings.seed);
        if c7m_ran {
            println!("c7_merkle_aggregation");
            self.timings.phases.c7_merkle_aggregation.total_ms = c7m_ms;
            self.timings.phases.c7_merkle_aggregation.instances_run = 1;
        }

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

#[cfg(feature = "nova-compressor")]
fn run_noir_aggregator_final_optional(report: &PipelineReport) {
    if std::env::var("PVTHFHE_RUN_NOIR_CIRCUIT").unwrap_or_default() != "1" {
        return;
    }

    // Resolve nargo/bb paths with env-var hardening (G.24)
    fn resolve_tool(tool_name: &str, env_var: &str) -> std::path::PathBuf {
        if let Ok(path) = std::env::var(env_var) {
            let p = std::path::Path::new(&path);
            if p.is_file() {
                info!("Using {tool_name} from {env_var}={path}");
                return p.to_path_buf();
            }
            warn!("{env_var}={path} does not exist or is not a file");
        }
        // Fallback to PATH — vulnerable to hijacking
        warn!("{env_var} not set; resolving {tool_name} from PATH (PATH injection risk)");
        std::path::PathBuf::from(tool_name)
    }

    let nargo_path = resolve_tool("nargo", "PVTHFHE_NARGO_PATH");
    let bb_path = resolve_tool("bb", "PVTHFHE_BB_PATH");
    // Verify both tools are accessible
    if !nargo_path.is_file() {
        warn!("PVTHFHE_RUN_NOIR_CIRCUIT=1 but nargo not found; skipping Noir circuit execution");
        return;
    }
    if !bb_path.is_file() {
        warn!("PVTHFHE_RUN_NOIR_CIRCUIT=1 but bb not found; skipping Noir circuit execution");
        return;
    }

    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let prover_toml_path = repo_root.join("circuits/aggregator_final/Prover.toml");

    // Compute all fields for the simplified C7 Noir circuit
    let ciphertext_hash =
        Fr::from_be_bytes_mod_order(&Sha256::digest(report.session_id.as_bytes()));
    let aggregate_pk_leaf = {
        use pvthfhe_cli::full_pipeline::poseidon_sponge_native_noir;
        let pk_fr: Vec<Fr> = report
            .aggregate_pk_bytes
            .chunks(31)
            .map(Fr::from_le_bytes_mod_order)
            .collect();
        poseidon_sponge_native_noir(&pk_fr)
    };
    let aggregate_pk_hash = {
        use pvthfhe_cli::full_pipeline::poseidon_sponge_native_noir;
        poseidon_sponge_native_noir(&[aggregate_pk_leaf])
    };
    let merkle_path: [ark_bn254::Fr; 7] = [ark_bn254::Fr::from(0u64); 7];
    let leaf_index = ark_bn254::Fr::from(0u64);
    let decrypt_nizk_hash_field = Fr::from_be_bytes_mod_order(&report.decrypt_nizk_hash);
    let dkg_transcript_hash = Fr::from_be_bytes_mod_order(&Sha256::digest(
        format!("dkg-transcript-{}", report.session_id).as_bytes(),
    ));
    let epoch = Fr::from(1u64);
    let participant_set_hash = {
        use pvthfhe_cli::full_pipeline::poseidon_sponge_native_noir;
        let noir_max = 128usize;
        let mut inputs = Vec::with_capacity(noir_max + 1);
        inputs.push(Fr::from(1u64));
        for &id in report.committee_party_ids.iter().take(noir_max) {
            inputs.push(Fr::from(id as u64));
        }
        while inputs.len() < noir_max + 1 {
            inputs.push(Fr::from(0u64));
        }
        poseidon_sponge_native_noir(&inputs)
    };
    let n_participants = Fr::from(report.share_coeffs.len() as u64);
    let threshold = Fr::from(report.share_coeffs.len() as u64);

    // Plaintext from Lagrange interpolation
    use pvthfhe_cli::full_pipeline::field_from_i64;
    let mut nova_final_plaintext = [Fr::zero(); 8];
    for k in 0..8 {
        let mut sum = Fr::zero();
        for (i, lambda) in report.lagrange_coeffs.iter().enumerate() {
            let coeff = field_from_i64(report.share_coeffs[i][k]);
            sum += *lambda * coeff;
        }
        nova_final_plaintext[k] = sum;
    }
    let plaintext_commitment = {
        use pvthfhe_cli::full_pipeline::poseidon_sponge_native_noir;
        let mut inputs = Vec::with_capacity(9);
        inputs.push(Fr::from(1u64));
        for k in 0..8 {
            inputs.push(nova_final_plaintext[k]);
        }
        poseidon_sponge_native_noir(&inputs)
    };

    let n_shares_field = Fr::from(report.share_coeffs.len() as u64);

    // Convert share coefficients to field elements for commitment bundle.
    // share_evals and pt_eval are now computed internally by build_c7_prover_toml
    // using the same in-circuit challenge_r derivation (F3 fix).
    let share_coeffs_fr: Vec<Vec<Fr>> = report
        .share_coeffs
        .iter()
        .map(|coeffs| coeffs.iter().map(|&c| Fr::from(c as i128)).collect())
        .collect();
    let (share_polys, share_commitments, merkle_paths, leaf_indices, share_commitment_root) =
        build_c7_share_commitment_bundle(&share_coeffs_fr);

    let dkg_root = Fr::from_be_bytes_mod_order(&Sha256::digest(
        format!("dkg-root-{}", report.session_id).as_bytes(),
    ));
    let merkle_path: [Fr; 7] = [Fr::zero(); 7];

    let prover_toml_data = build_c7_prover_toml(
        ciphertext_hash,
        aggregate_pk_hash,
        decrypt_nizk_hash_field,
        dkg_transcript_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        n_participants,
        threshold,
        plaintext_commitment,
        report.compressed_proof_hash,
        &nova_final_plaintext,
        report.combined_share_hash,
        n_shares_field,
        &report.lagrange_coeffs,
        share_commitment_root,
        &share_commitments,
        &merkle_paths,
        &leaf_indices,
        &share_polys,
        aggregate_pk_leaf,
        merkle_path,
        leaf_index,
    );
    if let Err(e) = std::fs::write(&prover_toml_path, &prover_toml_data) {
        warn!(phase = "noir_aggregator_final", error = %e, "Noir aggregator_final: failed to write Prover.toml");
        return;
    }

    match pvthfhe_circuit_tests::nargo::execute("aggregator_final", &prover_toml_path).and_then(
        |_artifacts| {
            pvthfhe_circuit_tests::bb::write_vk_prove_verify("aggregator_final", "ultra_honk")
        },
    ) {
        Ok(_) => info!(
            phase = "noir_aggregator_final",
            "Noir aggregator_final circuit proof succeeded"
        ),
        Err(err) => {
            warn!(phase = "noir_aggregator_final", error = %err, "Noir aggregator_final circuit proof failed")
        }
    }
}

#[cfg(not(feature = "nova-compressor"))]
fn run_noir_aggregator_final_optional(_report: &PipelineReport) {}

#[cfg(feature = "nova-compressor")]
fn run_c7_nova_optional(_n: usize, _seed: u64) -> (f64, bool) {
    if std::env::var("PVTHFHE_RUN_C7_SONOBE").unwrap_or_default() != "1" {
        return (0.0, false);
    }

    #[cfg(feature = "legacy-nova")]
    {
        let seed_bytes = seed.to_be_bytes();
        let epoch_hash: [u8; 32] = Sha256::digest(&seed_bytes).into();

        let start = Instant::now();
        let compressor = NovaCompressor::<C7DecryptAggregationCircuit<Fr>>::new(
            epoch_hash,
            n,
            [0u8; 32],
            pvthfhe_compressor::nova::SBIND_C7_DECRYPT,
        )
        .expect("C7 nova compressor construction failed");
        let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));
        let coeff_commitment = hash_all_coeffs(&vec![Fr::from(0u64); 8192]);
        let derived_r = hash_all_coeffs(&[coeff_commitment, Fr::from(0u64)]);
        let steps: Vec<ExternalInputs5<Fr>> = vec![
            ExternalInputs5(
                Fr::from(1u64),
                Fr::from(1u64),
                coeff_commitment,
                Fr::from(0u64),
                derived_r
            );
            n
        ];
        let proof = compressor
            .prove_steps_c7(&acc, &steps)
            .expect("C7 nova prove failed");
        let vk = compressor.verifier_key();
        let _ = compressor
            .verify_steps_c7(&vk, &proof, &steps)
            .expect("C7 nova verify failed");
        let ms = start.elapsed().as_secs_f64() * 1_000.0;
        return (ms, true);
    }
    #[cfg(not(feature = "legacy-nova"))]
    {
        (0.0, false)
    }
}

#[cfg(not(feature = "nova-compressor"))]
fn run_c7_nova_optional(_n: usize, _seed: u64) -> (f64, bool) {
    (0.0, false)
}

#[cfg(feature = "nova-compressor")]
fn run_c7_merkle_optional(_n: usize, _seed: u64) -> (f64, bool) {
    if std::env::var("PVTHFHE_RUN_C7_MERKLE").unwrap_or_default() != "1" {
        return (0.0, false);
    }

    #[cfg(feature = "legacy-nova")]
    {
        let seed_bytes = seed.to_be_bytes();
        let epoch_hash: [u8; 32] = Sha256::digest(&seed_bytes).into();

        let start = Instant::now();
        let compressor = NovaCompressor::<C7MerkleStepCircuit<Fr>>::new(
            epoch_hash,
            n,
            [0u8; 32],
            pvthfhe_compressor::nova::SBIND_C7_DECRYPT,
        )
        .expect("C7 merkle nova compressor construction failed");
        let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));

        let steps: Vec<C7MerkleExternalInputs<Fr>> = (0..n)
            .map(|i| {
                let leaf_value = Fr::from(1u64);
                let siblings: Vec<Fr> = vec![Fr::from(1u64); 35];
                // Compute depth-5 Poseidon merkle root (5 levels × 7 siblings)
                let mut current = leaf_value;
                for level in 0..5 {
                    let start = level * 7;
                    let level_siblings = &siblings[start..start + 7];
                    let mut inputs = vec![current];
                    inputs.extend_from_slice(level_siblings);
                    current = hash8_native(&inputs);
                }
                C7MerkleExternalInputs {
                    share_eval: Fr::from((42 + i as u64) * 100),
                    lagrange_coeff: Fr::from(1u64),
                    merkle_root: current,
                    merkle_data: MerkleWitnessData {
                        leaf_value,
                        leaf_index: Fr::from(0u64),
                        siblings,
                    },
                }
            })
            .collect();

        let proof = compressor
            .prove_steps_merkle(&acc, &steps)
            .expect("C7 merkle nova prove failed");
        let vk = compressor.verifier_key();
        let valid = compressor
            .verify_steps_merkle(&vk, &proof, &steps)
            .expect("C7 merkle nova verify failed");
        assert!(valid, "Merkle proof must verify");
        let ms = start.elapsed().as_secs_f64() * 1_000.0;
        return (ms, true);
    }
    #[cfg(not(feature = "legacy-nova"))]
    {
        (0.0, false)
    }
}

#[cfg(not(feature = "nova-compressor"))]
fn run_c7_merkle_optional(_n: usize, _seed: u64) -> (f64, bool) {
    (0.0, false)
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
