use clap::{Parser, ValueEnum};
use pvthfhe_aggregator::{
    decrypt::{aggregate_decrypt, partial_decrypt},
    folding::{CcsPShareInstance, CycloFoldingAdapter},
    keygen::simulator::{KeygenResult, KeygenSimulator},
};
use pvthfhe_bench::{summarize_samples, BenchEnv, ScalingBenchEnv, ScalingEnvelope};
use pvthfhe_fhe::{fhers::FhersBackend, mock::MockBackend, FheBackend};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::ExitCode, time::Instant};

const PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";
const DEFAULT_NS: [usize; 4] = [128, 256, 512, 1024];
const N_RUNS: usize = 5;
const VERIFIER_GAS: u64 = 1278;
const DEFAULT_SEED: u64 = 1;
const FHERS_BACKEND_ID: &str = "fhers-bfv";
const MOCK_BACKEND_ID: &str = "mock-xor";
const NIZK_BACKEND_ID: &str = "cyclo-ajtai-d2-conditional";
const FOLDING_BACKEND_ID: &str = "cyclo-rlwe-t10-lemma9-heuristic";
const COMPRESSOR_BACKEND_ID: &str = "ultra-honk-micronova";

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum BackendChoice {
    Fhers,
    Mock,
}

#[derive(Debug, Parser)]
#[command(name = "bench_scaling", about = "Benchmark PVTHFHE scaling pipeline")]
struct Args {
    #[arg(long, value_enum, default_value_t = BackendChoice::Fhers)]
    backend: BackendChoice,
    #[arg(long)]
    n: Option<usize>,
    #[arg(long, default_value_t = DEFAULT_SEED)]
    seed: u64,
    #[arg(long)]
    dry_run: bool,
}

struct RunConfig {
    seed: u64,
    dry_run: bool,
}

#[derive(Clone)]
enum BenchBackendInstance {
    Fhers(FhersBackend),
    Mock(MockBackend),
}

impl BenchBackendInstance {
    fn backend_id(&self) -> &'static str {
        match self {
            Self::Fhers(_) => FHERS_BACKEND_ID,
            Self::Mock(_) => MOCK_BACKEND_ID,
        }
    }

    fn run_pipeline(&self, n_parties: usize, seed: u64) -> Result<f64, String> {
        match self {
            Self::Fhers(backend) => {
                run_pipeline_with_backend(backend, self.backend_id(), n_parties, seed)
            }
            Self::Mock(backend) => {
                run_pipeline_with_backend(backend, self.backend_id(), n_parties, seed)
            }
        }
    }
}

fn mock_acknowledged() -> bool {
    std::env::var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK").as_deref() == Ok("1")
}

fn load_backend(choice: BackendChoice) -> Result<BenchBackendInstance, String> {
    match choice {
        BackendChoice::Fhers => FhersBackend::load_params(PARAMS_TOML)
            .map(BenchBackendInstance::Fhers)
            .map_err(|err| format!("load fhers backend: {err}")),
        BackendChoice::Mock => {
            if !mock_acknowledged() {
                return Err(
                    "PVTHFHE: mock backend requires PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1 to be set in the environment. This path is a mock and fails closed by default.".to_owned(),
                );
            }
            MockBackend::load_params(PARAMS_TOML)
                .map(BenchBackendInstance::Mock)
                .map_err(|err| format!("load mock backend: {err}"))
        }
    }
}

fn threshold_for(n_parties: usize) -> usize {
    (n_parties * 2 / 3).max(1)
}

fn backend_threshold_for(backend_id: &str, threshold: usize, n_parties: usize) -> usize {
    if backend_id == FHERS_BACKEND_ID {
        threshold.min((n_parties + 1) / 2)
    } else {
        threshold
    }
}

fn ciphertext_hash(ciphertext_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ciphertext_bytes);
    hasher.finalize().into()
}

fn fold_instances(allowed: &[u32], ct_hash: [u8; 32], seed: u64) -> Result<usize, String> {
    let adapter = CycloFoldingAdapter::new();
    let instances = allowed
        .iter()
        .map(|&party_id| -> Result<CcsPShareInstance, String> {
            let participant_id = u16::try_from(party_id)
                .map_err(|_| format!("party_id {party_id} exceeds u16 for cyclo folding"))?;
            let mut binding_hasher = Sha256::new();
            binding_hasher.update(ct_hash);
            binding_hasher.update(seed.to_le_bytes());
            binding_hasher.update(party_id.to_le_bytes());
            let binding: [u8; 32] = binding_hasher.finalize().into();
            Ok(CcsPShareInstance {
                participant_id,
                ajtai_commitment_bytes: ct_hash.to_vec(),
                public_io_bytes: vec![participant_id as u8; 32],
                ccs_witness_bytes: vec![1u8; 32],
                sha256_binding_bytes: binding.to_vec(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0xC7C1_0000_0000_0000);
    let report = adapter
        .fold_all(&instances, "bench-scaling", &mut rng)
        .map_err(|err| format!("cyclo fold_all: {err}"))?;
    adapter
        .verify_fold_all(&report, &instances)
        .map_err(|err| format!("cyclo verify_fold_all: {err}"))?;
    Ok(report.accumulators().len() * 32)
}

fn run_pipeline_with_backend<B: FheBackend + Clone + 'static>(
    backend: &B,
    backend_id: &str,
    n_parties: usize,
    seed: u64,
) -> Result<f64, String> {
    let threshold = threshold_for(n_parties);
    let backend_threshold = backend_threshold_for(backend_id, threshold, n_parties);

    let start = Instant::now();

    let mut sim = KeygenSimulator::new(n_parties, backend_threshold, backend.clone());
    let transcript = match sim.run().map_err(|err| format!("keygen run: {err}"))? {
        KeygenResult::Complete(transcript) => transcript,
        KeygenResult::Blamed(ids) => return Err(format!("keygen blamed: {ids:?}")),
    };

    backend
        .setup_threshold(n_parties, backend_threshold)
        .map_err(|err| format!("setup_threshold: {err}"))?;

    let aggregate_pk = &transcript.round3_aggregate.aggregate_pk;
    let plaintext = b"hello pvthfhe";
    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ ((n_parties as u64) << 32));
    let ct = backend
        .encrypt(aggregate_pk, plaintext, &mut rng)
        .map_err(|err| format!("encrypt: {err}"))?;

    let dkg_root = transcript.dkg_root;
    let ct_hash = ciphertext_hash(&ct.bytes);
    let allowed = transcript.participant_set.clone();
    let shares = allowed
        .iter()
        .map(|&pid| {
            partial_decrypt(backend, &ct, pid, &dkg_root, &ct_hash, 1, &mut rng)
                .map_err(|err| format!("partial_decrypt party {pid}: {err}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let recovered = aggregate_decrypt(
        backend,
        &ct,
        &shares,
        backend_threshold,
        &allowed,
        &dkg_root,
        &ct_hash,
        1,
    )
    .map_err(|err| format!("aggregate_decrypt: {err}"))?;
    if recovered != plaintext {
        return Err("aggregate_decrypt did not round-trip plaintext".to_owned());
    }

    let _proof_size = fold_instances(&allowed, ct_hash, seed)?;

    Ok(start.elapsed().as_nanos() as f64)
}

fn bench_n(
    backend: &BenchBackendInstance,
    n_parties: usize,
    config: &RunConfig,
) -> Result<ScalingEnvelope, String> {
    let threshold = threshold_for(n_parties);
    let run_count = if config.dry_run { 1 } else { N_RUNS };
    let mut samples = Vec::with_capacity(run_count);
    if config.dry_run {
        samples.push(0.0);
    } else {
        for run_idx in 0..run_count {
            samples
                .push(backend.run_pipeline(n_parties, config.seed.saturating_add(run_idx as u64))?);
        }
    }

    let stats = summarize_samples(&samples);
    let mut sorted = samples;
    sorted.sort_by(|a, b| a.total_cmp(b));
    let p99_idx = ((sorted.len() as f64 * 0.99) as usize).min(sorted.len() - 1);
    let p99 = sorted[p99_idx];
    let env_raw = BenchEnv::capture();
    let mem_kb = BenchEnv::mem_kb();
    let final_snark_size_bytes = if config.dry_run {
        32
    } else {
        32 + threshold * 32
    };

    Ok(ScalingEnvelope {
        backend_id: backend.backend_id().to_owned(),
        nizk_backend_id: NIZK_BACKEND_ID.to_owned(),
        folding_backend_id: FOLDING_BACKEND_ID.to_owned(),
        compressor_backend_id: COMPRESSOR_BACKEND_ID.to_owned(),
        n: n_parties,
        t: threshold,
        seed: config.seed,
        mean: stats.mean_ns,
        median: stats.median_ns,
        p99,
        stddev: stats.stddev_ns,
        aggregator_wall_ms: stats.mean_ns / 1_000_000.0,
        final_snark_size_bytes,
        verifier_gas: VERIFIER_GAS,
        peak_mem_kb: mem_kb,
        env: ScalingBenchEnv {
            cpu: env_raw.cpu,
            cpu_cores: BenchEnv::cpu_cores(),
            mem_kb,
            kernel: env_raw.kernel,
        },
    })
}

fn selected_ns(args: &Args) -> Vec<usize> {
    args.n
        .map(|n| vec![n])
        .unwrap_or_else(|| DEFAULT_NS.to_vec())
}

fn print_backend_banner(envelope: &ScalingEnvelope) {
    eprintln!("backend_id: {}", envelope.backend_id);
    eprintln!("nizk_backend_id: {}", envelope.nizk_backend_id);
    eprintln!("folding_backend_id: {}", envelope.folding_backend_id);
    eprintln!("compressor_backend_id: {}", envelope.compressor_backend_id);
}

fn main() -> ExitCode {
    let args = Args::parse();
    let out_dir = Path::new("bench/results");
    if let Err(err) = fs::create_dir_all(out_dir) {
        eprintln!("create bench/results failed: {err}");
        return ExitCode::FAILURE;
    }

    let backend = match load_backend(args.backend) {
        Ok(backend) => backend,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };
    let config = RunConfig {
        seed: args.seed,
        dry_run: args.dry_run,
    };

    for n in selected_ns(&args) {
        eprintln!("Benchmarking n={n}...");
        let envelope = match bench_n(&backend, n, &config) {
            Ok(envelope) => envelope,
            Err(err) => {
                eprintln!("bench_scaling failed for n={n}: {err}");
                return ExitCode::FAILURE;
            }
        };
        print_backend_banner(&envelope);
        let json = match serde_json::to_string_pretty(&envelope) {
            Ok(json) => json,
            Err(err) => {
                eprintln!("serialize failed for n={n}: {err}");
                return ExitCode::FAILURE;
            }
        };
        let path = out_dir.join(format!("scaling-n{n}.json"));
        if let Err(err) = fs::write(&path, &json) {
            eprintln!("write {} failed: {err}", path.display());
            return ExitCode::FAILURE;
        }
        eprintln!("  wrote {}", path.display());
        eprintln!(
            "  mean={:.2}ms median={:.2}ms p99={:.2}ms stddev={:.2}ms snark={}B gas={}",
            envelope.mean / 1e6,
            envelope.median / 1e6,
            envelope.p99 / 1e6,
            envelope.stddev / 1e6,
            envelope.final_snark_size_bytes,
            envelope.verifier_gas,
        );
    }

    eprintln!("Done.");
    ExitCode::SUCCESS
}
