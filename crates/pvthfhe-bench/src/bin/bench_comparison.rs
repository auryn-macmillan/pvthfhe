use clap::Parser;
use pvthfhe_bench::comparison_map::{mapping_for_comparison_row, COMPARISON_ROW_NAMES};
use pvthfhe_bench::e2e_timings::E2eTimings;
use pvthfhe_bench::BenchEnv;
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

const NIZK_BACKEND_ID: &str = "cyclo-ajtai-d2-conditional";
const FOLDING_BACKEND_ID: &str = "cyclo-rlwe-t10-lemma9-heuristic";
#[cfg(feature = "sonobe-compressor")]
const COMPRESSOR_BACKEND_ID: &str = "nova-bn254-grumpkin";
#[cfg(all(feature = "surrogate-compressor", not(feature = "sonobe-compressor")))]
const COMPRESSOR_BACKEND_ID: &str = "sha256-surrogate-compressor";
#[cfg(not(any(feature = "sonobe-compressor", feature = "surrogate-compressor")))]
const COMPRESSOR_BACKEND_ID: &str = "ultra-honk-micronova";
const FHE_BACKEND_ID: &str = "fhers-bfv";
const PVSS_BACKEND_ID: &str = "lattice-pvss-bfv-d2";
const COMPARISON_TARGET_NAME: &str = "Interfold integration_summary.json";
const COMPARISON_TARGET_SOURCE: &str =
    "https://github.com/gnosisguild/enclave/tree/main/circuits/benchmarks/results_secure";
const DEFAULT_E2E_TIMINGS: &str = "bench/results/e2e_timings.json";
const OUTPUT_REAL: &str = "bench/results/comparison.json";
const OUTPUT_DRYRUN: &str = "bench/results/comparison-dryrun.json";

#[derive(Debug, Parser)]
#[command(
    name = "bench_comparison",
    about = "Emit Interfold-shaped PVTHFHE comparison JSON"
)]
struct Args {
    #[arg(long, default_value = DEFAULT_E2E_TIMINGS)]
    e2e_timings: PathBuf,
    #[arg(long)]
    n: usize,
    #[arg(long)]
    t: usize,
    #[arg(long)]
    seed: u64,
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Serialize)]
struct ComparisonEnvelope {
    circuit_timings: Vec<CircuitTimingRow>,
    phase_totals: PhaseTotals,
    hardware: HardwareDisclosure,
    backend_ids: BackendIds,
    commit_sha: String,
    comparison_target: ComparisonTarget,
}

#[derive(Debug, Serialize)]
struct CircuitTimingRow {
    name: &'static str,
    prove_ms: Option<f64>,
    verify_ms: Option<f64>,
    witness_ms: Option<f64>,
    vk_kb: Option<f64>,
    proof_kb: Option<f64>,
    status: &'static str,
    cardinality_tag: &'static str,
    instances_run: usize,
    comparability_note: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    gap_reason: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct PhaseTotals {
    dkg_ms: Option<f64>,
    decrypt_ms: Option<f64>,
    onchain_verify_ms: Option<f64>,
    end_to_end_ms: Option<f64>,
}

#[derive(Debug, Serialize)]
struct HardwareDisclosure {
    cpu: String,
    cpu_cores: usize,
    ram_gb: u64,
    kernel: String,
}

#[derive(Debug, Serialize)]
struct BackendIds {
    fhe: &'static str,
    nizk: &'static str,
    folding: &'static str,
    compressor: &'static str,
    pvss: &'static str,
}

#[derive(Debug, Serialize)]
struct ComparisonTarget {
    name: &'static str,
    source: &'static str,
    n: usize,
    t: usize,
    seed: u64,
    dry_run: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let out_dir = Path::new("bench/results");
    if let Err(err) = fs::create_dir_all(out_dir) {
        eprintln!("create bench/results failed: {err}");
        return ExitCode::FAILURE;
    }

    let bench_env = BenchEnv::capture();
    let timings = match load_e2e_timings(&args.e2e_timings) {
        Ok(timings) => timings,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };
    let envelope = ComparisonEnvelope {
        circuit_timings: COMPARISON_ROW_NAMES
            .into_iter()
            .map(|name| row_for(name, &timings))
            .collect(),
        phase_totals: PhaseTotals {
            dkg_ms: Some(timings.phases.pvss_share_encrypt.total_ms),
            decrypt_ms: None,
            onchain_verify_ms: None,
            end_to_end_ms: Some(
                timings.phases.pvss_share_encrypt.total_ms
                    + timings.phases.pvss_share_encrypt.verify_ms
                    + timings.phases.pvss_share_encrypt.recover_ms,
            ),
        },
        hardware: HardwareDisclosure {
            cpu: bench_env.cpu,
            cpu_cores: BenchEnv::cpu_cores(),
            ram_gb: bench_env.ram_gb,
            kernel: bench_env.kernel,
        },
        backend_ids: BackendIds {
            fhe: FHE_BACKEND_ID,
            nizk: NIZK_BACKEND_ID,
            folding: FOLDING_BACKEND_ID,
            compressor: COMPRESSOR_BACKEND_ID,
            pvss: PVSS_BACKEND_ID,
        },
        commit_sha: bench_env.git_sha,
        comparison_target: ComparisonTarget {
            name: COMPARISON_TARGET_NAME,
            source: COMPARISON_TARGET_SOURCE,
            n: args.n,
            t: args.t,
            seed: args.seed,
            dry_run: args.dry_run,
        },
    };

    let json = match serde_json::to_string_pretty(&envelope) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("serialize comparison JSON failed: {err}");
            return ExitCode::FAILURE;
        }
    };
    let path = if args.dry_run {
        OUTPUT_DRYRUN
    } else {
        OUTPUT_REAL
    };
    if let Err(err) = fs::write(path, json) {
        eprintln!("write {path} failed: {err}");
        return ExitCode::FAILURE;
    }

    eprintln!("wrote {path}");
    ExitCode::SUCCESS
}

fn load_e2e_timings(path: &Path) -> Result<E2eTimings, String> {
    let raw =
        fs::read_to_string(path).map_err(|err| format!("read {} failed: {err}", path.display()))?;
    let timings: E2eTimings = serde_json::from_str(&raw)
        .map_err(|err| format!("parse {} failed: {err}", path.display()))?;
    E2eTimings::check_version(&timings.schema_version)
        .map_err(|err| format!("invalid e2e timings {}: {err}", path.display()))?;
    Ok(timings)
}

fn row_for(name: &'static str, timings: &E2eTimings) -> CircuitTimingRow {
    if name == "ZkPkBfv" {
        return CircuitTimingRow {
            name,
            prove_ms: Some(timings.phases.nizk_prove.total_ms),
            verify_ms: None,
            witness_ms: None,
            vk_kb: None,
            proof_kb: None,
            status: "real",
            cardinality_tag: cardinality_tag(name),
            instances_run: timings.phases.nizk_prove.instances_run,
            comparability_note: comparability_note(name),
            gap_reason: None,
        };
    }

    if name == "ZkShareEncryption" {
        return CircuitTimingRow {
            name,
            prove_ms: Some(timings.phases.pvss_share_encrypt.deal_ms),
            verify_ms: Some(timings.phases.pvss_share_encrypt.verify_ms),
            witness_ms: Some(timings.phases.pvss_share_encrypt.deal_ms),
            vk_kb: None,
            proof_kb: None,
            status: "real",
            cardinality_tag: cardinality_tag(name),
            instances_run: timings.phases.pvss_share_encrypt.instances_run,
            comparability_note: comparability_note(name),
            gap_reason: Some("Verifier key size is not exposed by the PVSS adapter"),
        };
    }

    if name == "ZkShareComputation" {
        return CircuitTimingRow {
            name,
            prove_ms: Some(timings.phases.keygen.total_ms),
            verify_ms: None,
            witness_ms: None,
            vk_kb: None,
            proof_kb: None,
            status: "real",
            cardinality_tag: cardinality_tag(name),
            instances_run: timings.phases.keygen.instances_run,
            comparability_note: comparability_note(name),
            gap_reason: None,
        };
    }

    if name == "ZkVerifyShareProofs" {
        return CircuitTimingRow {
            name,
            prove_ms: Some(timings.phases.pvss_share_encrypt.verify_ms),
            verify_ms: None,
            witness_ms: None,
            vk_kb: None,
            proof_kb: None,
            status: "real",
            cardinality_tag: cardinality_tag(name),
            instances_run: timings.phases.pvss_share_encrypt.instances_run,
            comparability_note: comparability_note(name),
            gap_reason: None,
        };
    }

    if name == "ZkDkgAggregation" {
        return CircuitTimingRow {
            name,
            prove_ms: Some(timings.phases.compressor_prove.total_ms),
            verify_ms: None,
            witness_ms: None,
            vk_kb: None,
            proof_kb: None,
            status: "real",
            cardinality_tag: cardinality_tag(name),
            instances_run: timings.phases.compressor_prove.instances_run,
            comparability_note: comparability_note(name),
            gap_reason: None,
        };
    }

    if name == "ZkDkgShareDecryption" {
        return CircuitTimingRow {
            name,
            prove_ms: Some(timings.phases.pvss_decrypt_prove.total_ms),
            verify_ms: None,
            witness_ms: None,
            vk_kb: None,
            proof_kb: None,
            status: "real",
            cardinality_tag: cardinality_tag(name),
            instances_run: timings.phases.pvss_decrypt_prove.instances_run,
            comparability_note: comparability_note(name),
            gap_reason: None,
        };
    }

    if name == "onchain_verify" {
        return CircuitTimingRow {
            name,
            prove_ms: Some(timings.phases.onchain_verify.total_ms),
            verify_ms: None,
            witness_ms: None,
            vk_kb: None,
            proof_kb: None,
            status: "real-fallback",
            cardinality_tag: cardinality_tag(name),
            instances_run: timings.phases.onchain_verify.instances_run,
            comparability_note: comparability_note(name),
            gap_reason: Some(
                "Measured via fallback compressor.verify proxy on the NoGo on-chain path",
            ),
        };
    }

    if name == "ZkThresholdShareDecryption" {
        return CircuitTimingRow {
            name,
            prove_ms: Some(timings.phases.partial_decrypt.total_ms),
            verify_ms: None,
            witness_ms: None,
            vk_kb: None,
            proof_kb: None,
            status: "real",
            cardinality_tag: cardinality_tag(name),
            instances_run: timings.phases.partial_decrypt.instances_run,
            comparability_note: comparability_note(name),
            gap_reason: None,
        };
    }

    if matches!(
        name,
        "ZkDecryptedSharesAggregation" | "ZkDecryptionAggregation"
    ) {
        return CircuitTimingRow {
            name,
            prove_ms: Some(timings.phases.aggregate_decrypt.total_ms),
            verify_ms: None,
            witness_ms: None,
            vk_kb: None,
            proof_kb: None,
            status: "real",
            cardinality_tag: cardinality_tag(name),
            instances_run: timings.phases.aggregate_decrypt.instances_run,
            comparability_note: comparability_note(name),
            gap_reason: Some("merged into single PVTHFHE aggregate_decrypt pass"),
        };
    }

    if matches!(name, "ZkNodeDkgFold" | "ZkPkAggregation") {
        return CircuitTimingRow {
            name,
            prove_ms: Some(timings.phases.cyclo_fold.total_ms),
            verify_ms: None,
            witness_ms: None,
            vk_kb: None,
            proof_kb: None,
            status: "real",
            cardinality_tag: cardinality_tag(name),
            instances_run: timings.phases.cyclo_fold.instances_run,
            comparability_note: comparability_note(name),
            gap_reason: Some("merged into single PVTHFHE cyclo_fold pass"),
        };
    }

    let gap_reason = mapping_for_comparison_row(name).and_then(|mapping| mapping.gap_reason);

    CircuitTimingRow {
        name,
        prove_ms: None,
        verify_ms: None,
        witness_ms: None,
        vk_kb: None,
        proof_kb: None,
        status: "n/a",
        cardinality_tag: cardinality_tag(name),
        instances_run: 0,
        comparability_note: comparability_note(name),
        gap_reason,
    }
}

fn cardinality_tag(name: &str) -> &'static str {
    mapping_for_comparison_row(name)
        .map(|mapping| mapping.cardinality)
        .unwrap_or("1:1")
}

fn comparability_note(name: &str) -> &'static str {
    match name {
        "ZkPkBfv" => "Maps to one Sigma+Ajtai proof per party; report aggregate-of-N when wired.",
        "ZkShareComputation" => {
            "PVTHFHE measures full keygen simulator (Round1+Round2+Round3); Interfold ZkShareComputation is the share-computation step in isolation. Reader-side adjustment may be needed."
        }
        "ZkShareEncryption" => {
            "Will map to lattice PVSS share-encryption proofs once Phase P lands."
        }
        "ZkVerifyShareProofs" => {
            "Will map to verifier-side PVSS share-proof checks once Phase P lands."
        }
        "ZkNodeDkgFold" => {
            "PVTHFHE merged this stage into a single cyclo_fold pass; the merged timing is reported in both rows and should not be double-counted."
        }
        "ZkPkAggregation" => {
            "PVTHFHE merged this stage into a single cyclo_fold pass; the merged timing is reported in both rows and should not be double-counted."
        }
        "ZkDkgAggregation" => "Will map to compressor proof once comparison wiring is implemented.",
        "ZkThresholdShareDecryption" => {
            "Maps to one Sigma+Ajtai decrypt proof per participating party."
        }
        "ZkDkgShareDecryption" => "Will map to decrypt-side PVSS proofs once Phase P lands.",
        "ZkDecryptedSharesAggregation" => {
            "PVTHFHE merged this cost into a single aggregate_decrypt pass; merged timing is reported in both rows."
        }
        "ZkDecryptionAggregation" => {
            "PVTHFHE merged this cost into a single aggregate_decrypt pass; merged timing is reported in both rows."
        }
        "onchain_verify" => {
            "Will map to BB UltraHonk verifier execution once Noir/on-chain wiring lands."
        }
        _ => "Comparison note unavailable.",
    }
}
