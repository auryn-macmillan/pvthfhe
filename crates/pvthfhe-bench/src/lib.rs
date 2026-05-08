#![allow(missing_docs, clippy::as_conversions)]

pub mod backends;
pub mod comparison_map;
pub mod e2e_timings;
pub mod folding;
pub mod render_comparison;
pub mod worked_example;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingBenchEnv {
    pub cpu: String,
    pub cpu_cores: usize,
    pub mem_kb: u64,
    pub kernel: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingEnvelope {
    pub backend_id: String,
    pub nizk_backend_id: String,
    pub folding_backend_id: String,
    pub compressor_backend_id: String,
    pub n: usize,
    pub t: usize,
    pub seed: u64,
    pub mean: f64,
    pub median: f64,
    pub p99: f64,
    pub stddev: f64,
    pub aggregator_wall_ms: f64,
    pub final_snark_size_bytes: usize,
    pub verifier_gas: u64,
    pub peak_mem_kb: u64,
    pub env: ScalingBenchEnv,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchEnv {
    pub cpu: String,
    pub ram_gb: u64,
    pub kernel: String,
    pub git_sha: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchRecord {
    pub case: String,
    pub backend: String,
    pub median_ns: f64,
    pub mean_ns: f64,
    pub stddev_ns: f64,
    pub n_runs: u64,
}

#[derive(Debug, Clone)]
pub struct BenchStats {
    pub median_ns: f64,
    pub mean_ns: f64,
    pub stddev_ns: f64,
}

impl BenchEnv {
    pub fn capture() -> Self {
        let cpu = std::fs::read_to_string("/proc/cpuinfo")
            .unwrap_or_default()
            .lines()
            .find(|line| line.starts_with("model name"))
            .and_then(|line| line.split(':').nth(1))
            .map(|value| value.trim().to_owned())
            .unwrap_or_else(|| "unknown".to_owned());

        let ram_kb = std::fs::read_to_string("/proc/meminfo")
            .unwrap_or_default()
            .lines()
            .find(|line| line.starts_with("MemTotal:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);

        let kernel = std::fs::read_to_string("/proc/version")
            .unwrap_or_default()
            .split_whitespace()
            .take(3)
            .collect::<Vec<_>>()
            .join(" ");

        let git_sha = std::process::Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "unknown".to_owned());

        let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        Self {
            cpu,
            ram_gb: ram_kb / 1_048_576,
            kernel,
            git_sha,
            timestamp,
        }
    }

    pub fn cpu_cores() -> usize {
        std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
    }

    pub fn mem_kb() -> u64 {
        std::fs::read_to_string("/proc/meminfo")
            .unwrap_or_default()
            .lines()
            .find(|line| line.starts_with("MemTotal:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    }
}

pub fn summarize_samples(samples_ns: &[f64]) -> BenchStats {
    assert!(!samples_ns.is_empty(), "samples_ns must not be empty");

    let mut sorted = samples_ns.to_vec();
    sorted.sort_by(|left, right| left.total_cmp(right));

    let mean_ns = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let median_ns = if sorted.len().is_multiple_of(2) {
        let high = sorted.len() / 2;
        (sorted[high - 1] + sorted[high]) / 2.0
    } else {
        sorted[sorted.len() / 2]
    };
    let variance = sorted
        .iter()
        .map(|sample| (sample - mean_ns).powi(2))
        .sum::<f64>()
        / sorted.len() as f64;

    BenchStats {
        median_ns,
        mean_ns,
        stddev_ns: variance.sqrt(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        backends::{BackendAvailability, BackendGap, BackendProbe, RqOps},
        summarize_samples, worked_example, BenchRecord,
    };

    #[test]
    fn summarize_samples_reports_expected_moments() {
        let stats = summarize_samples(&[10.0, 20.0, 30.0, 40.0]);
        assert_eq!(stats.mean_ns, 25.0);
        assert_eq!(stats.median_ns, 25.0);
        assert!((stats.stddev_ns - 11.180339887).abs() < 1e-6);
    }

    #[test]
    fn bench_record_serializes_required_fields() {
        let json = match serde_json::to_value(BenchRecord {
            case: "ntt_forward(N=4096,q=q0)".to_owned(),
            backend: "fhe_rs".to_owned(),
            median_ns: 1.0,
            mean_ns: 2.0,
            stddev_ns: 0.5,
            n_runs: 10,
        }) {
            Ok(value) => value,
            Err(err) => unreachable!("serialize BenchRecord: {err}"),
        };

        assert!(json["case"].is_string());
        assert!(json["backend"].is_string());
        assert!(json["median_ns"].is_number());
        assert!(json["mean_ns"].is_number());
        assert!(json["stddev_ns"].is_number());
        assert!(json["n_runs"].is_number());
    }

    #[test]
    fn backend_probe_can_report_feature_gaps() {
        let probe = BackendProbe {
            name: "poulpy",
            availability: BackendAvailability::FeatureGap(BackendGap {
                backend: "poulpy",
                reason: "nightly-only HAL is not yet wired",
            }),
        };

        assert_eq!(probe.name, "poulpy");
        assert!(matches!(
            probe.availability,
            BackendAvailability::FeatureGap(_)
        ));
    }

    fn assert_rq_ops_contract<T: RqOps>(backend: &T) {
        let mut coeffs = vec![0_u64; 8];
        backend.sample_uniform(&mut coeffs, 7);
        backend.ntt_fwd(&mut coeffs);
        backend.ntt_inv(&mut coeffs);
    }

    #[test]
    fn fhe_rs_adapter_is_discoverable() {
        let probe = crate::backends::fhe_rs::FheRsBackend::probe();
        let _ = assert_rq_ops_contract::<crate::backends::fhe_rs::FheRsBackend>;
        assert_eq!(probe.name, "fhe_rs");
    }

    #[test]
    fn scaling_envelope_has_required_t5_fields() {
        use crate::ScalingEnvelope;
        let env = crate::BenchEnv::capture();
        let envelope = ScalingEnvelope {
            backend_id: "fhers-bfv".to_owned(),
            nizk_backend_id: "cyclo-ajtai-d2-conditional".to_owned(),
            folding_backend_id: "cyclo-rlwe-t10-lemma9-heuristic".to_owned(),
            compressor_backend_id: "ultra-honk-micronova".to_owned(),
            n: 128,
            t: 85,
            seed: 1,
            mean: 1.0,
            median: 1.0,
            p99: 1.0,
            stddev: 0.0,
            aggregator_wall_ms: 1.0,
            final_snark_size_bytes: 32,
            verifier_gas: 1278,
            peak_mem_kb: 1024,
            env: crate::ScalingBenchEnv {
                cpu: env.cpu,
                cpu_cores: crate::BenchEnv::cpu_cores(),
                mem_kb: env.ram_gb * 1_048_576,
                kernel: env.kernel,
            },
        };
        let json = match serde_json::to_value(&envelope) {
            Ok(v) => v,
            Err(e) => unreachable!("serialize ScalingEnvelope: {e}"),
        };
        assert!(json["mean"].is_number(), "missing mean");
        assert!(json["median"].is_number(), "missing median");
        assert!(json["p99"].is_number(), "missing p99");
        assert!(json["stddev"].is_number(), "missing stddev");
        assert!(json["backend_id"].is_string(), "missing backend_id");
        assert!(
            json["nizk_backend_id"].is_string(),
            "missing nizk_backend_id"
        );
        assert!(
            json["folding_backend_id"].is_string(),
            "missing folding_backend_id"
        );
        assert!(
            json["compressor_backend_id"].is_string(),
            "missing compressor_backend_id"
        );
        assert!(json["t"].is_number(), "missing t");
        assert!(json["seed"].is_number(), "missing seed");
        assert!(json["env"]["cpu"].is_string(), "missing env.cpu");
        assert!(
            json["env"]["cpu_cores"].is_number(),
            "missing env.cpu_cores"
        );
        assert!(json["env"]["mem_kb"].is_number(), "missing env.mem_kb");
        assert!(json["env"]["kernel"].is_string(), "missing env.kernel");
    }

    #[test]
    fn worked_example_seed_42_round_trips_message() {
        let transcript = worked_example::generate(42);

        assert_eq!(transcript.m_recovered, transcript.message);
        assert_eq!(transcript.partials.len(), 3);
        assert_eq!(transcript.participant_set, vec![0, 1, 2]);
        assert!(transcript
            .randomness
            .u
            .iter()
            .any(|coefficient| *coefficient != 0));
        assert_eq!(transcript.partials[0].party_id, 0);
        assert_eq!(transcript.partials[1].party_id, 1);
        assert_eq!(transcript.partials[2].party_id, 2);
    }
}
