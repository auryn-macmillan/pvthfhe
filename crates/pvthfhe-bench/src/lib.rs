pub mod backends;
pub mod folding;

use serde::{Deserialize, Serialize};

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
}

pub fn summarize_samples(samples_ns: &[f64]) -> BenchStats {
    assert!(!samples_ns.is_empty(), "samples_ns must not be empty");

    let mut sorted = samples_ns.to_vec();
    sorted.sort_by(|left, right| left.partial_cmp(right).unwrap());

    let mean_ns = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let median_ns = if sorted.len().is_multiple_of(2) {
        let high = sorted.len() / 2;
        (sorted[high - 1] + sorted[high]) / 2.0
    } else {
        sorted[sorted.len() / 2]
    };
    let variance = sorted.iter().map(|sample| (sample - mean_ns).powi(2)).sum::<f64>() / sorted.len() as f64;

    BenchStats {
        median_ns,
        mean_ns,
        stddev_ns: variance.sqrt(),
    }
}

#[cfg(test)]
mod tests {
    use super::{backends::{BackendAvailability, BackendGap, BackendProbe, RqOps}, summarize_samples, BenchRecord};

    #[test]
    fn summarize_samples_reports_expected_moments() {
        let stats = summarize_samples(&[10.0, 20.0, 30.0, 40.0]);
        assert_eq!(stats.mean_ns, 25.0);
        assert_eq!(stats.median_ns, 25.0);
        assert!((stats.stddev_ns - 11.180339887).abs() < 1e-6);
    }

    #[test]
    fn bench_record_serializes_required_fields() {
        let json = serde_json::to_value(BenchRecord {
            case: "ntt_forward(N=4096,q=q0)".to_owned(),
            backend: "fhe_rs".to_owned(),
            median_ns: 1.0,
            mean_ns: 2.0,
            stddev_ns: 0.5,
            n_runs: 10,
        })
        .unwrap();

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
        assert!(matches!(probe.availability, BackendAvailability::FeatureGap(_)));
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
}
