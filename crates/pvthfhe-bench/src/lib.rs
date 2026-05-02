use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchEnv {
    pub cpu: String,
    pub ram_gb: u64,
    pub kernel: String,
    pub git_sha: String,
    pub timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchResult {
    pub name: String,
    #[serde(rename = "mean")]
    pub mean_ns: f64,
    #[serde(rename = "median")]
    pub median_ns: f64,
    #[serde(rename = "p99")]
    pub p99_ns: f64,
    #[serde(rename = "stddev")]
    pub stddev_ns: f64,
    pub n_runs: u64,
    pub env: BenchEnv,
}

impl BenchEnv {
    pub fn capture() -> Self {
        let cpu = std::fs::read_to_string("/proc/cpuinfo")
            .unwrap_or_default()
            .lines()
            .find(|l| l.starts_with("model name"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let ram_kb: u64 = std::fs::read_to_string("/proc/meminfo")
            .unwrap_or_default()
            .lines()
            .find(|l| l.starts_with("MemTotal:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
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
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        BenchEnv {
            cpu,
            ram_gb: ram_kb / 1_048_576,
            kernel,
            git_sha,
            timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder() {}

    #[test]
    fn bench_result_has_all_envelope_fields() {
        let result = BenchResult {
            name: "test".to_string(),
            mean_ns: 100.0,
            median_ns: 95.0,
            p99_ns: 200.0,
            stddev_ns: 10.0,
            n_runs: 10,
            env: BenchEnv {
                cpu: "unknown".to_string(),
                ram_gb: 0,
                kernel: "unknown".to_string(),
                git_sha: "unknown".to_string(),
                timestamp: "2026-05-02".to_string(),
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["mean"].is_number(), "missing mean");
        assert!(parsed["median"].is_number(), "missing median");
        assert!(parsed["p99"].is_number(), "missing p99");
        assert!(parsed["stddev"].is_number(), "missing stddev");
        assert!(parsed["n_runs"].is_number(), "missing n_runs");
        assert!(parsed["env"]["cpu"].is_string(), "missing env.cpu");
        assert!(parsed["env"]["ram_gb"].is_number(), "missing env.ram_gb");
        assert!(parsed["env"]["kernel"].is_string(), "missing env.kernel");
        assert!(parsed["env"]["git_sha"].is_string(), "missing env.git_sha");
        assert!(parsed["env"]["timestamp"].is_string(), "missing env.timestamp");
        assert!(parsed["name"].is_string(), "missing name");
    }
}
