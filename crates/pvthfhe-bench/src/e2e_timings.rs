use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eTimings {
    pub schema_version: String,
    pub n: usize,
    pub t: usize,
    pub seed: u64,
    pub compressor_backend_id: String,
    pub phases: E2ePhases,
    pub produced_at_unix_secs: u64,
    pub git_sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2ePhases {
    pub keygen: PhaseTiming,
    pub nizk_prove: PerInstancePhase,
    pub nizk_verify: PerInstancePhase,
    pub pvss_share_encrypt: PvssPhaseDetail,
    pub pvss_decrypt_prove: PerInstancePhase,
    pub cyclo_fold: PhaseTiming,
    pub compressor_prove: PhaseTiming,
    pub compressor_verify: PhaseTiming,
    pub partial_decrypt: PerInstancePhase,
    pub aggregate_decrypt: PhaseTiming,
    pub noir_sonobe_wrap: PhaseTiming,
    pub noir_aggregator_final: PhaseTiming,
    pub c7_decrypt_aggregation: PhaseTiming,
    pub c7_merkle_aggregation: PhaseTiming,
    pub onchain_verify: PhaseTiming,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseTiming {
    pub total_ms: f64,
    pub instances_run: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerInstancePhase {
    pub total_ms: f64,
    pub instances_run: usize,
    pub per_instance_ms: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PvssPhaseDetail {
    pub total_ms: f64,
    pub instances_run: usize,
    pub deal_ms: f64,
    pub verify_ms: f64,
    pub recover_ms: f64,
}

impl E2eTimings {
    pub const SCHEMA_VERSION: &str = "1.0.0";

    pub fn new(n: usize, t: usize, seed: u64, compressor_backend_id: impl Into<String>) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION.to_owned(),
            n,
            t,
            seed,
            compressor_backend_id: compressor_backend_id.into(),
            phases: E2ePhases::zeroed(),
            produced_at_unix_secs: chrono::Utc::now().timestamp().try_into().ok().unwrap_or(0),
            git_sha: std::process::Command::new("git")
                .args(["rev-parse", "--short", "HEAD"])
                .output()
                .ok()
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "unknown".to_owned()),
        }
    }

    pub fn check_version(json_version: &str) -> Result<(), String> {
        if json_version == Self::SCHEMA_VERSION {
            Ok(())
        } else {
            Err(format!(
                "schema version mismatch: expected {}, got {}",
                Self::SCHEMA_VERSION,
                json_version
            ))
        }
    }
}

impl E2ePhases {
    fn zeroed() -> Self {
        Self {
            keygen: PhaseTiming::zeroed(),
            nizk_prove: PerInstancePhase::zeroed(),
            nizk_verify: PerInstancePhase::zeroed(),
            pvss_share_encrypt: PvssPhaseDetail::zeroed(),
            pvss_decrypt_prove: PerInstancePhase::zeroed(),
            cyclo_fold: PhaseTiming::zeroed(),
            compressor_prove: PhaseTiming::zeroed(),
            compressor_verify: PhaseTiming::zeroed(),
            partial_decrypt: PerInstancePhase::zeroed(),
            aggregate_decrypt: PhaseTiming::zeroed(),
            noir_sonobe_wrap: PhaseTiming::zeroed(),
            noir_aggregator_final: PhaseTiming::zeroed(),
            c7_decrypt_aggregation: PhaseTiming::zeroed(),
            c7_merkle_aggregation: PhaseTiming::zeroed(),
            onchain_verify: PhaseTiming::zeroed(),
        }
    }
}

impl PhaseTiming {
    fn zeroed() -> Self {
        Self {
            total_ms: 0.0,
            instances_run: 0,
        }
    }
}

impl PerInstancePhase {
    fn zeroed() -> Self {
        Self {
            total_ms: 0.0,
            instances_run: 0,
            per_instance_ms: Vec::new(),
        }
    }
}

impl PvssPhaseDetail {
    fn zeroed() -> Self {
        Self {
            total_ms: 0.0,
            instances_run: 0,
            deal_ms: 0.0,
            verify_ms: 0.0,
            recover_ms: 0.0,
        }
    }
}
