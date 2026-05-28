use crate::comparison_map::{comparison_row_name, mapping_for};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tera::{Context, Tera};

const DEFAULT_TEMPLATE: &str = include_str!("../../../bench/templates/comparison.md.tera");
const OUR_TOOLCHAIN: &str = "Rust 1.95.0, Nargo 1.0.0-beta.20, BB 5.0.0-nightly.20260324, nova-snark v0.71, fhe.rs rev 5f24d0b62a7329b789db07a065b68accd614a47b";
const OUR_PARAMS_TEMPLATE: &str = "N=8192, log₂q=174, B_e=16, B_s=1, B_r=TBD, T={t}, H={h}";

#[derive(Debug)]
pub enum RenderComparisonError {
    InvalidCommitSha(String),
    MissingCircuitMapping(String),
    MissingComparisonRow(String),
    CardinalityMismatch {
        circuit: String,
        expected: String,
        actual: String,
    },
    Template(tera::Error),
}

impl std::fmt::Display for RenderComparisonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCommitSha(commit_sha) => {
                write!(f, "invalid commit SHA for output filename: {commit_sha}")
            }
            Self::MissingCircuitMapping(circuit) => {
                write!(f, "missing circuit mapping for {circuit}")
            }
            Self::MissingComparisonRow(circuit) => {
                write!(f, "missing comparison row for {circuit}")
            }
            Self::CardinalityMismatch {
                circuit,
                expected,
                actual,
            } => write!(
                f,
                "cardinality mismatch for {circuit}: expected {expected}, got {actual}"
            ),
            Self::Template(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for RenderComparisonError {}

impl From<tera::Error> for RenderComparisonError {
    fn from(value: tera::Error) -> Self {
        Self::Template(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonEnvelope {
    pub circuit_timings: Vec<ComparisonCircuitTiming>,
    pub phase_totals: PhaseTotals,
    pub hardware: HardwareDisclosure,
    pub backend_ids: BackendIds,
    pub commit_sha: String,
    pub comparison_target: ComparisonTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonCircuitTiming {
    pub name: String,
    pub prove_ms: Option<f64>,
    pub verify_ms: Option<f64>,
    pub witness_ms: Option<f64>,
    pub vk_kb: Option<f64>,
    pub proof_kb: Option<f64>,
    pub status: String,
    pub cardinality_tag: String,
    pub instances_run: usize,
    pub comparability_note: String,
    pub gap_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseTotals {
    pub dkg_ms: Option<f64>,
    pub decrypt_ms: Option<f64>,
    pub onchain_verify_ms: Option<f64>,
    pub end_to_end_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareDisclosure {
    pub cpu: String,
    pub cpu_cores: usize,
    pub ram_gb: u64,
    pub kernel: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendIds {
    pub fhe: String,
    pub nizk: String,
    pub folding: String,
    pub compressor: String,
    pub pvss: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonTarget {
    pub name: String,
    pub source: String,
    pub n: usize,
    pub t: usize,
    pub seed: u64,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEnvelope {
    #[serde(rename = "_provenance")]
    pub provenance: BaselineProvenance,
    pub circuit_timings: Vec<BaselineCircuitTiming>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineProvenance {
    pub source_url: String,
    pub source_commit: String,
    pub retrieved: String,
    pub hardware: String,
    pub toolchain: String,
    pub config: String,
    pub estimation_method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineCircuitTiming {
    pub name: String,
    pub ms: f64,
    pub note: String,
}

#[derive(Debug, Serialize)]
struct TemplateContext {
    our_hardware: String,
    their_hardware: String,
    our_toolchain: String,
    their_toolchain: String,
    our_params: String,
    their_params: String,
    our_commit_sha: String,
    baseline_source_url: String,
    baseline_source_commit: String,
    baseline_retrieved: String,
    baseline_estimation_method: String,
    no_normalization_note: String,
    circuit_rows: Vec<TemplateRow>,
}

#[derive(Debug, Serialize)]
struct TemplateRow {
    name: String,
    cardinality: String,
    our_ms: String,
    their_ms: String,
    ratio: String,
    status: String,
    note: String,
}

pub fn render_comparison_markdown(
    comparison: &ComparisonEnvelope,
    baseline: &BaselineEnvelope,
) -> Result<String, RenderComparisonError> {
    render_comparison_markdown_with_template(DEFAULT_TEMPLATE, comparison, baseline)
}

pub fn render_comparison_markdown_with_template(
    template: &str,
    comparison: &ComparisonEnvelope,
    baseline: &BaselineEnvelope,
) -> Result<String, RenderComparisonError> {
    let template_context = build_context(comparison, baseline)?;
    let context = Context::from_serialize(template_context)?;
    Tera::one_off(template, &context, false).map_err(Into::into)
}

pub fn report_output_path(
    output_dir: &Path,
    commit_sha: &str,
) -> Result<PathBuf, RenderComparisonError> {
    let valid_sha = validated_commit_sha(commit_sha)?;
    Ok(output_dir.join(format!("comparison-{valid_sha}.md")))
}

fn build_context(
    comparison: &ComparisonEnvelope,
    baseline: &BaselineEnvelope,
) -> Result<TemplateContext, RenderComparisonError> {
    let circuit_rows = baseline
        .circuit_timings
        .iter()
        .map(
            |baseline_row| -> Result<TemplateRow, RenderComparisonError> {
                let mapping = mapping_for(&baseline_row.name).ok_or_else(|| {
                    RenderComparisonError::MissingCircuitMapping(baseline_row.name.clone())
                })?;
                let our_name = comparison_row_name(&baseline_row.name);
                let comparison_row = comparison
                    .circuit_timings
                    .iter()
                    .find(|row| row.name == our_name)
                    .ok_or_else(|| {
                        RenderComparisonError::MissingComparisonRow(baseline_row.name.clone())
                    })?;
                if comparison_row.cardinality_tag != mapping.cardinality {
                    return Err(RenderComparisonError::CardinalityMismatch {
                        circuit: baseline_row.name.clone(),
                        expected: mapping.cardinality.to_owned(),
                        actual: comparison_row.cardinality_tag.clone(),
                    });
                }
                let our_ms = primary_ms(comparison_row);

                Ok(TemplateRow {
                    name: baseline_row.name.clone(),
                    cardinality: mapping.cardinality.to_owned(),
                    our_ms: format_optional_ms(our_ms),
                    their_ms: format_ms(baseline_row.ms),
                    ratio: format_ratio(our_ms, baseline_row.ms),
                    status: comparison_row.status.clone(),
                    note: build_note(
                        mapping.aggregation_rule,
                        &comparison_row.comparability_note,
                        comparison_row.instances_run,
                        mapping.proof_system_note,
                        comparison_row.gap_reason.as_deref(),
                        &baseline_row.note,
                    ),
                })
            },
        )
        .collect::<Result<Vec<_>, _>>()?;

    Ok(TemplateContext {
        our_hardware: format_our_hardware(&comparison.hardware),
        their_hardware: format_their_hardware(&baseline.provenance.hardware),
        our_toolchain: OUR_TOOLCHAIN.to_owned(),
        their_toolchain: format!(
            "{}; Rust/Nova/fhe.rs details unpublished in baseline",
            baseline.provenance.toolchain
        ),
        our_params: OUR_PARAMS_TEMPLATE
            .replace("{t}", &comparison.comparison_target.t.to_string())
            .replace("{h}", &comparison.comparison_target.n.to_string()),
        their_params: format!(
            "{}; upstream did not publish N/log₂q/B_e/B_s/B_r in the vendored baseline",
            baseline.provenance.config
        ),
        our_commit_sha: comparison.commit_sha.clone(),
        baseline_source_url: baseline.provenance.source_url.clone(),
        baseline_source_commit: baseline.provenance.source_commit.clone(),
        baseline_retrieved: baseline.provenance.retrieved.clone(),
        baseline_estimation_method: baseline.provenance.estimation_method.clone(),
        no_normalization_note:
            "No normalization applied: Interfold numbers are reported verbatim from the vendored baseline; reader-side normalization only.".to_owned(),
        circuit_rows,
    })
}

fn primary_ms(row: &ComparisonCircuitTiming) -> Option<f64> {
    row.prove_ms.or(row.witness_ms).or(row.verify_ms)
}

fn format_our_hardware(hardware: &HardwareDisclosure) -> String {
    format!(
        "{}, {} cores, {} GB RAM, {}",
        hardware.cpu, hardware.cpu_cores, hardware.ram_gb, hardware.kernel
    )
}

fn format_their_hardware(raw: &str) -> String {
    let mut parts = raw.splitn(2, ',');
    let cpu = parts.next().unwrap_or(raw).trim();
    let tail = parts
        .next()
        .map(str::trim)
        .unwrap_or("hardware details unpublished");
    let normalized_tail = tail
        .replace("14c", "14 cores")
        .replace("/48GB", ", 48 GB RAM")
        .replace("/62GB", ", 62 GB RAM");
    format!("{cpu}, {normalized_tail}, OS unpublished in baseline")
}

fn format_optional_ms(value: Option<f64>) -> String {
    value.map(format_ms).unwrap_or_else(|| "n/a".to_owned())
}

fn format_ms(value: f64) -> String {
    format!("{value:.1}")
}

fn format_ratio(our_ms: Option<f64>, their_ms: f64) -> String {
    match our_ms {
        Some(value) if their_ms > 0.0 => format!("{:.4}x", value / their_ms),
        _ => "n/a".to_owned(),
    }
}

fn build_note(
    aggregation_rule: &str,
    comparability_note: &str,
    instances_run: usize,
    proof_system_note: Option<&str>,
    gap_reason: Option<&str>,
    baseline_note: &str,
) -> String {
    let mut parts = vec![
        format!("aggregation={aggregation_rule}"),
        format!("instances_run={instances_run}"),
        comparability_note.to_owned(),
        format!("Interfold baseline: {baseline_note}"),
    ];
    if let Some(note) = proof_system_note {
        parts.push(note.to_owned());
    }
    if let Some(gap) = gap_reason {
        parts.push(format!("gap: {gap}"));
    }
    parts.join("; ")
}

fn validated_commit_sha(commit_sha: &str) -> Result<&str, RenderComparisonError> {
    let is_valid =
        (7..=64).contains(&commit_sha.len()) && commit_sha.chars().all(|ch| ch.is_ascii_hexdigit());
    if is_valid {
        Ok(commit_sha)
    } else {
        Err(RenderComparisonError::InvalidCommitSha(
            commit_sha.to_owned(),
        ))
    }
}
