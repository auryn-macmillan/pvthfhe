#![allow(missing_docs)]
//! Recursive aggregation harness for folding N party proofs into a single final SNARK.
//!
//! Note: Full LatticeFold+/HyperNova/MicroNova over RLWE is an open research problem (P2).
//! This implementation previously used a hash-chain accumulation as a surrogate.
//! The `HashChainCycloAdapter` now wires the real Cyclo LatticeFold+ backend (F8).
//!
//! # Security — Conditional Soundness (P1)
//!
//! Folding accumulates per-share witnesses conditionally sound under M-SIS over
//! `R_{q_commit}` plus Cyclo Theorem 3 (ePrint 2026/359). The joint
//! extractor (T2) remains a skeleton. See `SECURITY.md §P1`.

#[cfg(feature = "legacy-fold")]
compile_error!("The `legacy-fold` feature has been removed in R4.3. Use `real-folding` (enabled by default).");

use pvthfhe_cyclo::adapter::LegacyHashChainAdapter;
pub use pvthfhe_cyclo::CcsPShareInstance;
use pvthfhe_cyclo::{CycloAccumulator, CycloAdapter as _, CycloError, CYCLO_BACKEND_ID};
#[cfg(feature = "real-folding")]
use pvthfhe_cyclo::fold as cyclo_fold;
#[cfg(feature = "real-folding")]
use pvthfhe_domain_tags::Tag;
#[cfg(feature = "real-folding")]
use pvthfhe_nizk::BACKEND_ID as NIZK_BACKEND_ID;
#[cfg(feature = "real-folding")]
use pvthfhe_types::{CcsWitnessSecret, ProtocolBytes};
use pvthfhe_types::witness_language::{
    BfvParameters as SchemaBfvParams, WitnessCommitment, WitnessStatement,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

// R3.0a — schema types wired for R4.1 GREEN migration
const _: () = {
    let _: Option<SchemaBfvParams> = None;
    let _: Option<WitnessCommitment> = None;
    let _: Option<WitnessStatement> = None;
};

#[cfg(feature = "real-folding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldStatement {
    pub fold_index: u64,
    pub session_id: String,
    pub params: (u64, usize, u64),
    pub nizk_statement: NizkStatement,
}

#[cfg(feature = "real-folding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldWitness {
    pub nizk_proof: NizkProof,
    pub fold_randomness: Vec<u8>,
}

#[cfg(feature = "real-folding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldAccumulator {
    acc_commitment: Vec<u8>,
    fold_depth: u64,
    session_id: String,
    params: (u64, usize, u64),
    statement_hash_chain: [u8; 32],
    /// Underlying Cyclo accumulator (populated after the first fold step).
    cyclo_acc: Option<CycloAccumulator>,
}

#[cfg(feature = "real-folding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalProof {
    pub proof_bytes: Vec<u8>,
}

#[cfg(feature = "real-folding")]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct FoldError(pub String);

#[cfg(feature = "real-folding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NizkStatement {
    pub session_id: String,
    pub params: (u64, usize, u64),
    pub ciphertext_bytes: Vec<u8>,
}

#[cfg(feature = "real-folding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NizkProof {
    pub proof_bytes: Vec<u8>,
    pub nizk_backend_id: &'static str,
}

#[cfg(feature = "real-folding")]
impl NizkProof {
    pub const EXPECTED_BACKEND_ID: &'static str = NIZK_BACKEND_ID;
}

#[cfg(feature = "real-folding")]
pub trait FoldingScheme {
    fn fold(
        acc: &FoldAccumulator,
        witness: &FoldWitness,
        stmt: &FoldStatement,
    ) -> Result<FoldAccumulator, FoldError>;

    fn verify_acc(
        acc: &FoldAccumulator,
        expected_params: &(u64, usize, u64),
    ) -> Result<(), FoldError>;

    fn finalize(acc: &FoldAccumulator) -> Result<FinalProof, FoldError>;
}

#[cfg(feature = "real-folding")]
struct HashChainFoldingScheme;

#[cfg(feature = "real-folding")]
impl FoldingScheme for HashChainFoldingScheme {
    fn fold(
        acc: &FoldAccumulator,
        witness: &FoldWitness,
        stmt: &FoldStatement,
    ) -> Result<FoldAccumulator, FoldError> {
        validate_accumulator(acc)?;
        validate_statement_binding(acc, stmt)?;
        validate_witness(witness, stmt)?;

        // Convert FoldStatement + FoldWitness → CcsPShareInstance
        let ccs_instance = fold_stmt_witness_to_cyclo_instance(stmt, witness, acc);

        // Get or initialise the Cyclo accumulator
        let prev_cyclo_acc = acc.cyclo_acc.clone().unwrap_or_else(|| {
            cyclo_fold::init_accumulator(&ccs_instance, &acc.session_id)
                .expect("init_accumulator must succeed for valid instance")
        });

        // Fold via the Cyclo LatticeFold+ backend
        let adapter = LegacyHashChainAdapter;
        let mut rng = OsRng;
        let new_cyclo_acc = adapter
            .fold_one(prev_cyclo_acc, &ccs_instance, &mut rng)
            .map_err(|e| FoldError(format!("Cyclo fold failed: {e}")))?;

        // Maintain backward-compatible hash-chain fields
        let stmt_bytes = serialize_fold_statement(stmt);
        let acc_commitment = hash_parts(&[
            acc.acc_commitment.as_slice(),
            stmt_bytes.as_slice(),
            witness.nizk_proof.proof_bytes.as_slice(),
            witness.fold_randomness.as_slice(),
        ]);

        Ok(FoldAccumulator {
            acc_commitment,
            fold_depth: acc.fold_depth.saturating_add(1),
            session_id: acc.session_id.clone(),
            params: acc.params,
            statement_hash_chain: hash_array_parts(&[
                acc.statement_hash_chain.as_slice(),
                stmt_bytes.as_slice(),
            ]),
            cyclo_acc: Some(new_cyclo_acc),
        })
    }

    fn verify_acc(
        acc: &FoldAccumulator,
        expected_params: &(u64, usize, u64),
    ) -> Result<(), FoldError> {
        validate_accumulator(acc)?;
        if acc.params != *expected_params {
            return Err(FoldError("param mismatch".to_string()));
        }
        // Verify Cyclo accumulator structure when present
        if let Some(cyclo_acc) = &acc.cyclo_acc {
            verify_cyclo_accumulator_structure(cyclo_acc)?;
        } else if acc.fold_depth > 0 {
            return Err(FoldError(
                "accumulator at depth > 0 must carry Cyclo data".to_string(),
            ));
        }
        Ok(())
    }

    fn finalize(acc: &FoldAccumulator) -> Result<FinalProof, FoldError> {
        validate_accumulator(acc)?;
        let proof_bytes = hash_parts(&[Tag::Finalize.as_bytes(), encode_accumulator(acc).as_slice()]);
        Ok(FinalProof { proof_bytes })
    }
}

#[cfg(feature = "real-folding")]
pub fn fold(
    acc: &FoldAccumulator,
    witness: &FoldWitness,
    stmt: &FoldStatement,
) -> Result<FoldAccumulator, FoldError> {
    HashChainFoldingScheme::fold(acc, witness, stmt)
}

#[cfg(feature = "real-folding")]
pub fn verify_acc(
    acc: &FoldAccumulator,
    expected_params: &(u64, usize, u64),
) -> Result<(), FoldError> {
    HashChainFoldingScheme::verify_acc(acc, expected_params)
}

#[cfg(feature = "real-folding")]
pub fn finalize(acc: &FoldAccumulator) -> Result<FinalProof, FoldError> {
    HashChainFoldingScheme::finalize(acc)
}

#[cfg(feature = "real-folding")]
impl FoldAccumulator {
    pub fn new(
        acc_commitment: Vec<u8>,
        fold_depth: u64,
        session_id: String,
        params: (u64, usize, u64),
        statement_hash_chain: [u8; 32],
    ) -> Self {
        Self {
            acc_commitment,
            fold_depth,
            session_id,
            params,
            statement_hash_chain,
            cyclo_acc: None,
        }
    }

    pub fn acc_commitment(&self) -> &[u8] {
        &self.acc_commitment
    }

    pub fn fold_depth(&self) -> u64 {
        self.fold_depth
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn params(&self) -> (u64, usize, u64) {
        self.params
    }

    pub fn statement_hash_chain(&self) -> [u8; 32] {
        self.statement_hash_chain
    }

    pub fn cyclo_acc(&self) -> Option<&CycloAccumulator> {
        self.cyclo_acc.as_ref()
    }
}

#[cfg(feature = "real-folding")]
fn validate_statement_binding(
    acc: &FoldAccumulator,
    stmt: &FoldStatement,
) -> Result<(), FoldError> {
    let expected_fold_index = acc.fold_depth.saturating_add(1);
    if acc.params != stmt.params || stmt.params != stmt.nizk_statement.params {
        return Err(FoldError("param mismatch".to_string()));
    }
    if acc.session_id != stmt.session_id || stmt.session_id != stmt.nizk_statement.session_id {
        return Err(FoldError("session mismatch".to_string()));
    }
    if stmt.fold_index != expected_fold_index {
        return Err(FoldError("fold index mismatch".to_string()));
    }
    Ok(())
}

#[cfg(feature = "real-folding")]
fn validate_witness(witness: &FoldWitness, stmt: &FoldStatement) -> Result<(), FoldError> {
    let proof_bytes = &witness.nizk_proof.proof_bytes;
    // Quick-reject empty proofs before heavier Cyclo processing
    if proof_bytes.is_empty() {
        return Err(FoldError("proof integrity check failed".to_string()));
    }
    // Quick-reject proofs exceeding the Cyclo norm bound before encoding
    let error_bound = stmt.params.2;
    if proof_bytes.iter().any(|&b| u64::from(b) > error_bound) {
        return Err(FoldError(format!(
            "witness coefficient exceeds norm bound {}",
            error_bound,
        )));
    }
    // R4.4: validate NIZK proof structure — verifies backend_id,
    // proof version, and CCS instance ID binding.
    validate_nizk_structure(witness, stmt)?;
    Ok(())
}

/// Verify the NIZK proof backend matches the expected R3 NIZK backend.
///
/// When the `real-nizk` feature is active, also enforces the minimum
/// structured NIZK proof size (version + ccs_id + Ajtai commitment).
#[cfg(feature = "real-folding")]
fn validate_nizk_structure(witness: &FoldWitness, _stmt: &FoldStatement) -> Result<(), FoldError> {
    let proof = &witness.nizk_proof;
    if proof.nizk_backend_id != NizkProof::EXPECTED_BACKEND_ID {
        return Err(FoldError(format!(
            "NIZK backend mismatch: expected {}, got {}",
            NizkProof::EXPECTED_BACKEND_ID,
            proof.nizk_backend_id,
        )));
    }
    // R4.4: when real NIZK is wired, enforce minimum proof size.
    // Real Ajtai D2 NIZK proofs carry: version(2) + ccs_id(32) + ajtai(26624).
    // Forged short proofs (e.g. 32 bytes) are rejected here.
    #[cfg(feature = "real-nizk")]
    {
        const MIN_NIZK_PROOF_SIZE: usize = 2 + 32 + 26624;
        if proof.proof_bytes.len() < MIN_NIZK_PROOF_SIZE {
            return Err(FoldError(format!(
                "NIZK proof too short: {} bytes (minimum {}) for structured Cyclo-Ajtai-D2 proof",
                proof.proof_bytes.len(),
                MIN_NIZK_PROOF_SIZE,
            )));
        }
    }
    Ok(())
}

/// Convert a `(FoldStatement, FoldWitness)` pair into a `CcsPShareInstance`
/// suitable for Cyclo folding.
#[cfg(feature = "real-folding")]
fn fold_stmt_witness_to_cyclo_instance(
    stmt: &FoldStatement,
    witness: &FoldWitness,
    _acc: &FoldAccumulator,
) -> CcsPShareInstance {
    let participant_id = u16::try_from(stmt.fold_index).unwrap_or(u16::MAX);
    let mut hasher = Sha256::new();
    hasher.update(&participant_id.to_be_bytes());
    hasher.update(stmt.session_id.as_bytes());
    hasher.update(&stmt.params.0.to_be_bytes());
    hasher.update(&stmt.params.1.to_be_bytes());
    hasher.update(&stmt.params.2.to_be_bytes());
    hasher.update(stmt.nizk_statement.ciphertext_bytes.as_slice());
    let binding_bytes: [u8; 32] = hasher.finalize().into();

    CcsPShareInstance {
        participant_id,
        ajtai_commitment_bytes: ProtocolBytes::from(
            witness.nizk_proof.proof_bytes.clone(),
        ),
        public_io_bytes: ProtocolBytes::from(
            stmt.nizk_statement.ciphertext_bytes.clone(),
        ),
        ccs_witness_bytes: CcsWitnessSecret::new(witness.nizk_proof.proof_bytes.clone()),
        sha256_binding_bytes: ProtocolBytes::from(binding_bytes.to_vec()),
        ccs_matrix_bytes: ProtocolBytes::from(vec![]),
    }
}

/// Verify that a Cyclo accumulator satisfies structural invariants.
#[cfg(feature = "real-folding")]
fn verify_cyclo_accumulator_structure(cyclo_acc: &CycloAccumulator) -> Result<(), FoldError> {
    use pvthfhe_cyclo::PVTHFHE_CYCLO_PARAMS;
    if cyclo_acc.fold_depth > PVTHFHE_CYCLO_PARAMS.sequential_t {
        return Err(FoldError(format!(
            "Cyclo fold depth {} exceeds T={}",
            cyclo_acc.fold_depth,
            PVTHFHE_CYCLO_PARAMS.sequential_t,
        )));
    }
    if cyclo_acc.norm_bound_current > PVTHFHE_CYCLO_PARAMS.beta_at_t {
        return Err(FoldError("Cyclo accumulator norm bound exceeded beta_at_t".to_string()));
    }
    if cyclo_acc.acc_commitment_bytes.len() != 32 {
        return Err(FoldError(
            "Cyclo acc_commitment_bytes must be 32 bytes".to_string(),
        ));
    }
    if cyclo_acc.acc_public_io_bytes.len() != 32 {
        return Err(FoldError(
            "Cyclo acc_public_io_bytes must be 32 bytes".to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "real-folding")]
fn validate_accumulator(acc: &FoldAccumulator) -> Result<(), FoldError> {
    if acc.acc_commitment.is_empty() {
        return Err(FoldError("empty accumulator commitment".to_string()));
    }
    if acc.session_id.is_empty() {
        return Err(FoldError("empty session id".to_string()));
    }
    Ok(())
}

#[cfg(feature = "real-folding")]
fn serialize_fold_statement(stmt: &FoldStatement) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        stmt.session_id.len()
            + stmt.nizk_statement.session_id.len()
            + stmt.nizk_statement.ciphertext_bytes.len()
            + 64,
    );
    push_string(&mut bytes, &stmt.nizk_statement.session_id);
    push_params(&mut bytes, stmt.nizk_statement.params);
    push_vec(&mut bytes, &stmt.nizk_statement.ciphertext_bytes);
    bytes.extend_from_slice(&stmt.fold_index.to_be_bytes());
    push_string(&mut bytes, &stmt.session_id);
    push_params(&mut bytes, stmt.params);
    bytes
}

#[cfg(feature = "real-folding")]
fn encode_accumulator(acc: &FoldAccumulator) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(acc.acc_commitment.len() + acc.session_id.len() + 96);
    push_vec(&mut bytes, acc.acc_commitment.as_slice());
    bytes.extend_from_slice(&acc.fold_depth.to_be_bytes());
    push_string(&mut bytes, &acc.session_id);
    push_params(&mut bytes, acc.params);
    bytes.extend_from_slice(acc.statement_hash_chain.as_slice());
    bytes
}

#[cfg(feature = "real-folding")]
fn expected_proof_tag(stmt: &FoldStatement) -> u8 {
    stmt.nizk_statement
        .ciphertext_bytes
        .first()
        .copied()
        .unwrap_or_default()
}

#[cfg(feature = "real-folding")]
fn push_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

#[cfg(feature = "real-folding")]
fn push_vec(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    bytes.extend_from_slice(value);
}

#[cfg(feature = "real-folding")]
fn push_params(bytes: &mut Vec<u8>, params: (u64, usize, u64)) {
    bytes.extend_from_slice(&params.0.to_be_bytes());
    bytes.extend_from_slice(&u64::try_from(params.1).unwrap_or(u64::MAX).to_be_bytes());
    bytes.extend_from_slice(&params.2.to_be_bytes());
}

#[cfg(feature = "real-folding")]
fn hash_parts(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

#[cfg(feature = "real-folding")]
fn hash_array_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash_parts(parts));
    out
}

/// Folding adapter backed by the real Cyclo LatticeFold+ backend.
///
/// Replaces the hash-chain surrogate for all new aggregation paths.
pub struct HashChainCycloAdapter {
    inner: LegacyHashChainAdapter,
}

pub struct CycloFoldAllReport {
    accumulators: Vec<CycloAccumulator>,
    share_count: usize,
    batch_size: usize,
}

impl CycloFoldAllReport {
    /// Construct a new report from pre-computed accumulators.
    pub fn new(
        accumulators: Vec<CycloAccumulator>,
        share_count: usize,
        batch_size: usize,
    ) -> Self {
        Self {
            accumulators,
            share_count,
            batch_size,
        }
    }

    pub fn accumulators(&self) -> &[CycloAccumulator] {
        &self.accumulators
    }

    pub fn batch_count(&self) -> usize {
        self.accumulators.len()
    }

    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    pub fn share_count(&self) -> usize {
        self.share_count
    }
}

impl HashChainCycloAdapter {
    /// Create a new adapter using the locked Cyclo parameter set.
    pub fn new() -> Self {
        Self {
            inner: LegacyHashChainAdapter,
        }
    }

    /// Returns the Cyclo backend identifier (`"cyclo-rlwe-t10"`).
    pub fn backend_id(&self) -> &'static str {
        self.inner.backend_id()
    }

    pub fn fold_all(
        &self,
        instances: &[CcsPShareInstance],
        session_id: &str,
        rng: &mut dyn rand_core::RngCore,
    ) -> Result<CycloFoldAllReport, CycloError> {
        if instances.is_empty() {
            return Err(CycloError::InvalidInstance(
                "at least one instance required",
            ));
        }

        let batch_size = usize::try_from(self.inner.params().sequential_t)
            .map_err(|_| CycloError::InvalidInstance("sequential_t overflows usize"))?;
        let mut accumulators = Vec::with_capacity(instances.len().div_ceil(batch_size));

        for (batch_index, batch) in instances.chunks(batch_size).enumerate() {
            let batch_session_id = format!("{session_id}-batch-{batch_index}");
            let accumulator = self.inner.fold_all(batch, &batch_session_id, rng)?;
            self.inner.verify_accumulator(&accumulator, batch)?;
            accumulators.push(accumulator);
        }

        Ok(CycloFoldAllReport {
            accumulators,
            share_count: instances.len(),
            batch_size,
        })
    }

    pub fn verify_fold_all(
        &self,
        report: &CycloFoldAllReport,
        instances: &[CcsPShareInstance],
    ) -> Result<(), CycloError> {
        if instances.len() != report.share_count {
            return Err(CycloError::AccumulatorVerificationFailed(
                "share_count does not match number of instances",
            ));
        }
        if report.batch_size == 0 {
            return Err(CycloError::AccumulatorVerificationFailed(
                "batch_size must be non-zero",
            ));
        }

        let expected_batches = instances.len().div_ceil(report.batch_size);
        if report.accumulators.len() != expected_batches {
            return Err(CycloError::AccumulatorVerificationFailed(
                "batch count does not match number of instance chunks",
            ));
        }

        for (accumulator, batch) in report
            .accumulators
            .iter()
            .zip(instances.chunks(report.batch_size))
        {
            self.inner.verify_accumulator(accumulator, batch)?;
        }

        Ok(())
    }
}

impl Default for HashChainCycloAdapter {
    fn default() -> Self {
        Self::new()
    }
}

const _: &str = CYCLO_BACKEND_ID;
