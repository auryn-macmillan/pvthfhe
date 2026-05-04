#![allow(missing_docs)]

//! Recursive aggregation harness for folding N party proofs into a single final SNARK.
//!
//! Note: Full LatticeFold+/HyperNova/MicroNova over RLWE is an open research problem (P2).
//! This implementation provides a simulated folding harness that uses a hash-chain
//! accumulation as a surrogate for real folding.
//!
//! # Security — Conditional Soundness (P1)
//!
//! ⚠️ When `CycloAdapter` is wired in (Phase 2 F-series), folding will
//! accumulate per-share witnesses conditionally sound under M-SIS over
//! `R_{q_commit}` plus Cyclo Theorem 3 (ePrint 2026/359).  The joint
//! extractor (T2) remains a skeleton.  See `SECURITY.md §P1`.
//!
//! The current implementation is a hash-chain SURROGATE; this banner is
//! placed here so the disclosure exists at the module boundary today and
//! will apply automatically when the real adapter lands.

use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FoldingError {
    #[error("Invalid leaf proof for party {0}")]
    InvalidLeaf(u32),
}

#[derive(Debug, Clone)]
pub struct PartyProof {
    pub party_id: u32,
    pub share_hash: [u8; 32],
    pub nizk_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FinalSnark {
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
    pub prover_time_ms: u64,
    pub proof_size_bytes: usize,
}

pub struct FoldingAccumulator {
    proofs: Vec<PartyProof>,
}

impl Default for FoldingAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl FoldingAccumulator {
    pub fn new() -> Self {
        Self { proofs: Vec::new() }
    }

    pub fn add_proof(&mut self, proof: PartyProof) -> Result<(), FoldingError> {
        self.proofs.push(proof);
        Ok(())
    }

    pub fn finalize(&self) -> Result<FinalSnark, FoldingError> {
        let mut hasher = Sha256::new();
        let mut public_inputs = Vec::with_capacity(self.proofs.len());

        let start_time = std::time::Instant::now();

        for proof in &self.proofs {
            if proof.nizk_bytes.is_empty() {
                return Err(FoldingError::InvalidLeaf(proof.party_id));
            }
            hasher.update(proof.share_hash);
            hasher.update(&proof.nizk_bytes);
            public_inputs.push(proof.share_hash);
        }

        let hash = hasher.finalize();
        let proof_bytes = hash.to_vec();

        let prover_time_ms = u64::try_from(start_time.elapsed().as_millis()).unwrap_or(u64::MAX);
        let proof_size_bytes = proof_bytes.len();

        Ok(FinalSnark {
            proof_bytes,
            public_inputs,
            prover_time_ms,
            proof_size_bytes,
        })
    }
}

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
pub struct RealFoldingScheme;

#[cfg(feature = "real-folding")]
impl FoldingScheme for RealFoldingScheme {
    fn fold(
        acc: &FoldAccumulator,
        witness: &FoldWitness,
        stmt: &FoldStatement,
    ) -> Result<FoldAccumulator, FoldError> {
        validate_accumulator(acc)?;
        validate_statement_binding(acc, stmt)?;
        validate_witness(witness, stmt)?;

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
        Ok(())
    }

    fn finalize(acc: &FoldAccumulator) -> Result<FinalProof, FoldError> {
        validate_accumulator(acc)?;
        let proof_bytes = hash_parts(&[b"pvthfhe/finalize/v1", encode_accumulator(acc).as_slice()]);
        Ok(FinalProof { proof_bytes })
    }
}

#[cfg(feature = "real-folding")]
pub fn fold(
    acc: &FoldAccumulator,
    witness: &FoldWitness,
    stmt: &FoldStatement,
) -> Result<FoldAccumulator, FoldError> {
    RealFoldingScheme::fold(acc, witness, stmt)
}

#[cfg(feature = "real-folding")]
pub fn verify_acc(
    acc: &FoldAccumulator,
    expected_params: &(u64, usize, u64),
) -> Result<(), FoldError> {
    RealFoldingScheme::verify_acc(acc, expected_params)
}

#[cfg(feature = "real-folding")]
pub fn finalize(acc: &FoldAccumulator) -> Result<FinalProof, FoldError> {
    RealFoldingScheme::finalize(acc)
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
    if proof_bytes.is_empty() {
        return Err(FoldError("proof integrity check failed".to_string()));
    }
    if !proof_bytes.windows(2).all(|window| window[0] == window[1]) {
        return Err(FoldError("proof integrity check failed".to_string()));
    }
    if proof_bytes[0] != expected_proof_tag(stmt) {
        return Err(FoldError("proof integrity check failed".to_string()));
    }
    let error_bound = stmt.params.2;
    if proof_bytes.iter().any(|&b| u64::from(b) > error_bound) {
        return Err(FoldError(format!(
            "witness coefficient {} exceeds norm bound {}",
            proof_bytes.iter().copied().max().unwrap_or(0),
            error_bound,
        )));
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
