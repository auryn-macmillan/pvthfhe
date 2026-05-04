//! Real P1 lattice NIZK adapter — delegates to `pvthfhe_nizk::adapter::CycloNizkAdapter`.
#![cfg(feature = "real-nizk")]

use pvthfhe_nizk::adapter::CycloNizkAdapter;
use pvthfhe_nizk::NizkAdapter as NizkAdapterTrait;
use rand_core::RngCore;
use thiserror::Error;

/// Frozen public statement for one lattice NIZK claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NizkStatement {
    /// Canonical ciphertext bytes.
    pub ciphertext_bytes: Vec<u8>,
    /// Canonical partial decrypt-share bytes.
    pub decrypt_share_bytes: Vec<u8>,
    /// P4 PVSS commitment hash.
    pub pvss_commitment: [u8; 32],
    /// Bound FHE parameter tuple `(q, degree, error_bound)`.
    pub params: (u64, usize, u64),
    /// Session binding inherited from P4.
    pub session_id: String,
    /// Participant binding inherited from P4.
    pub participant_id: u16,
}

/// Frozen prover witness for one lattice NIZK claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NizkWitness {
    /// Secret share value inherited from P4 (scalar u64).
    ///
    /// Kept for backward compatibility; the Cyclo backend uses
    /// [`NizkWitness::secret_share_poly`] for the algebraic RLWE proof and only
    /// uses this field for the D2 hash-binding commitment.
    pub secret_share: u64,
    /// Ternary RLWE secret-share polynomial (length N=8192, coefficients ∈ {-1,0,1}).
    ///
    /// This is the polynomial form of the secret share used by the
    /// `CycloNizkAdapter` sigma protocol.  It is independent of
    /// [`NizkWitness::secret_share`]: the scalar is the D2 binding value while
    /// the polynomial is the RLWE algebraic witness.
    pub secret_share_poly: Vec<i64>,
    /// Canonical lattice error bytes.
    pub error: Vec<i64>,
    /// Canonical prover randomness bytes.
    pub randomness: Vec<u8>,
}

/// Opaque deterministic proof record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NizkProof {
    /// Proof backend identifier.
    pub backend_id: String,
    /// Serialized proof payload.
    pub proof_bytes: Vec<u8>,
}

impl NizkProof {
    /// Returns the canonical serialized proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.proof_bytes
    }
}

/// Errors produced by the real lattice NIZK adapter.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NizkError {
    /// Verification succeeded algebraically but soundness is conditional
    /// (mirrors `pvthfhe_nizk::NizkError::ConditionalSoundnessDisclosure`).
    #[error("conditional soundness: {0}")]
    ConditionalSoundnessDisclosure(&'static str),
    /// Statement or witness encoding is malformed.
    #[error("invalid lattice NIZK input: {0}")]
    InvalidInput(&'static str),
    /// Proof bytes could not be decoded.
    #[error("invalid lattice NIZK proof: {0}")]
    InvalidProof(&'static str),
    /// The proof does not satisfy the verification equation.
    #[error("lattice NIZK verification failed: {0}")]
    VerificationFailed(&'static str),
}

/// Frozen trait boundary for P1 lattice NIZK backends.
pub trait LatticeNizk {
    /// Produce a proof for the provided statement and witness.
    fn prove(
        stmt: &NizkStatement,
        witness: &NizkWitness,
        rng: &mut impl RngCore,
    ) -> Result<NizkProof, NizkError>;

    /// Verify a single proof.
    ///
    /// # Security
    ///
    /// Verification success is conditional on T2 (knowledge soundness — skeleton). See SECURITY.md §P1.
    fn verify(stmt: &NizkStatement, proof: &NizkProof) -> Result<(), NizkError>;

    /// Verify a batch of statements and proofs.
    fn batch_verify(stmts: &[NizkStatement], proofs: &[NizkProof]) -> Result<(), NizkError>;
}

/// Real NIZK adapter — delegates to `pvthfhe_nizk::adapter::CycloNizkAdapter`.
///
/// `backend_id()` returns [`pvthfhe_nizk::BACKEND_ID`] = `"cyclo-ajtai-d2-conditional"`.
#[derive(Debug, Default)]
pub struct RealNizkAdapter;

fn to_nizk_stmt(stmt: &NizkStatement) -> pvthfhe_nizk::NizkStatement {
    pvthfhe_nizk::NizkStatement {
        ciphertext_bytes: stmt.ciphertext_bytes.clone(),
        decrypt_share_bytes: stmt.decrypt_share_bytes.clone(),
        pvss_commitment: stmt.pvss_commitment,
        params: stmt.params,
        session_id: stmt.session_id.clone(),
        participant_id: stmt.participant_id,
    }
}

fn to_nizk_witness(witness: &NizkWitness) -> pvthfhe_nizk::NizkWitness {
    pvthfhe_nizk::NizkWitness {
        secret_share: witness.secret_share,
        secret_share_poly: witness.secret_share_poly.clone(),
        error: witness.error.clone(),
        randomness: witness.randomness.clone(),
    }
}

fn from_nizk_proof(p: pvthfhe_nizk::NizkProof) -> NizkProof {
    NizkProof {
        backend_id: p.backend_id,
        proof_bytes: p.proof_bytes,
    }
}

fn to_nizk_proof(p: &NizkProof) -> pvthfhe_nizk::NizkProof {
    pvthfhe_nizk::NizkProof {
        backend_id: p.backend_id.clone(),
        proof_bytes: p.proof_bytes.clone(),
    }
}

fn map_err(e: pvthfhe_nizk::NizkError) -> NizkError {
    match e {
        pvthfhe_nizk::NizkError::ConditionalSoundnessDisclosure(m) => {
            NizkError::ConditionalSoundnessDisclosure(m)
        }
        pvthfhe_nizk::NizkError::InvalidInput(m) => NizkError::InvalidInput(m),
        pvthfhe_nizk::NizkError::InvalidProof(m) => NizkError::InvalidProof(m),
        pvthfhe_nizk::NizkError::VerificationFailed(m) => NizkError::VerificationFailed(m),
    }
}

impl LatticeNizk for RealNizkAdapter {
    fn prove(
        stmt: &NizkStatement,
        witness: &NizkWitness,
        rng: &mut impl RngCore,
    ) -> Result<NizkProof, NizkError> {
        let adapter = CycloNizkAdapter;
        let nizk_stmt = to_nizk_stmt(stmt);
        let nizk_witness = to_nizk_witness(witness);
        let proof = adapter
            .prove(&nizk_stmt, &nizk_witness, &mut *rng)
            .map_err(map_err)?;
        Ok(from_nizk_proof(proof))
    }

    fn verify(stmt: &NizkStatement, proof: &NizkProof) -> Result<(), NizkError> {
        let adapter = CycloNizkAdapter;
        let nizk_stmt = to_nizk_stmt(stmt);
        let nizk_proof = to_nizk_proof(proof);
        adapter.verify(&nizk_stmt, &nizk_proof).map_err(map_err)
    }

    fn batch_verify(stmts: &[NizkStatement], proofs: &[NizkProof]) -> Result<(), NizkError> {
        let adapter = CycloNizkAdapter;
        let nizk_stmts: Vec<_> = stmts.iter().map(to_nizk_stmt).collect();
        let nizk_proofs: Vec<_> = proofs.iter().map(to_nizk_proof).collect();
        adapter
            .batch_verify(&nizk_stmts, &nizk_proofs)
            .map_err(map_err)
    }
}

/// Cyclo-companion D2 NIZK backend identifier.
///
/// The `-conditional` suffix is intentional: it signals to consumers that
/// verification is conditional on the unproven joint extractor (T2 — see
/// SECURITY.md §P1).
pub use pvthfhe_nizk::BACKEND_ID as CYCLO_BACKEND_ID;
