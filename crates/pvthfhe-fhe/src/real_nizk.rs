//! Frozen P1 lattice NIZK stub surface for RED tests.

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
    /// Secret share value inherited from P4.
    pub secret_share: u64,
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
    /// The real lattice NIZK backend is not implemented yet.
    #[error("real lattice NIZK not implemented")]
    NotImplemented,
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
    fn verify(stmt: &NizkStatement, proof: &NizkProof) -> Result<(), NizkError>;

    /// Verify a batch of statements and proofs.
    fn batch_verify(stmts: &[NizkStatement], proofs: &[NizkProof]) -> Result<(), NizkError>;
}

/// Stub adapter used by the RED test phase.
#[derive(Debug, Default)]
pub struct RealNizkAdapter;

impl LatticeNizk for RealNizkAdapter {
    fn prove(
        _stmt: &NizkStatement,
        _witness: &NizkWitness,
        _rng: &mut impl RngCore,
    ) -> Result<NizkProof, NizkError> {
        unimplemented!("TODO(B.I.2): implement real lattice NIZK prover")
    }

    fn verify(_stmt: &NizkStatement, _proof: &NizkProof) -> Result<(), NizkError> {
        unimplemented!("TODO(B.I.2): implement real lattice NIZK verifier")
    }

    fn batch_verify(_stmts: &[NizkStatement], _proofs: &[NizkProof]) -> Result<(), NizkError> {
        unimplemented!("TODO(B.I.2): implement real lattice NIZK batch verifier")
    }
}
