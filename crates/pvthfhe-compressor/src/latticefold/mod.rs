//! LatticeFold+ — Lattice-native folding protocol.
//!
//! Implements the LatticeFold+ folding scheme from ePrint 2025/247:
//! - §4.3 Monomial set check: algebraic range proof without bit decomposition.
//! - §4.1 Double commitments: commitments of commitments for shorter proofs.
//! - §5 Folding: fold n instances into one using random β.
//! - §5.2 Sumcheck transformation: fold double commitments via sumcheck.
//!
//! This module is gated behind `#[cfg(feature = "enable-latticefold")]`.
//!
//! # Architecture
//!
//! ```text
//! latticefold/
//! ├── prover.rs         ← LatticeFoldProver (fold n → 1)
//! ├── verifier.rs       ← LatticeFoldVerifier (verify accumulator)
//! ├── fold.rs           ← Core fold/verify primitives
//! ├── compressor.rs     ← LatticeFoldCompressor (compressor API)
//! ├── range_proof.rs    ← Algebraic range proof
//! ├── double_commit.rs  ← Double commitment scheme (§4.1)
//! ├── sumcheck.rs       ← Sumcheck transformation (§5.2)
//! ├── pk_aggregation.rs ← PK aggregation step circuit (C5)
//! ├── bfv_snapshot.rs   ← BFV encryption snapshot circuit
//! └── fhe_compute_circuit.rs ← FHE compute step circuit
//! ```

pub mod bfv_snapshot;
pub mod compressor;
pub mod double_commit;
pub mod fhe_compute_circuit;
pub mod fold;
pub mod pk_aggregation;
pub mod prover;
pub mod range_proof;
pub mod sumcheck;
pub mod verifier;

pub use bfv_snapshot::{
    prove_bfv_snapshot, verify_bfv_snapshot, BfvSnapshotProof, BfvSnapshotProver,
    BfvSnapshotVerifier,
};
pub use compressor::{ExternalInputs3, LatticeFoldCompressor};
pub use double_commit::{double_commit, smart_commit, verify_double_commitment, DoubleCommitment};
pub use fhe_compute_circuit::{
    prove_fhe_compute, verify_fhe_compute, FheComputeProof, FheComputeProver, FheComputeState,
    FheComputeStepCircuit, FheComputeVerifier, FheOperation,
};
pub use fold::{fold_instances, verify_folded_instance, FoldedInstance, SumcheckProof};
pub use pk_aggregation::{
    prove_pk_aggregation, sigma_verify_step, verify_pk_aggregation, PkAggregationProof,
    PkAggregationProver, PkAggregationState, PkAggregationStepCircuit, PkAggregationVerifier,
};
pub use prover::{LatticeFoldAccumulator, LatticeFoldProver};
pub use range_proof::{algebraic_range_check, AlgebraicRangeProof};
pub use sumcheck::sumcheck_transform;
pub use verifier::{LatticeFoldVerifier, VerificationProof};
