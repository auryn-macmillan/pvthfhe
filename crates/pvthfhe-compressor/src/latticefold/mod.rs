//! LatticeFold+ — Lattice-native folding protocol.
//!
//! Implements the LatticeFold+ folding scheme from ePrint 2025/247:
//! - §4.3 Monomial set check: algebraic range proof without bit decomposition.
//! - §4.1 Double commitments: commitments of commitments for shorter proofs.
//! - §5 Folding: fold n instances into one using random β.
//! - §5.2 Sumcheck transformation: fold double commitments via sumcheck.
//!
//! This module is gated behind `#[cfg(feature = "enable-latticefold")]`.

pub mod compressor;
pub mod fold;
pub mod range_proof;

pub use compressor::LatticeFoldCompressor;
pub use fold::{double_commit, fold_instances, verify_double_commitment, verify_folded_instance};
pub use range_proof::{algebraic_range_check, AlgebraicRangeProof};
