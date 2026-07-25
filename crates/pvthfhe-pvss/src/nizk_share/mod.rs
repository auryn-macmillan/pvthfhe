//! R3.1 Share-encryption NIZK — Greco-primary binding proof.
//!
//! This module implements a Fiat-Shamir NIZK for share well-formedness.
//! The proof proves knowledge of (share_bytes, encryption_randomness) such that
//! the ciphertext in the statement is a valid BFV encryption of the share under
//! the recipient's public key.
//!
//! **D.1 GREEN**: BFV encryption sigma proof wired via `bfv_sigma` module.
//! V4 proofs include a self-contained BFV encryption relation proof.
//! V3 and earlier proofs fail-closed (rejected).

mod codec;
mod prove;
mod statement;
mod verify;

pub use prove::{build_bfv_encryption_proof, ShareNizkProver};
pub use statement::{
    canonical_bfv_params_digest, compute_ciphertext_v, compute_share_commitment,
    compute_share_commitment_tracked, ShareNizkBatchedStatement, ShareNizkOpenedProof,
    ShareNizkProof, ShareNizkStatement, ShareNizkTrackStatement, ShareNizkTrackType,
    ShareNizkWitness,
};
pub use verify::{
    verify_bfv_encryption_proof, verify_non_leaking_relation_boundary, ShareNizkBatchedVerifier,
    ShareNizkVerifier,
};

use pvthfhe_foundations::types::witness_language::{
    BfvParameters as SchemaBfvParams, R3Relation, WitnessStatement,
};

/// Locked domain separator for PVSS share-encryption proofs.
pub const SHARE_NIZK_DOMAIN_SEPARATOR: &str = "pvthfhe-pvss-share-encryption-v4";

// R3.0a — schema types wired for R3.1 GREEN migration
const _: () = {
    let _: Option<SchemaBfvParams> = None;
    let _: Option<R3Relation> = None;
    let _: Option<WitnessStatement> = None;
};

/// Canonical BFV parameters TOML used for parameter binding.
const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

const PROOF_VERSION: u16 = 4;
const WIRE_VERSION: u8 = 4;
const CHALLENGE_LEN: usize = 32;
const DIGEST_LEN: usize = 32;
const MAX_FIELD_LEN: usize = 16 << 20;
