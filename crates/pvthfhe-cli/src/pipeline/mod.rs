//! Full-pipeline driver, split by pipeline stage.
//!
//! Stage modules: [`dkg`] (keygen + DKG ceremony + PVSS share encryption),
//! [`prove`] (keygen NIZK prove/verify), [`encrypt`] (threshold setup +
//! encryption), [`fold`] (Cyclo folding), [`decrypt`] (threshold decrypt + C7
//! aggregation), [`compress`] (IVC compression), [`onchain`] (Noir
//! aggregator_final proving and the `C7Prover.toml` write site).
//! [`driver`] owns `run_full_pipeline`, which orchestrates the stages.
//!
//! The public surface is re-exported at the historical `crate::full_pipeline::*`
//! paths; this module is the implementation home.

pub(crate) mod compress;
pub(crate) mod decrypt;
pub(crate) mod dkg;
mod driver;
pub(crate) mod encrypt;
pub(crate) mod fold;
pub(crate) mod onchain;
pub(crate) mod prove;

use pvthfhe_bench::e2e_timings::E2eTimings;
use pvthfhe_fhe::FheBackend;
use sha2::{Digest, Sha256};
use std::time::Instant;

use ark_bn254::Fr;

pub use driver::run_full_pipeline;
pub use fold::build_fold_instances;
pub use onchain::{
    build_binary_merkle_tree, build_c7_prover_toml, build_c7_share_commitment_bundle,
    compute_combined_poly, compute_rlc_beta, compute_share_verification_hash,
    eval_c7_share_poly_noir, field_from_i64, prove_binary_merkle_paths,
};

/// Matches Noir circuit's MAX_PARTICIPANTS constant at
/// `circuits/aggregator_final/src/main.nr:15`.
pub(crate) const NOIR_MAX_PARTICIPANTS: usize = 128;

/// Matches Noir circuit's DEPTH (binary Merkle tree depth).
pub(crate) const DEPTH_BINARY: usize = 7; // 128 leaves = 7 Merkle path hops
/// Matches Noir circuit's N (polynomial coefficient count) for computation.
pub(crate) const N_COEFFS: usize = 8;
/// Noir circuit array size (ring_dim.nr: global N = 256). TOML output arrays are padded to this.
pub(crate) const CIRCUIT_N: usize = 256;

/// Creates an FHE backend from a TOML parameter string.
///
/// Returns the locked `FhersBackend` (BFV via gnosisguild/fhe.rs).
pub fn create_backend(params_toml: &str) -> anyhow::Result<Box<dyn FheBackend>> {
    use pvthfhe_fhe::fhers::FhersBackend;
    Ok(Box::new(FhersBackend::load_params(params_toml)?))
}

/// Pipeline track selector.
///
/// Track A: default Cyclo Ajtai commitment path.
/// Track B: AjtaiMatrix commitments with norm enforcement and native
///          ring-equation verification (default with `pipeline-extra-checks`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Track {
    /// Cyclo Ajtai commitment path.
    A,
    /// AjtaiMatrix commitments, norm enforcement, native ring-equation verification.
    B,
}

impl std::str::FromStr for Track {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "A" => Ok(Track::A),
            "B" => Ok(Track::B),
            _ => Err(format!("Invalid track: {s}. Use A or B")),
        }
    }
}

/// Full pipeline configuration.
#[derive(Debug, Clone, Copy)]
pub struct PipelineConfig {
    /// Number of parties.
    pub n: usize,
    /// Threshold.
    pub t: usize,
    /// Deterministic seed.
    pub seed: u64,
}

/// Full pipeline execution report.
#[derive(Debug, Clone)]
pub struct PipelineReport {
    /// Collected phase timings.
    pub timings: E2eTimings,
    /// Whether aggregate decrypt matched the original plaintext.
    pub plaintext_roundtrip_ok: bool,
    /// Whether all verification checks (NIZK, fold, compressor, decrypt NIZK) passed.
    /// Set to `true` only when `run_full_pipeline` completes without error — any
    /// verification failure propagates via `?` and prevents reaching this constructor.
    pub all_verifications_passed: bool,
    /// Aggregate public key hash.
    pub aggregate_pk_hash_hex: String,
    /// Ciphertext hash.
    pub ciphertext_hash_hex: String,
    /// Compressed proof digest.
    pub compressed_proof_digest_hex: String,
    /// Share coefficient vectors (per-party decrypt coefficients), for Noir C7 Prover.toml.
    pub share_coeffs: Vec<Vec<i64>>,
    /// Lagrange coefficients for threshold reconstruction, for Noir C7 Prover.toml.
    pub lagrange_coeffs: Vec<Fr>,
    /// Committee party IDs (1-based), for Noir C7 Prover.toml.
    pub committee_party_ids: Vec<u32>,
    /// Aggregate public key bytes, for Noir C7 Prover.toml.
    pub aggregate_pk_bytes: Vec<u8>,
    /// Session identifier, for Noir C7 Prover.toml.
    pub session_id: String,
    /// SHA-256 binding over all decrypt NIZK proof bytes, for Noir C7 Prover.toml.
    pub decrypt_nizk_hash: [u8; 32],
    /// G.4: Session nonce (Fr) used in d_commitment binding.
    /// Deterministically derived from session_id until Interfold E3 integration.
    pub session_nonce: Fr,
    /// Whether the d_commitment was verified end-to-end against the Noir circuit output.
    /// None = verification skipped (pending full G.4 Interfold registry integration).
    pub d_commitment_verified: Option<bool>,
    /// G.12: Per-party Schnorr signing public keys (G1Affine x-coordinate as Fr).
    pub party_signing_pks: Vec<Fr>,
    /// G.12: Per-party Schnorr signing public keys (G1Affine y-coordinate as Fr).
    pub party_signing_pkys: Vec<Fr>,
    /// G.12: Per-party Schnorr signature R-points (G1Affine x-coordinate as Fr).
    pub share_sig_rs: Vec<Fr>,
    /// G.12: Per-party Schnorr signature R-points (G1Affine y-coordinate as Fr).
    pub share_sig_rys: Vec<Fr>,
    pub ivc_snark_proof_hash: Option<[u8; 32]>,
    pub share_verification_hash: Option<[u8; 32]>,
    /// G.12: Per-party Schnorr signature s-values.
    pub share_sig_ss: Vec<Fr>,
    pub node_schnorr_pks: Vec<Fr>,
    pub node_schnorr_sigs: Vec<(Fr, Fr)>,
    /// G.12: Combined share hash over the per-share coefficient vectors.
    pub combined_share_hash: Fr,
    /// Hash-chain 1.1: Poseidon hash over all NIZK proof bytes.
    pub all_nizk_proof_hash: Fr,
    /// Hash-chain 1.2: SHA-256→Fr hash of the compressed proof digest.
    pub compressed_proof_hash: Fr,
    /// Per-party secret key commitments (Ajtai D2 hash of sk_i).
    /// Used to verify that NIZK proofs use the party's actual DKG secret key share.
    pub sk_commitments: Vec<[u8; 32]>,
    /// Per-party secret key bindings (SHA-256 over d_rns || participant_id || session_id).
    /// Computed from the proof-embedded d_rns and checked against the DKG registry.
    pub sk_bindings: Vec<[u8; 32]>,
    /// Whether the DKG ceremony (dealer→recipient PVSS) passed all verifications.
    pub dkg_verified: bool,
    /// Whether the dealer parity check (H·shares == 0) passed for all dealers.
    pub parity_verified: bool,
    /// Total number of shares processed in the DKG ceremony (n × n).
    pub dkg_share_count: usize,
    /// Per-recipient commitment fold hashes from the DKG ceremony.
    pub recipient_fold_hashes: Vec<Fr>,
    pub recipient_parity_proof_hashes: Vec<Fr>,
    /// Poseidon accumulator binding C0→C2→C4→C6 pipeline phases into a single
    /// hash. Computed as: acc = participant_set_hash, then for each phase:
    ///   acc = Poseidon(acc, phase_hash). Passed to aggregator_final as a
    /// public input to verify the cross-circuit DKG commitment chain.
    pub pipeline_integrity_hash: Fr,
    /// C5 aggregate public-key formation proof root (SHA-256).
    /// Populated from the keygen simulator's Round3Aggregate. Used as a verifier
    /// statement anchor to prove that `pk_agg = Σ pk_i` with per-participant PoP.
    pub c5_proof_root: [u8; 32],
}

/// Observer hooks for pipeline narration and metrics.
pub trait PipelineObserver {
    /// Called before a phase begins.
    fn phase_start(&mut self, _name: &str, _detail: Option<&str>) {}

    /// Called after a phase completes.
    fn phase_end(&mut self, _name: &str, _ms: f64) {}

    /// Called for extra notes.
    fn note(&mut self, _msg: &str) {}
}

pub(crate) fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub(crate) fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn track_a_from_str() {
        assert_eq!("A".parse::<Track>().unwrap(), Track::A);
    }

    #[test]
    fn track_b_from_str() {
        assert_eq!("B".parse::<Track>().unwrap(), Track::B);
    }

    #[test]
    fn track_invalid() {
        assert!("X".parse::<Track>().is_err());
    }

    #[test]
    fn track_a_lowercase() {
        assert_eq!("a".parse::<Track>().unwrap(), Track::A);
    }

    #[test]
    fn track_b_lowercase() {
        assert_eq!("b".parse::<Track>().unwrap(), Track::B);
    }

    #[test]
    fn track_empty_defaults_b() {
        let track: Track = "".parse().unwrap_or(Track::B);
        assert_eq!(track, Track::B);
    }
}
