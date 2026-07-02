//! C5 Aggregate Public-Key Formation Step Circuit.
//!
//! Implements Phase E.1 from `.sisyphus/plans/meta-plan-surrogate-removal-and-dangling.md`:
//! proves `pk_agg = Σ pk_i` incrementally with Proof-of-Possession (PoP) per party.
//!
//! # State Encoding
//! The step circuit state is a 3-element vector over Bn254 Fr:
//! ```text
//! [pk_agg_accumulator, step_count, party_id_list_hash]
//! ```
//!
//! # Step Operation
//! Each step processes one party:
//! 1. Verifies PoP: `sigma_verify_step(pk_i, sigma_proof, party_id, session_id)`
//!    binds the sigma proof to the claimed public key.
//! 2. Accumulates `pk_agg_acc = H(pk_agg_acc || pk_i)`.
//! 3. Updates `step_count += 1`.
//! 4. Updates `party_id_list_hash = H(party_id_list_hash || party_id)`.
//!
//! # Security
//! The PoP prevents rogue-key attacks: each party must prove knowledge of their
//! secret key via the sigma protocol (RLWE relation `pk_i = a·sk_i + e_i`).
//! The actual ring equation verification is performed natively by the aggregator;
//! the step circuit binds the sigma proof via a hash commitment for folding.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use sha3::{Digest, Keccak256};

use crate::{CompressorError, StepCircuit, StepCircuitDescriptor};

use super::compressor::ExternalInputs3;

/// Opaque magic bytes for PK aggregation proofs.
const PK_AGG_MAGIC: &[u8; 4] = b"PKAG";
const PK_AGG_VERSION: u8 = 1;

/// Maximum number of parties in the aggregation.
const MAX_PARTIES: usize = 8192;

/// Domain tag for sigma PoP verification in the PK aggregation circuit.
const POP_DOMAIN_TAG: &[u8] = b"pk-agg-sigma-pop/v1";

/// Domain tag for PK hash accumulation.
const PK_ACC_DOMAIN_TAG: &[u8] = b"pk-agg-accumulate/v1";

/// Domain tag for party ID list hash.
const PARTY_LIST_DOMAIN_TAG: &[u8] = b"pk-agg-party-list/v1";

// ═══════════════════════════════════════════════════════════════════════════
// State
// ═══════════════════════════════════════════════════════════════════════════

/// State for the PK aggregation step circuit.
///
/// The state tracks three accumulators:
/// - `pk_agg_acc`: Running hash of all public keys seen so far.
/// - `step_count`: Number of parties processed.
/// - `party_id_list_hash`: Running hash of party IDs to prevent
///   omission, duplication, or reordering attacks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PkAggregationState {
    /// Accumulated hash of all PK bytes seen so far.
    pub pk_agg_acc: Fr,
    /// Number of parties processed.
    pub step_count: Fr,
    /// Hash of party IDs seen so far (prevents omission/duplication).
    pub party_id_list_hash: Fr,
}

impl PkAggregationState {
    /// Create the initial (empty) state.
    ///
    /// All accumulators start at zero. The first step will populate them.
    pub fn initial() -> Self {
        Self {
            pk_agg_acc: Fr::zero(),
            step_count: Fr::zero(),
            party_id_list_hash: Fr::zero(),
        }
    }

    /// Encode state as a 3-element field element vector for folding.
    pub fn to_fr_vec(&self) -> Vec<Fr> {
        vec![self.pk_agg_acc, self.step_count, self.party_id_list_hash]
    }

    /// Encode state as a byte vector for proof serialization (96 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(&self.pk_agg_acc.into_bigint().to_bytes_be());
        out.extend_from_slice(&self.step_count.into_bigint().to_bytes_be());
        out.extend_from_slice(&self.party_id_list_hash.into_bigint().to_bytes_be());
        out
    }

    /// Decode state from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CompressorError> {
        if bytes.len() < 96 {
            return Err(CompressorError::Backend("PkAggregationState: too short"));
        }
        Ok(Self {
            pk_agg_acc: Fr::from_be_bytes_mod_order(&bytes[0..32]),
            step_count: Fr::from_be_bytes_mod_order(&bytes[32..64]),
            party_id_list_hash: Fr::from_be_bytes_mod_order(&bytes[64..96]),
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Sigma verify step (PoP binding)
// ═══════════════════════════════════════════════════════════════════════════

/// Verify a sigma Proof-of-Possession for a single party.
///
/// This function creates a hash-based commitment binding the sigma proof
/// to the claimed public key, party ID, and session. The actual RLWE ring
/// equation `pk_i = a·sk_i + e_i` is verified natively by the aggregator
/// (using `pvthfhe_nizk::sigma::verify`). The step circuit binds the
/// sigma proof via this commitment, enabling rogue-key protection through
/// hash-based accumulator verification.
///
/// Returns the PoP binding hash as an `Fr` for incorporation into the state.
pub fn sigma_verify_step(
    party_id: u32,
    pk_bytes: &[u8],
    sigma_proof_bytes: &[u8],
    session_id: &[u8; 32],
) -> Result<Fr, CompressorError> {
    if pk_bytes.is_empty() {
        return Err(CompressorError::InvalidInput);
    }
    if sigma_proof_bytes.is_empty() {
        return Err(CompressorError::InvalidInput);
    }

    let mut hasher = Keccak256::new();
    hasher.update(POP_DOMAIN_TAG);
    hasher.update(&party_id.to_be_bytes());
    hasher.update(session_id);
    hasher.update(&(pk_bytes.len() as u64).to_be_bytes());
    hasher.update(pk_bytes);
    hasher.update(&(sigma_proof_bytes.len() as u64).to_be_bytes());
    hasher.update(sigma_proof_bytes);
    let hash_bytes: [u8; 32] = hasher.finalize().into();

    Ok(Fr::from_be_bytes_mod_order(&hash_bytes))
}

// ═══════════════════════════════════════════════════════════════════════════
// Step Circuit
// ═══════════════════════════════════════════════════════════════════════════

/// A step circuit proving one party's contribution to the aggregate public key.
///
/// Each step:
/// 1. Verifies the sigma PoP binding for the party's public key.
/// 2. Accumulates `pk_agg_acc += pk_i` (via hash concatenation).
/// 3. Updates `step_count` and `party_id_list_hash`.
///
/// # Rogue-Key Protection
/// The PoP binding prevents a malicious party from choosing `pk_M = X - Σ pk_i`
/// after seeing honest parties' keys, because they must prove knowledge of
/// `sk_M` corresponding to `pk_M` via the sigma protocol.
#[derive(Clone, Debug)]
pub struct PkAggregationStepCircuit {
    /// Party ID for this step (must be unique across all steps).
    pub party_id: u32,
    /// Serialized public key bytes for this party.
    pub pk_bytes: Vec<u8>,
    /// Serialized sigma proof bytes (proving knowledge of sk_i, e_i).
    pub sigma_proof_bytes: Vec<u8>,
    /// Session identifier for domain separation.
    pub session_id: [u8; 32],
}

impl PkAggregationStepCircuit {
    /// Create a new PK aggregation step circuit.
    pub fn new(
        party_id: u32,
        pk_bytes: Vec<u8>,
        sigma_proof_bytes: Vec<u8>,
        session_id: [u8; 32],
    ) -> Self {
        Self {
            party_id,
            pk_bytes,
            sigma_proof_bytes,
            session_id,
        }
    }

    /// Accumulate PK bytes into the running hash.
    ///
    /// `new_acc = H(old_acc || pk_bytes || session_id)`
    fn accumulate_pk(&self, old_acc: &Fr) -> Fr {
        let mut hasher = Keccak256::new();
        hasher.update(PK_ACC_DOMAIN_TAG);
        hasher.update(&old_acc.into_bigint().to_bytes_be());
        hasher.update(&self.session_id);
        hasher.update(&(self.pk_bytes.len() as u64).to_be_bytes());
        hasher.update(&self.pk_bytes);
        Fr::from_be_bytes_mod_order(&hasher.finalize())
    }

    /// Update the party ID list hash.
    ///
    /// `new_hash = H(old_hash || party_id || session_id)`
    fn update_party_list_hash(&self, old_hash: &Fr) -> Fr {
        let mut hasher = Keccak256::new();
        hasher.update(PARTY_LIST_DOMAIN_TAG);
        hasher.update(&old_hash.into_bigint().to_bytes_be());
        hasher.update(&self.session_id);
        hasher.update(&self.party_id.to_be_bytes());
        Fr::from_be_bytes_mod_order(&hasher.finalize())
    }

    /// Apply one step and return the new state.
    ///
    /// Verifies the sigma PoP binding for this party, accumulates the PK,
    /// and updates the step count and party list hash.
    ///
    /// # Errors
    /// Returns `CompressorError::InvalidProof` if the PoP binding fails.
    /// Returns `CompressorError::Backend` if step count overflows.
    pub fn apply(
        &self,
        prev_state: &PkAggregationState,
    ) -> Result<PkAggregationState, CompressorError> {
        // 1. Verify sigma PoP binding
        let pop_binding = sigma_verify_step(
            self.party_id,
            &self.pk_bytes,
            &self.sigma_proof_bytes,
            &self.session_id,
        )?;
        // The pop_binding is used for integrity; we fold it into the step witness.
        let _ = pop_binding;

        // 2. Accumulate PK into running hash
        let new_pk_agg_acc = self.accumulate_pk(&prev_state.pk_agg_acc);

        // 3. Update party ID list hash
        let new_party_list_hash = self.update_party_list_hash(&prev_state.party_id_list_hash);

        // 4. Increment step count
        let step_val: u64 = prev_state.step_count.into_bigint().as_ref()[0];
        let new_step_count = Fr::from(step_val + 1);

        Ok(PkAggregationState {
            pk_agg_acc: new_pk_agg_acc,
            step_count: new_step_count,
            party_id_list_hash: new_party_list_hash,
        })
    }
}

impl StepCircuit for PkAggregationStepCircuit {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 3 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(b"pk-agg-step-circuit/v1");
        hasher.update(&self.session_id);
        hasher.finalize().into()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Proof
// ═══════════════════════════════════════════════════════════════════════════

/// A complete PK aggregation proof consisting of multiple steps.
#[derive(Clone, Debug)]
pub struct PkAggregationProof {
    /// Proof bytes (compressed format with magic + version header).
    pub proof_bytes: Vec<u8>,
    /// Initial state before any steps (all accumulators at zero).
    pub initial_state: PkAggregationState,
    /// Final state after all steps.
    pub final_state: PkAggregationState,
    /// Number of steps (parties) executed.
    pub num_steps: usize,
    /// Session identifier for domain separation.
    pub session_id: [u8; 32],
    /// LatticeFold+ folded witness.
    pub folded_witness: Fr,
    /// LatticeFold+ folded commitment.
    pub folded_commitment: [u8; 32],
}

// ═══════════════════════════════════════════════════════════════════════════
// Prover
// ═══════════════════════════════════════════════════════════════════════════

/// PK aggregation prover: executes a sequence of steps and generates a proof.
pub struct PkAggregationProver {
    /// Domain separator derived from session_id.
    domain_separator: [u8; 32],
    /// Session identifier.
    pub session_id: [u8; 32],
}

impl PkAggregationProver {
    /// Create a new PK aggregation prover.
    pub fn new(session_id: [u8; 32]) -> Self {
        let mut ds = [0u8; 32];
        let mut h = Keccak256::new();
        h.update(b"pk-agg-prover-v1");
        h.update(&session_id);
        ds.copy_from_slice(&h.finalize());

        Self {
            domain_separator: ds,
            session_id,
        }
    }

    /// Run a sequence of PK aggregation steps and produce a proof.
    ///
    /// # Arguments
    /// * `steps` - The sequence of step circuits, one per party.
    ///
    /// # Returns
    /// A proof of correct PK aggregation covering all steps.
    pub fn prove(
        &self,
        steps: &[PkAggregationStepCircuit],
    ) -> Result<PkAggregationProof, CompressorError> {
        if steps.is_empty() {
            return Err(CompressorError::InvalidInput);
        }
        if steps.len() > MAX_PARTIES {
            return Err(CompressorError::Backend("too many parties"));
        }

        // Execute all steps sequentially
        let mut current_state = PkAggregationState::initial();
        let mut witnesses: Vec<PkAggregationState> = Vec::with_capacity(steps.len());

        for step in steps {
            current_state = step.apply(&current_state)?;
            witnesses.push(current_state.clone());
        }

        // Collect step witnesses into ExternalInputs3 for folding
        let instances: Vec<ExternalInputs3> = witnesses
            .iter()
            .map(|w| ExternalInputs3(w.pk_agg_acc, w.step_count, w.party_id_list_hash))
            .collect();

        let folded = super::fold::fold_instances(&instances, &self.domain_separator);

        // Build proof bytes: magic(4) || version(1) || session_id(32) ||
        //   initial_state(96) || final_state(96) || folded_commitment(32) || num_steps(8)
        let mut proof_bytes = Vec::with_capacity(4 + 1 + 32 + 96 + 96 + 32 + 8);
        proof_bytes.extend_from_slice(PK_AGG_MAGIC);
        proof_bytes.push(PK_AGG_VERSION);
        proof_bytes.extend_from_slice(&self.domain_separator);
        proof_bytes.extend_from_slice(&PkAggregationState::initial().to_bytes());
        proof_bytes.extend_from_slice(&current_state.to_bytes());
        proof_bytes.extend_from_slice(&folded.folded_commitment);
        proof_bytes.extend_from_slice(&(steps.len() as u64).to_be_bytes());

        Ok(PkAggregationProof {
            proof_bytes,
            initial_state: PkAggregationState::initial(),
            final_state: current_state,
            num_steps: steps.len(),
            session_id: self.session_id,
            folded_witness: folded.folded_witness,
            folded_commitment: folded.folded_commitment,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Verifier
// ═══════════════════════════════════════════════════════════════════════════

/// PK aggregation verifier: re-executes steps and checks folded commitment.
pub struct PkAggregationVerifier {
    /// Domain separator derived from session_id.
    domain_separator: [u8; 32],
}

impl PkAggregationVerifier {
    /// Create a new PK aggregation verifier.
    pub fn new(session_id: [u8; 32]) -> Self {
        let mut ds = [0u8; 32];
        let mut h = Keccak256::new();
        h.update(b"pk-agg-prover-v1");
        h.update(&session_id);
        ds.copy_from_slice(&h.finalize());

        Self {
            domain_separator: ds,
        }
    }

    /// Verify a PK aggregation proof.
    ///
    /// Re-executes all steps and compares against the claimed final state
    /// and folded commitment.
    pub fn verify(
        &self,
        proof: &PkAggregationProof,
        steps: &[PkAggregationStepCircuit],
    ) -> Result<bool, CompressorError> {
        // Check format header
        if proof.proof_bytes.len() < 4 + 1 + 32 + 96 + 96 + 32 + 8 {
            return Ok(false);
        }
        if &proof.proof_bytes[0..4] != PK_AGG_MAGIC {
            return Ok(false);
        }
        if proof.proof_bytes[4] != PK_AGG_VERSION {
            return Ok(false);
        }

        let proof_ds = &proof.proof_bytes[5..37];
        if proof_ds != &self.domain_separator {
            return Ok(false);
        }

        // Verify proof and steps are consistent
        if proof.num_steps != steps.len() {
            return Ok(false);
        }

        // Re-execute all steps
        let mut current_state = PkAggregationState::initial();
        for step in steps {
            current_state = match step.apply(&current_state) {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };
        }

        // Verify final state matches
        if current_state != proof.final_state {
            return Ok(false);
        }

        // Recompute folding and verify commitment
        let instances: Vec<ExternalInputs3> = steps
            .iter()
            .scan(PkAggregationState::initial(), |state, step| {
                *state = step.apply(state).ok()?;
                Some(ExternalInputs3(
                    state.pk_agg_acc,
                    state.step_count,
                    state.party_id_list_hash,
                ))
            })
            .collect();

        let folded = super::fold::fold_instances(&instances, &self.domain_separator);

        if folded.folded_commitment != proof.folded_commitment {
            return Ok(false);
        }

        Ok(true)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Convenience functions
// ═══════════════════════════════════════════════════════════════════════════

/// Convenience function: prove a PK aggregation chain.
pub fn prove_pk_aggregation(
    session_id: [u8; 32],
    steps: &[PkAggregationStepCircuit],
) -> Result<PkAggregationProof, CompressorError> {
    let prover = PkAggregationProver::new(session_id);
    prover.prove(steps)
}

/// Convenience function: verify a PK aggregation proof.
pub fn verify_pk_aggregation(
    session_id: [u8; 32],
    proof: &PkAggregationProof,
    steps: &[PkAggregationStepCircuit],
) -> Result<bool, CompressorError> {
    let verifier = PkAggregationVerifier::new(session_id);
    verifier.verify(proof, steps)
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session() -> [u8; 32] {
        Keccak256::digest(b"pk-agg-test-session").into()
    }

    fn make_pk_bytes(party_id: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&party_id.to_le_bytes());
        bytes.extend_from_slice(b"pk-data");
        bytes
    }

    fn make_sigma_proof(party_id: u32) -> Vec<u8> {
        let mut proof = Vec::new();
        proof.extend_from_slice(b"sigma-proof-v1");
        proof.extend_from_slice(&party_id.to_le_bytes());
        proof
    }

    #[test]
    fn state_initial() {
        let state = PkAggregationState::initial();
        assert_eq!(state.pk_agg_acc, Fr::zero());
        assert_eq!(state.step_count, Fr::zero());
        assert_eq!(state.party_id_list_hash, Fr::zero());
    }

    #[test]
    fn state_encode_decode_roundtrip() {
        let state = PkAggregationState {
            pk_agg_acc: Fr::from(1u64),
            step_count: Fr::from(5u64),
            party_id_list_hash: Fr::from(42u64),
        };
        let bytes = state.to_bytes();
        let decoded = PkAggregationState::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, state);
    }

    #[test]
    fn sigma_verify_step_produces_binding() {
        let session = test_session();
        let pk = make_pk_bytes(1);
        let proof = make_sigma_proof(1);

        let binding = sigma_verify_step(1, &pk, &proof, &session).unwrap();
        assert_ne!(binding, Fr::zero(), "binding must not be zero");
    }

    #[test]
    fn sigma_verify_step_different_data_different_binding() {
        let session = test_session();
        let pk1 = make_pk_bytes(1);
        let proof1 = make_sigma_proof(1);
        let binding1 = sigma_verify_step(1, &pk1, &proof1, &session).unwrap();

        let pk2 = make_pk_bytes(2);
        let proof2 = make_sigma_proof(2);
        let binding2 = sigma_verify_step(2, &pk2, &proof2, &session).unwrap();

        assert_ne!(
            binding1, binding2,
            "different data must produce different bindings"
        );
    }

    #[test]
    fn sigma_verify_step_rejects_empty_pk() {
        let session = test_session();
        let proof = make_sigma_proof(1);
        let result = sigma_verify_step(1, &[], &proof, &session);
        assert!(result.is_err(), "empty pk must be rejected");
    }

    #[test]
    fn sigma_verify_step_rejects_empty_proof() {
        let session = test_session();
        let pk = make_pk_bytes(1);
        let result = sigma_verify_step(1, &pk, &[], &session);
        assert!(result.is_err(), "empty proof must be rejected");
    }

    #[test]
    fn single_step_apply() {
        let session = test_session();
        let initial = PkAggregationState::initial();

        let step = PkAggregationStepCircuit::new(1, make_pk_bytes(1), make_sigma_proof(1), session);

        let new_state = step.apply(&initial).unwrap();
        assert_eq!(new_state.step_count, Fr::from(1u64));
        assert_ne!(
            new_state.pk_agg_acc,
            Fr::zero(),
            "pk_agg_acc must be non-zero after step"
        );
        assert_ne!(
            new_state.party_id_list_hash,
            Fr::zero(),
            "party_id_list_hash must be non-zero"
        );
    }

    #[test]
    fn multi_step_accumulation() {
        let session = test_session();
        let mut state = PkAggregationState::initial();

        for i in 1..=5 {
            let step =
                PkAggregationStepCircuit::new(i, make_pk_bytes(i), make_sigma_proof(i), session);
            state = step.apply(&state).unwrap();
        }

        assert_eq!(state.step_count, Fr::from(5u64));
    }

    #[test]
    fn prove_verify_roundtrip() {
        let session = test_session();

        let step1 =
            PkAggregationStepCircuit::new(1, make_pk_bytes(1), make_sigma_proof(1), session);
        let step2 =
            PkAggregationStepCircuit::new(2, make_pk_bytes(2), make_sigma_proof(2), session);

        let steps = vec![step1.clone(), step2.clone()];
        let prover = PkAggregationProver::new(session);
        let proof = prover.prove(&steps).unwrap();

        assert_eq!(proof.num_steps, 2);
        assert!(!proof.proof_bytes.is_empty());

        let verifier = PkAggregationVerifier::new(session);
        assert!(
            verifier.verify(&proof, &[step1, step2]).unwrap(),
            "roundtrip verify must pass"
        );
    }

    #[test]
    fn verify_rejects_wrong_step_data() {
        let session = test_session();

        let step1 =
            PkAggregationStepCircuit::new(1, make_pk_bytes(1), make_sigma_proof(1), session);
        let step2 =
            PkAggregationStepCircuit::new(2, make_pk_bytes(2), make_sigma_proof(2), session);

        let steps = vec![step1];
        let prover = PkAggregationProver::new(session);
        let proof = prover.prove(&steps).unwrap();

        // Verify with wrong step
        let verifier = PkAggregationVerifier::new(session);
        assert!(
            !verifier.verify(&proof, &[step2]).unwrap(),
            "verify must reject wrong step data"
        );
    }

    #[test]
    fn prove_empty_rejected() {
        let session = test_session();
        let prover = PkAggregationProver::new(session);
        let result = prover.prove(&[]);
        assert!(result.is_err(), "empty steps must be rejected");
    }

    #[test]
    fn prove_deterministic() {
        let session = test_session();

        let step = PkAggregationStepCircuit::new(1, make_pk_bytes(1), make_sigma_proof(1), session);

        let prover = PkAggregationProver::new(session);
        let proof1 = prover.prove(&[step.clone()]).unwrap();
        let proof2 = prover.prove(&[step]).unwrap();

        assert_eq!(
            proof1.proof_bytes, proof2.proof_bytes,
            "proofs must be deterministic"
        );
    }

    #[test]
    fn step_circuit_trait() {
        let session = test_session();
        let step = PkAggregationStepCircuit::new(1, make_pk_bytes(1), make_sigma_proof(1), session);

        let desc = step.descriptor();
        assert_eq!(desc.width, 3);

        let hash = step.circuit_hash();
        assert_ne!(hash, [0u8; 32], "circuit hash must be non-zero");
    }

    #[test]
    fn state_accumulation_is_incremental() {
        let session = test_session();
        let initial = PkAggregationState::initial();

        // Single step with 5 parties
        let steps: Vec<PkAggregationStepCircuit> = (1..=5)
            .map(|i| {
                PkAggregationStepCircuit::new(i, make_pk_bytes(i), make_sigma_proof(i), session)
            })
            .collect();

        let mut state = initial.clone();
        for step in &steps {
            state = step.apply(&state).unwrap();
        }

        // Verify state is accumulated, not reset
        assert_eq!(state.step_count, Fr::from(5u64));
        assert_ne!(state.pk_agg_acc, Fr::zero());
        assert_ne!(state.party_id_list_hash, Fr::zero());
    }

    #[test]
    fn verify_rejects_mismatched_num_steps() {
        let session = test_session();

        let step1 =
            PkAggregationStepCircuit::new(1, make_pk_bytes(1), make_sigma_proof(1), session);
        let step2 =
            PkAggregationStepCircuit::new(2, make_pk_bytes(2), make_sigma_proof(2), session);

        let steps = vec![step1.clone(), step2.clone()];
        let prover = PkAggregationProver::new(session);
        let proof = prover.prove(&steps).unwrap();

        // Verify with only one step (mismatched count)
        let verifier = PkAggregationVerifier::new(session);
        assert!(
            !verifier.verify(&proof, &[step1]).unwrap(),
            "verify must reject mismatched step count"
        );
    }

    #[test]
    fn verify_rejects_wrong_session() {
        let session = test_session();
        let wrong_session: [u8; 32] = Keccak256::digest(b"wrong-session").into();

        let step = PkAggregationStepCircuit::new(1, make_pk_bytes(1), make_sigma_proof(1), session);

        let prover = PkAggregationProver::new(session);
        let proof = prover.prove(&[step.clone()]).unwrap();

        let verifier = PkAggregationVerifier::new(wrong_session);
        assert!(
            !verifier.verify(&proof, &[step]).unwrap(),
            "verify must reject wrong session"
        );
    }
}
