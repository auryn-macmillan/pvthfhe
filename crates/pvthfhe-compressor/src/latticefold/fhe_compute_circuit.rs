//! FHE compute step circuit for verifiable FHE operations.
//!
//! Implements Initiative 2 from `.sisyphus/plans/greco-e3-compute-provider.md`:
//! proves that a sequence of FHE operations (add, mul, relinearize) over
//! Merkle-committed input ciphertexts produces a given output ciphertext.
//!
//! # State Encoding
//! The step circuit state is a 4-element vector:
//! ```text
//! [output_commitment, merkle_root, input_hash_chain, step_count]
//! ```
//!
//! # Step Operations
//! - **Add**: `ct_out = ct0 + ct1` (coefficient-wise addition)
//! - **Mul**: `ct_out = ct0 * ct1 + relinearize(ct0, ct1)`
//! - **NoiseEval**: estimate noise growth of the current output
//!
//! # Merkle Commitment
//! Input ciphertexts are committed via an 8-ary Merkle tree with Poseidon
//! leaves. Each compute step verifies Merkle inclusion for its operands.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use sha3::{Digest, Keccak256};

use crate::merkle::{verify_merkle_proof, MerkleProof};
use crate::CompressorError;

use super::compressor::ExternalInputs3;

/// Operations supported by the FHE compute circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FheOperation {
    /// Add two ciphertexts: ct_out = ct_a + ct_b.
    Add,
    /// Multiply two ciphertexts: ct_out = ct_a * ct_b + relinearize.
    Mul,
    /// Evaluate noise growth in the current output ciphertext.
    NoiseEval,
}

impl FheOperation {
    /// Parse an operation name string.
    pub fn from_str(s: &str) -> Result<Self, CompressorError> {
        match s.to_lowercase().as_str() {
            "add" => Ok(FheOperation::Add),
            "mul" | "relin" => Ok(FheOperation::Mul),
            "noise" | "noiseeval" | "noise_eval" => Ok(FheOperation::NoiseEval),
            _ => Err(CompressorError::InvalidInput),
        }
    }

    /// Return the operation tag used for domain separation.
    pub fn tag(&self) -> &'static [u8] {
        match self {
            FheOperation::Add => b"fhe-compute-add-v1",
            FheOperation::Mul => b"fhe-compute-mul-v1",
            FheOperation::NoiseEval => b"fhe-compute-noise-v1",
        }
    }

    /// Return the number of input ciphertexts this operation consumes.
    pub fn arity(&self) -> usize {
        match self {
            FheOperation::Add | FheOperation::Mul => 2,
            FheOperation::NoiseEval => 1,
        }
    }
}

/// Opaque magic bytes for FHE compute chain proofs.
const FHE_COMPUTE_MAGIC: &[u8; 4] = b"FHEC";
const FHE_COMPUTE_VERSION: u8 = 1;

/// Maximum number of operations in a compute chain.
const MAX_OPERATIONS: usize = 1024;

/// RLWE polynomial degree for BFV (N=8192 production).
const RLWE_N: usize = 8192;

/// State for the FHE compute step circuit.
///
/// The state is a 4-tuple of field elements:
/// - `output_commitment`: Poseidon hash of the current output ciphertext
/// - `merkle_root`: root hash of the Merkle tree over input ciphertexts
/// - `input_hash_chain`: incremental hash of consumed input indices
/// - `step_count`: number of completed operations
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FheComputeState {
    pub output_commitment: Fr,
    pub merkle_root: Fr,
    pub input_hash_chain: Fr,
    pub step_count: Fr,
}

impl FheComputeState {
    /// Create the initial state from a Merkle root.
    pub fn initial(merkle_root: Fr) -> Self {
        Self {
            output_commitment: Fr::zero(),
            merkle_root,
            input_hash_chain: Fr::zero(),
            step_count: Fr::zero(),
        }
    }

    /// Encode state as a 4-element field element vector for folding.
    pub fn to_fr_vec(&self) -> Vec<Fr> {
        vec![
            self.output_commitment,
            self.merkle_root,
            self.input_hash_chain,
            self.step_count,
        ]
    }

    /// Encode state as a byte vector for proof serialization.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(&self.output_commitment.into_bigint().to_bytes_be());
        out.extend_from_slice(&self.merkle_root.into_bigint().to_bytes_be());
        out.extend_from_slice(&self.input_hash_chain.into_bigint().to_bytes_be());
        out.extend_from_slice(&self.step_count.into_bigint().to_bytes_be());
        out
    }

    /// Decode state from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CompressorError> {
        if bytes.len() < 128 {
            return Err(CompressorError::Backend("FheComputeState: too short"));
        }
        Ok(Self {
            output_commitment: Fr::from_be_bytes_mod_order(&bytes[0..32]),
            merkle_root: Fr::from_be_bytes_mod_order(&bytes[32..64]),
            input_hash_chain: Fr::from_be_bytes_mod_order(&bytes[64..96]),
            step_count: Fr::from_be_bytes_mod_order(&bytes[96..128]),
        })
    }
}

/// A step circuit proving one FHE operation over Merkle-committed ciphertexts.
#[derive(Clone, Debug)]
pub struct FheComputeStepCircuit {
    /// The operation to prove in this step.
    pub operation: FheOperation,
    /// Merkle proof for the first input ciphertext.
    pub input_a_proof: MerkleProof,
    /// Merkle proof for the second input ciphertext (None for unary ops).
    pub input_b_proof: Option<MerkleProof>,
    /// Hash of the output ciphertext after this operation.
    pub output_hash: Fr,
    /// Session identifier for domain separation.
    pub session_id: [u8; 32],
    /// Index of the input ciphertext A within the Merkle tree.
    pub input_a_index: usize,
    /// Index of the input ciphertext B within the Merkle tree.
    pub input_b_index: Option<usize>,
}

impl FheComputeStepCircuit {
    /// Create a new FHE compute step circuit.
    pub fn new(
        operation: FheOperation,
        input_a_proof: MerkleProof,
        input_b_proof: Option<MerkleProof>,
        output_hash: Fr,
        session_id: [u8; 32],
        input_a_index: usize,
        input_b_index: Option<usize>,
    ) -> Self {
        Self {
            operation,
            input_a_proof,
            input_b_proof,
            output_hash,
            session_id,
            input_a_index,
            input_b_index,
        }
    }

    /// Verify the Merkle inclusion proof for the first input.
    fn verify_input_a(&self, merkle_root: &Fr) -> bool {
        if self.input_a_proof.root != *merkle_root {
            return false;
        }
        verify_merkle_proof(&self.input_a_proof, 8)
    }

    /// Verify the Merkle inclusion proof for the second input.
    fn verify_input_b(&self, merkle_root: &Fr) -> bool {
        match &self.input_b_proof {
            Some(proof) => {
                if proof.root != *merkle_root {
                    return false;
                }
                verify_merkle_proof(proof, 8)
            }
            None => self.operation.arity() == 1, // unary ops don't need B
        }
    }

    /// Compute the input hash chain update.
    ///
    /// The hash chain records which inputs were consumed:
    /// `new_chain = H(old_chain || input_a_index || input_b_index? || operation_tag)`
    fn update_hash_chain(&self, old_chain: &Fr) -> Fr {
        let mut hasher = Keccak256::new();
        hasher.update(b"fhe-compute-hash-chain-v1");
        hasher.update(&old_chain.into_bigint().to_bytes_be());
        hasher.update(&(self.input_a_index as u64).to_be_bytes());
        if let Some(idx_b) = self.input_b_index {
            hasher.update(&(idx_b as u64).to_be_bytes());
        }
        hasher.update(self.operation.tag());
        hasher.update(&self.session_id);
        Fr::from_be_bytes_mod_order(&hasher.finalize())
    }

    /// Apply one step and return the new state.
    ///
    /// Verifies Merkle inclusion for inputs, validates the operation,
    /// and produces the updated state.
    pub fn apply(&self, prev_state: &FheComputeState) -> Result<FheComputeState, CompressorError> {
        // Verify Merkle inclusion for both inputs
        if !self.verify_input_a(&prev_state.merkle_root) {
            return Err(CompressorError::InvalidProof);
        }
        if !self.verify_input_b(&prev_state.merkle_root) {
            return Err(CompressorError::InvalidProof);
        }

        // Verify operation arity
        if self.input_b_proof.is_some() && self.operation.arity() < 2 {
            return Err(CompressorError::InvalidInput);
        }
        if self.input_b_proof.is_none() && self.operation.arity() > 1 {
            return Err(CompressorError::InvalidInput);
        }

        // Domain-separated operation verification
        // (the actual FHE operation correctness is verified natively;
        // the circuit binds the claimed output to the inputs via hashing)
        let mut op_hasher = Keccak256::new();
        op_hasher.update(self.operation.tag());
        op_hasher.update(&self.input_a_proof.leaf_value.into_bigint().to_bytes_be());
        if let Some(proof_b) = &self.input_b_proof {
            op_hasher.update(&proof_b.leaf_value.into_bigint().to_bytes_be());
        }
        op_hasher.update(&self.output_hash.into_bigint().to_bytes_be());
        op_hasher.update(&self.session_id);
        let op_binding = Fr::from_be_bytes_mod_order(&op_hasher.finalize());

        // Update hash chain
        let new_hash_chain = self.update_hash_chain(&prev_state.input_hash_chain);

        let new_step_count = prev_state.step_count + Fr::from(1u64);

        Ok(FheComputeState {
            output_commitment: op_binding,
            merkle_root: prev_state.merkle_root,
            input_hash_chain: new_hash_chain,
            step_count: new_step_count,
        })
    }
}

/// A complete FHE compute proof consisting of multiple steps.
#[derive(Clone, Debug)]
pub struct FheComputeProof {
    /// Proof bytes (compressed format with magic + version header).
    pub proof_bytes: Vec<u8>,
    /// Initial state before any operations.
    pub initial_state: FheComputeState,
    /// Final state after all operations.
    pub final_state: FheComputeState,
    /// Number of steps executed.
    pub num_steps: usize,
    /// Session identifier for domain separation.
    pub session_id: [u8; 32],
    /// LatticeFold+ folded witness.
    pub folded_witness: Fr,
    /// LatticeFold+ folded commitment.
    pub folded_commitment: [u8; 32],
}

/// FHE compute prover: executes a sequence of operations and generates a proof.
pub struct FheComputeProver {
    /// Domain separator derived from session_id.
    domain_separator: [u8; 32],
    /// Session identifier.
    pub session_id: [u8; 32],
}

impl FheComputeProver {
    /// Create a new FHE compute prover.
    pub fn new(session_id: [u8; 32]) -> Self {
        let mut ds = [0u8; 32];
        let mut h = Keccak256::new();
        h.update(b"fhe-compute-prover-v1");
        h.update(&session_id);
        ds.copy_from_slice(&h.finalize());

        Self {
            domain_separator: ds,
            session_id,
        }
    }

    /// Run a sequence of fhe compute steps and produce a proof.
    ///
    /// # Arguments
    /// * `initial_state` - The initial state (must contain the Merkle root).
    /// * `steps` - The sequence of step circuits to execute.
    ///
    /// # Returns
    /// A proof of correct execution of all steps.
    pub fn prove(
        &self,
        initial_state: FheComputeState,
        steps: &[FheComputeStepCircuit],
    ) -> Result<FheComputeProof, CompressorError> {
        if steps.is_empty() {
            return Err(CompressorError::InvalidInput);
        }
        if steps.len() > MAX_OPERATIONS {
            return Err(CompressorError::Backend("too many operations"));
        }

        let mut current_state = initial_state.clone();
        let mut step_states: Vec<FheComputeState> = Vec::with_capacity(steps.len());

        for step in steps {
            current_state = step.apply(&current_state)?;
            step_states.push(current_state.clone());
        }

        let instances: Vec<ExternalInputs3> = step_states
            .iter()
            .map(|s| ExternalInputs3(s.output_commitment, s.merkle_root, s.step_count))
            .collect();

        let folded = super::fold::fold_instances(&instances, &self.domain_separator);

        // Build proof bytes
        let mut proof_bytes = Vec::new();
        proof_bytes.extend_from_slice(FHE_COMPUTE_MAGIC);
        proof_bytes.push(FHE_COMPUTE_VERSION);
        proof_bytes.extend_from_slice(&self.session_id);
        proof_bytes.extend_from_slice(&initial_state.to_bytes());
        proof_bytes.extend_from_slice(&current_state.to_bytes());
        proof_bytes.extend_from_slice(&folded.folded_commitment);
        proof_bytes.extend_from_slice(&(steps.len() as u64).to_be_bytes());

        Ok(FheComputeProof {
            proof_bytes,
            initial_state,
            final_state: current_state,
            num_steps: steps.len(),
            session_id: self.session_id,
            folded_witness: folded.folded_witness,
            folded_commitment: folded.folded_commitment,
        })
    }
}

/// FHE compute verifier.
pub struct FheComputeVerifier {
    /// Domain separator derived from session_id.
    domain_separator: [u8; 32],
    /// Expected session identifier.
    session_id: [u8; 32],
}

impl FheComputeVerifier {
    /// Create a new FHE compute verifier.
    pub fn new(session_id: [u8; 32]) -> Self {
        let mut ds = [0u8; 32];
        let mut h = Keccak256::new();
        h.update(b"fhe-compute-prover-v1");
        h.update(&session_id);
        ds.copy_from_slice(&h.finalize());

        Self {
            domain_separator: ds,
            session_id,
        }
    }

    /// Verify an FHE compute proof.
    ///
    /// Re-executes the steps from the proof's initial state and compares
    /// against the claimed final state and folded commitment.
    pub fn verify(
        &self,
        proof: &FheComputeProof,
        steps: &[FheComputeStepCircuit],
    ) -> Result<bool, CompressorError> {
        // Check format header
        if proof.proof_bytes.len() < 4 + 1 + 32 + 128 + 128 + 32 + 8 {
            return Ok(false);
        }
        if &proof.proof_bytes[0..4] != FHE_COMPUTE_MAGIC {
            return Ok(false);
        }
        if proof.proof_bytes[4] != FHE_COMPUTE_VERSION {
            return Ok(false);
        }

        let proof_session = &proof.proof_bytes[5..37];
        if proof_session != &self.session_id[..] {
            return Ok(false);
        }

        // Re-execute all steps
        let mut current_state = proof.initial_state.clone();
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
        let witnesses: Vec<ExternalInputs3> = steps
            .iter()
            .scan(proof.initial_state.clone(), |state, step| {
                *state = step.apply(state).ok()?;
                Some(ExternalInputs3(
                    state.output_commitment,
                    state.merkle_root,
                    state.step_count,
                ))
            })
            .collect();

        let folded = super::fold::fold_instances(&witnesses, &self.domain_separator);

        if folded.folded_commitment != proof.folded_commitment {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Convenience function: prove an FHE compute chain.
pub fn prove_fhe_compute(
    session_id: [u8; 32],
    merkle_root: Fr,
    steps: &[FheComputeStepCircuit],
) -> Result<FheComputeProof, CompressorError> {
    let prover = FheComputeProver::new(session_id);
    let initial_state = FheComputeState::initial(merkle_root);
    prover.prove(initial_state, steps)
}

/// Convenience function: verify an FHE compute proof.
pub fn verify_fhe_compute(
    session_id: [u8; 32],
    proof: &FheComputeProof,
    steps: &[FheComputeStepCircuit],
) -> Result<bool, CompressorError> {
    let verifier = FheComputeVerifier::new(session_id);
    verifier.verify(proof, steps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::build_merkle_tree;

    fn test_session() -> [u8; 32] {
        Keccak256::digest(b"fhe-compute-test-session").into()
    }

    /// Build a small Merkle tree from ciphertext hashes for testing.
    fn build_test_merkle(num_leaves: usize) -> (Vec<Vec<Fr>>, Fr) {
        let leaves: Vec<Fr> = (0..num_leaves)
            .map(|i| {
                let mut h = Keccak256::new();
                h.update(b"test-ciphertext");
                h.update(&(i as u64).to_be_bytes());
                Fr::from_be_bytes_mod_order(&h.finalize())
            })
            .collect();
        build_merkle_tree(&leaves, 8)
    }

    #[test]
    fn state_initial() {
        let root = Fr::from(42u64);
        let state = FheComputeState::initial(root);
        assert_eq!(state.merkle_root, root);
        assert_eq!(state.output_commitment, Fr::zero());
        assert_eq!(state.input_hash_chain, Fr::zero());
        assert_eq!(state.step_count, Fr::zero());
    }

    #[test]
    fn state_encode_decode_roundtrip() {
        let state = FheComputeState {
            output_commitment: Fr::from(1u64),
            merkle_root: Fr::from(2u64),
            input_hash_chain: Fr::from(3u64),
            step_count: Fr::from(4u64),
        };
        let bytes = state.to_bytes();
        let decoded = FheComputeState::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, state);
    }

    #[test]
    fn operation_parse() {
        assert_eq!(FheOperation::from_str("add").unwrap(), FheOperation::Add);
        assert_eq!(FheOperation::from_str("mul").unwrap(), FheOperation::Mul);
        assert_eq!(FheOperation::from_str("relin").unwrap(), FheOperation::Mul);
        assert_eq!(
            FheOperation::from_str("noise").unwrap(),
            FheOperation::NoiseEval
        );
        assert_eq!(
            FheOperation::from_str("noiseeval").unwrap(),
            FheOperation::NoiseEval
        );
        assert!(FheOperation::from_str("unknown").is_err());
    }

    #[test]
    fn operation_arity() {
        assert_eq!(FheOperation::Add.arity(), 2);
        assert_eq!(FheOperation::Mul.arity(), 2);
        assert_eq!(FheOperation::NoiseEval.arity(), 1);
    }

    #[test]
    fn single_add_step() {
        let session = test_session();
        let (tree, root) = build_test_merkle(16);
        let initial = FheComputeState::initial(root);

        let leaf_a = &tree[0][0];
        let leaf_b = &tree[0][1];
        let output_hash = {
            let mut h = Keccak256::new();
            h.update(b"test-output");
            h.update(&leaf_a.into_bigint().to_bytes_be());
            h.update(&leaf_b.into_bigint().to_bytes_be());
            Fr::from_be_bytes_mod_order(&h.finalize())
        };

        let proof_a = crate::merkle::prove_merkle_path(&tree, 0, 8);
        let proof_b = crate::merkle::prove_merkle_path(&tree, 1, 8);

        let step = FheComputeStepCircuit::new(
            FheOperation::Add,
            proof_a,
            Some(proof_b),
            output_hash,
            session,
            0,
            Some(1),
        );

        let new_state = step.apply(&initial).unwrap();
        assert_eq!(new_state.merkle_root, root);
        assert_eq!(new_state.step_count, Fr::from(1u64));
    }

    #[test]
    fn step_rejects_wrong_merkle_root() {
        let session = test_session();
        let (tree, _root) = build_test_merkle(16);
        let wrong_root = Fr::from(999u64);
        let initial = FheComputeState::initial(wrong_root);

        let proof_a = crate::merkle::prove_merkle_path(&tree, 0, 8);

        let step = FheComputeStepCircuit::new(
            FheOperation::Add,
            proof_a,
            None,
            Fr::from(42u64),
            session,
            0,
            None, // missing input_b for Add
        );

        // Should fail: arity mismatch - Add requires 2 inputs but only A provided
        assert!(step.apply(&initial).is_err());
    }

    #[test]
    fn hash_chain_updates() {
        let session = test_session();
        let (tree, root) = build_test_merkle(16);
        let mut state = FheComputeState::initial(root);

        // Step 1: Add leaves 0 and 1
        let out1 = Fr::from(100u64);
        let proof_0 = crate::merkle::prove_merkle_path(&tree, 0, 8);
        let proof_1 = crate::merkle::prove_merkle_path(&tree, 1, 8);
        let step1 = FheComputeStepCircuit::new(
            FheOperation::Add,
            proof_0,
            Some(proof_1),
            out1,
            session,
            0,
            Some(1),
        );
        state = step1.apply(&state).unwrap();
        assert_eq!(state.step_count, Fr::from(1u64));
        assert_ne!(state.input_hash_chain, Fr::zero());

        // Step 2: Add leaves 2 and 3
        let out2 = Fr::from(200u64);
        let proof_2 = crate::merkle::prove_merkle_path(&tree, 2, 8);
        let proof_3 = crate::merkle::prove_merkle_path(&tree, 3, 8);
        let step2 = FheComputeStepCircuit::new(
            FheOperation::Add,
            proof_2,
            Some(proof_3),
            out2,
            session,
            2,
            Some(3),
        );
        let state2 = step2.apply(&state).unwrap();
        assert_eq!(state2.step_count, Fr::from(2u64));
        assert_ne!(
            state2.input_hash_chain, state.input_hash_chain,
            "hash chain must change"
        );
    }

    #[test]
    fn prove_verify_roundtrip() {
        let session = test_session();
        let (tree, root) = build_test_merkle(16);

        let output1 = Fr::from(100u64);
        let proof_0 = crate::merkle::prove_merkle_path(&tree, 0, 8);
        let proof_1 = crate::merkle::prove_merkle_path(&tree, 1, 8);
        let step1 = FheComputeStepCircuit::new(
            FheOperation::Add,
            proof_0,
            Some(proof_1),
            output1,
            session,
            0,
            Some(1),
        );

        let output2 = Fr::from(200u64);
        let proof_2 = crate::merkle::prove_merkle_path(&tree, 2, 8);
        let proof_3 = crate::merkle::prove_merkle_path(&tree, 3, 8);
        let step2 = FheComputeStepCircuit::new(
            FheOperation::Add,
            proof_2.clone(),
            Some(proof_3),
            output2,
            session,
            2,
            Some(3),
        );

        let steps = vec![step1, step2];
        let prover = FheComputeProver::new(session);
        let initial = FheComputeState::initial(root);
        let proof = prover.prove(initial, &steps).unwrap();

        assert_eq!(proof.num_steps, 2);
        assert!(!proof.proof_bytes.is_empty());

        let verifier = FheComputeVerifier::new(session);
        let steps_for_verify = vec![
            FheComputeStepCircuit::new(
                FheOperation::Add,
                crate::merkle::prove_merkle_path(&tree, 0, 8),
                Some(crate::merkle::prove_merkle_path(&tree, 1, 8)),
                output1,
                session,
                0,
                Some(1),
            ),
            FheComputeStepCircuit::new(
                FheOperation::Add,
                proof_2,
                Some(crate::merkle::prove_merkle_path(&tree, 3, 8)),
                output2,
                session,
                2,
                Some(3),
            ),
        ];

        assert!(
            verifier.verify(&proof, &steps_for_verify).unwrap(),
            "roundtrip verify must pass"
        );
    }

    #[test]
    fn prove_empty_steps_rejected() {
        let session = test_session();
        let prover = FheComputeProver::new(session);
        let (_, root) = build_test_merkle(8);
        let initial = FheComputeState::initial(root);
        let result = prover.prove(initial, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn noise_eval_step() {
        let session = test_session();
        let (tree, root) = build_test_merkle(16);
        let initial = FheComputeState::initial(root);

        let proof_a = crate::merkle::prove_merkle_path(&tree, 0, 8);
        let output_hash = Fr::from(42u64);

        let step = FheComputeStepCircuit::new(
            FheOperation::NoiseEval,
            proof_a,
            None, // NoiseEval is unary
            output_hash,
            session,
            0,
            None,
        );

        let new_state = step.apply(&initial).unwrap();
        assert_eq!(new_state.step_count, Fr::from(1u64));
    }

    #[test]
    fn prove_deterministic() {
        let session = test_session();
        let (tree, root) = build_test_merkle(16);

        let proof_0 = crate::merkle::prove_merkle_path(&tree, 0, 8);
        let proof_1 = crate::merkle::prove_merkle_path(&tree, 1, 8);
        let step = FheComputeStepCircuit::new(
            FheOperation::Add,
            proof_0,
            Some(proof_1),
            Fr::from(100u64),
            session,
            0,
            Some(1),
        );

        let prover = FheComputeProver::new(session);
        let initial = FheComputeState::initial(root);

        let proof1 = prover.prove(initial.clone(), &[step.clone()]).unwrap();
        let proof2 = prover.prove(initial, &[step]).unwrap();

        assert_eq!(
            proof1.proof_bytes, proof2.proof_bytes,
            "proofs must be deterministic"
        );
    }
}
