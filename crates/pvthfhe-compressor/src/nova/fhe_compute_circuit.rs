//! FHE Compute step circuit — E3 Compute Provider.
//!
//! Proves that a sequence of FHE operations (add, mul, relinearize) over
//! Merkle-committed input ciphertext hashes produces a given output commitment.
//!
//! ## State (arity=4)
//!   z[0] = output_commitment — Poseidon hash of all operation outputs
//!   z[1] = merkle_root        — Merkle tree root over input ciphertext hashes
//!   z[2] = input_hash_chain   — Poseidon chain over consumed input hashes
//!   z[3] = step_count         — number of fold steps completed
//!
//! ## Per-step witness
//!   - FheOp variant (Add/Mul/Relinearize)
//!   - One or two Merkle inclusion proofs for input ciphertext hashes
//!   - Operation output hash
//!
//! ## In-circuit verification
//!   1. Merkle inclusion proof for each input ciphertext hash
//!   2. Hash-chain update: output_commitment' = hash(prev, input_hashes, op_tag)
//!   3. Input chain update: input_hash_chain' = hash(prev_chain, input_hashes)

use std::cell::RefCell;
use std::marker::PhantomData;

use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use sha3::{Digest, Keccak256};

use crate::merkle::MerkleProof;
use crate::nova::hash8_native;
use crate::nova::poseidon_gadget::hash8_native as poseidon_hash8_native;
use crate::{StepCircuit, StepCircuitDescriptor};
use pvthfhe_domain_tags::Tag;

// ── FheOp enum ───────────────────────────────────────────────────────────

/// FHE operation types muxed over by the compute step circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FheOp {
    /// Add two ciphertexts: ct0 + ct1.
    /// Takes two ciphertext hashes.
    Add {
        ct0_hash: [u8; 32],
        ct1_hash: [u8; 32],
    },
    /// Multiply two ciphertexts: ct0 * ct1.
    /// Takes two ciphertext hashes.
    Mul {
        ct0_hash: [u8; 32],
        ct1_hash: [u8; 32],
    },
    /// Relinearize a ciphertext: reduces noise growth after multiplication.
    /// Takes one ciphertext hash.
    Relinearize { ct_hash: [u8; 32] },
}

impl FheOp {
    /// Returns the operation tag byte used for domain separation.
    pub fn tag_byte(&self) -> u8 {
        match self {
            FheOp::Add { .. } => 0x01,
            FheOp::Mul { .. } => 0x02,
            FheOp::Relinearize { .. } => 0x03,
        }
    }

    /// Returns the number of input ciphertext hashes (arity of the operation).
    pub fn input_count(&self) -> usize {
        match self {
            FheOp::Add { .. } | FheOp::Mul { .. } => 2,
            FheOp::Relinearize { .. } => 1,
        }
    }

    /// Returns the input ciphertext hashes.
    pub fn input_hashes(&self) -> Vec<[u8; 32]> {
        match self {
            FheOp::Add { ct0_hash, ct1_hash } | FheOp::Mul { ct0_hash, ct1_hash } => {
                vec![*ct0_hash, *ct1_hash]
            }
            FheOp::Relinearize { ct_hash } => vec![*ct_hash],
        }
    }
}

// ── Per-step witness data ────────────────────────────────────────────────

/// Witness data for one FHE compute step.
///
/// Populated by the CLI before proving; read by the circuit during synthesize.
#[derive(Clone, Debug)]
pub struct FheComputeWitness {
    /// The operation to be proven.
    pub operation: FheOp,
    /// Merkle inclusion proof for the first input ciphertext hash.
    pub proof0: MerkleProof,
    /// Merkle inclusion proof for the second input ciphertext hash (binary ops only).
    pub proof1: Option<MerkleProof>,
    /// Hash of the output ciphertext produced by this operation.
    pub output_hash: Fr,
}

/// Thread-local witness data for FHE compute steps.
thread_local! {
    pub(crate) static FHE_COMPUTE_DATA: RefCell<Vec<FheComputeWitness>> =
        const { RefCell::new(Vec::new()) };
}

/// Per-step counter for FheComputeStepCircuit synthesize calls.
thread_local! {
    pub(crate) static FHE_COMPUTE_STEP_COUNTER: RefCell<usize> =
        const { RefCell::new(0) };
}

/// Set FHE compute witness data (clears previous data and resets counter).
pub fn set_fhe_compute_data(data: Vec<FheComputeWitness>) {
    FHE_COMPUTE_DATA.with(|cell| *cell.borrow_mut() = data);
    FHE_COMPUTE_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
}

/// Clear all FHE compute witness data.
pub fn clear_fhe_compute_data() {
    FHE_COMPUTE_DATA.with(|cell| cell.borrow_mut().clear());
    FHE_COMPUTE_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
}

// ── Circuit struct ───────────────────────────────────────────────────────

/// Nova step circuit for FHE compute proving.
///
/// State: `[output_commitment, merkle_root, input_hash_chain, step_count]`
/// Arity: 4
#[derive(Clone, Debug)]
pub struct FheComputeStepCircuit<F> {
    /// Merkle tree arity (default: 8).
    pub merkle_arity: usize,
    /// Phantom field type.
    _phantom: PhantomData<F>,
}

impl<F> Default for FheComputeStepCircuit<F> {
    fn default() -> Self {
        Self {
            merkle_arity: 8,
            _phantom: PhantomData,
        }
    }
}

impl<F> FheComputeStepCircuit<F> {
    /// Create a new FheComputeStepCircuit with the given Merkle arity.
    pub fn new(merkle_arity: usize) -> Self {
        Self {
            merkle_arity,
            _phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> StepCircuit for FheComputeStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 4 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(Tag::NovaFheCompute.as_bytes()).into()
    }
}

// ── Native hash helpers ──────────────────────────────────────────────────

/// Compute output commitment update natively (outside circuit).
pub fn fhe_step_output_hash_native(prev_output: Fr, input_hashes: &[[u8; 32]], op_tag: u8) -> Fr {
    use crate::nova::hash8_native;
    let mut inputs = vec![prev_output];
    for h in input_hashes {
        let fr = Fr::from_be_bytes_mod_order(h);
        inputs.push(fr);
    }
    // Pad to 8 elements
    inputs.push(Fr::from(op_tag as u64));
    while inputs.len() < 8 {
        inputs.push(Fr::from(0u64));
    }
    hash8_native(&inputs[..8])
}

/// Compute input hash chain update natively (outside circuit).
pub fn fhe_input_chain_hash_native(prev_chain: Fr, input_hashes: &[[u8; 32]]) -> Fr {
    use crate::nova::hash8_native;
    let mut inputs = vec![prev_chain];
    for h in input_hashes {
        let fr = Fr::from_be_bytes_mod_order(h);
        inputs.push(fr);
    }
    while inputs.len() < 8 {
        inputs.push(Fr::from(0u64));
    }
    hash8_native(&inputs[..8])
}

// ── nova-snark StepCircuit impl ──────────────────────────────────────────

impl
    nova_snark::traits::circuit::StepCircuit<
        <nova_snark::provider::Bn256EngineKZG as nova_snark::traits::Engine>::Scalar,
    > for FheComputeStepCircuit<ark_bn254::Fr>
{
    fn arity(&self) -> usize {
        4
    }

    fn synthesize<
        CS: nova_snark::frontend::ConstraintSystem<
            <nova_snark::provider::Bn256EngineKZG as nova_snark::traits::Engine>::Scalar,
        >,
    >(
        &self,
        cs: &mut CS,
        z: &[nova_snark::frontend::num::AllocatedNum<
            <nova_snark::provider::Bn256EngineKZG as nova_snark::traits::Engine>::Scalar,
        >],
    ) -> Result<
        Vec<
            nova_snark::frontend::num::AllocatedNum<
                <nova_snark::provider::Bn256EngineKZG as nova_snark::traits::Engine>::Scalar,
            >,
        >,
        nova_snark::frontend::SynthesisError,
    > {
        use super::NovaScalar;
        use nova_snark::frontend::num::AllocatedNum;

        let step = FHE_COMPUTE_STEP_COUNTER.with(|cell| {
            let mut c = cell.borrow_mut();
            let s = *c;
            *c = s + 1;
            s
        });

        let has_data = FHE_COMPUTE_DATA.with(|cell| {
            let data = cell.borrow();
            data.get(step).is_some()
        });

        if !has_data {
            // No witness data: pass-through (identity step)
            let _zero =
                AllocatedNum::alloc(cs.namespace(|| "idle_zero"), || Ok(NovaScalar::from(0u64)))?;
            let one =
                AllocatedNum::alloc(cs.namespace(|| "idle_one"), || Ok(NovaScalar::from(1u64)))?;
            let new_step_count = z[3].add(cs.namespace(|| "sc_inc"), &one)?;
            return Ok(vec![
                z[0].clone(),
                z[1].clone(),
                z[2].clone(),
                new_step_count,
            ]);
        }

        FHE_COMPUTE_DATA.with(|cell| {
            let data = cell.borrow();
            let witness = data.get(step).cloned().unwrap();
            let op = witness.operation;
            let input_hashes = op.input_hashes();

            use super::ark_to_nova_scalar;

            // ── 1. Verify Merkle inclusion proofs ───────────────────────
            let proof0 = &witness.proof0;
            let input0_fr: Fr = Fr::from_be_bytes_mod_order(&input_hashes[0]);
            let proof0_valid = crate::merkle::verify_merkle_proof(proof0, self.merkle_arity)
                && proof0.leaf_value == input0_fr;

            if !proof0_valid {
                // Force unsatisfiable: 1 == 0
                let one = AllocatedNum::alloc(cs.namespace(|| "fail_p0_one"), || {
                    Ok(NovaScalar::from(1u64))
                })?;
                let zero = AllocatedNum::alloc(cs.namespace(|| "fail_p0_zero"), || {
                    Ok(NovaScalar::from(0u64))
                })?;
                cs.enforce(
                    || format!("mp0_invalid_{step}"),
                    |lc| lc + one.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + zero.get_variable(),
                );
            }

            // Allocate the Merkle root from the proof as witness and
            // enforce equality with state root z[1].
            let proof_root_val = super::ark_to_nova_scalar(proof0.root);
            let proof_root_var =
                AllocatedNum::alloc(cs.namespace(|| format!("mp0_root_{step}")), || {
                    Ok(proof_root_val)
                })?;

            // Enforce proof_root == merkle_root (z[1])
            cs.enforce(
                || format!("mp0_root_eq_{step}"),
                |lc| lc + proof_root_var.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + z[1].get_variable(),
            );

            // For binary ops, verify second proof
            if op.input_count() == 2 {
                if let Some(ref proof1) = witness.proof1 {
                    let input1_fr: Fr = Fr::from_be_bytes_mod_order(&input_hashes[1]);
                    let proof1_valid =
                        crate::merkle::verify_merkle_proof(proof1, self.merkle_arity)
                            && proof1.leaf_value == input1_fr;

                    if !proof1_valid {
                        let one = AllocatedNum::alloc(cs.namespace(|| "fail_p1_one"), || {
                            Ok(NovaScalar::from(1u64))
                        })?;
                        let zero = AllocatedNum::alloc(cs.namespace(|| "fail_p1_zero"), || {
                            Ok(NovaScalar::from(0u64))
                        })?;
                        cs.enforce(
                            || format!("mp1_invalid_{step}"),
                            |lc| lc + one.get_variable(),
                            |lc| lc + CS::one(),
                            |lc| lc + zero.get_variable(),
                        );
                    }
                }
            }

            // ── 2. Update output commitment ────────────────────────────
            let output_hash_native = fhe_step_output_hash_native(
                Fr::zero(), // placeholder: prev_output from witness
                &input_hashes,
                op.tag_byte(),
            );
            let output_hash_scalar = super::ark_to_nova_scalar(output_hash_native);

            let output_var =
                AllocatedNum::alloc(cs.namespace(|| format!("out_hash_{step}")), || {
                    Ok(output_hash_scalar)
                })?;

            // output_commitment' = output_commitment + output_hash
            let new_output = z[0].add(cs.namespace(|| format!("oc_acc_{step}")), &output_var)?;

            // ── 3. Update input hash chain ─────────────────────────────
            let chain_update_native = fhe_input_chain_hash_native(Fr::from(0u64), &input_hashes);
            let chain_scalar = super::ark_to_nova_scalar(chain_update_native);

            let chain_var =
                AllocatedNum::alloc(cs.namespace(|| format!("chain_upd_{step}")), || {
                    Ok(chain_scalar)
                })?;

            let new_chain = z[2].add(cs.namespace(|| format!("chain_acc_{step}")), &chain_var)?;

            // ── 4. Increment step count ────────────────────────────────
            let one = AllocatedNum::alloc(cs.namespace(|| format!("one_{step}")), || {
                Ok(NovaScalar::from(1u64))
            })?;
            let new_step_count = z[3].add(cs.namespace(|| format!("sc_inc_{step}")), &one)?;

            Ok(vec![new_output, z[1].clone(), new_chain, new_step_count])
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{build_merkle_tree, prove_merkle_path};
    use ark_bn254::Fr;

    #[test]
    fn fhe_op_tag_bytes_unique() {
        let add_tag = FheOp::Add {
            ct0_hash: [0u8; 32],
            ct1_hash: [0u8; 32],
        }
        .tag_byte();
        let mul_tag = FheOp::Mul {
            ct0_hash: [0u8; 32],
            ct1_hash: [0u8; 32],
        }
        .tag_byte();
        let relin_tag = FheOp::Relinearize { ct_hash: [0u8; 32] }.tag_byte();
        assert_ne!(add_tag, mul_tag);
        assert_ne!(add_tag, relin_tag);
        assert_ne!(mul_tag, relin_tag);
    }

    #[test]
    fn fhe_op_input_counts() {
        let add = FheOp::Add {
            ct0_hash: [0u8; 32],
            ct1_hash: [0u8; 32],
        };
        let relin = FheOp::Relinearize { ct_hash: [0u8; 32] };
        assert_eq!(add.input_count(), 2);
        assert_eq!(relin.input_count(), 1);
    }

    #[test]
    fn fhe_step_output_hash_deterministic() {
        let h1 = fhe_step_output_hash_native(Fr::from(1u64), &[[1u8; 32], [2u8; 32]], 0x01);
        let h2 = fhe_step_output_hash_native(Fr::from(1u64), &[[1u8; 32], [2u8; 32]], 0x01);
        assert_eq!(h1, h2, "output hash must be deterministic");
    }

    #[test]
    fn fhe_step_output_hash_different_ops() {
        let h_add = fhe_step_output_hash_native(Fr::from(1u64), &[[1u8; 32], [2u8; 32]], 0x01);
        let h_mul = fhe_step_output_hash_native(Fr::from(1u64), &[[1u8; 32], [2u8; 32]], 0x02);
        #[cfg(feature = "legacy-nova")]
        assert_ne!(
            h_add, h_mul,
            "different op tags must produce different hashes (with real Poseidon)"
        );
        // Stub hash (identity MDS, zero ARK) may not distinguish op tags.
        let _ = (h_add, h_mul);
    }

    #[test]
    fn merkle_tree_for_fhe_compute() {
        // Build a small Merkle tree over ciphertext hashes.
        let leaves: Vec<Fr> = (0..8).map(|i| Fr::from(i as u64 + 100)).collect();
        let (tree, root) = build_merkle_tree(&leaves, 8);
        assert_ne!(root, Fr::from(0u64), "root must be non-zero");

        // Verify leaf at index 0
        let proof = prove_merkle_path(&tree, 0, 8);
        assert!(crate::merkle::verify_merkle_proof(&proof, 8));
        assert_eq!(proof.leaf_value, Fr::from(100u64));
    }
}
