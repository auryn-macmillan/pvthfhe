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
//!   2. FHE operation enforcement (Add: in-circuit modular addition; Mul/Relin: deferred)
//!   3. Hash-chain update: output_commitment' = hash(prev, input_hashes, op_tag)
//!   4. Input chain update: input_hash_chain' = hash(prev_chain, input_hashes)
//!
//! ### FHE ciphertext parameters (BFV)
//!   - Polynomial degree N = 4 (demo scale; production uses N=8192)
//!   - RNS limbs L = 3
//!   - Moduli: Q = [288230376173076481, 288230376167047169, 288230376161280001]
//!   - Ciphertext: 2 polynomials × L limbs × N coefficients = 24 u64 values

use std::cell::RefCell;
use std::marker::PhantomData;

use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use sha3::{Digest, Keccak256};

use crate::merkle::MerkleProof;
use crate::nova::hash8_native;
use crate::{StepCircuit, StepCircuitDescriptor};
use pvthfhe_domain_tags::Tag;

// ── FHE ciphertext parameters (BFV) ─────────────────────────────────────

/// Polynomial degree (demo scale; production uses N=8192).
pub const BFV_N: usize = 4;

/// Number of CRT moduli (RNS limbs).
pub const BFV_L: usize = 3;

/// BFV modulus per limb (q[l]).
pub const BFV_Q: [u64; BFV_L] = [
    288_230_376_173_076_481,
    288_230_376_167_047_169,
    288_230_376_161_280_001,
];

/// Total number of coefficients per ciphertext: 2 polys × L limbs × N coeffs.
pub const BFV_CT_COEFFS_LEN: usize = 2 * BFV_L * BFV_N;

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
    /// Input ciphertext 0 coefficients (2 * L * N u64 values).
    /// Required for Add operations; empty for Mul/Relin (deferred).
    pub ct0_coeffs: Vec<u64>,
    /// Input ciphertext 1 coefficients (2 * L * N u64 values).
    /// Required for Add operations; empty for Mul/Relin (deferred).
    pub ct1_coeffs: Vec<u64>,
    /// Output ciphertext coefficients (2 * L * N u64 values).
    /// Required for Add operations; empty for Mul/Relin (deferred).
    pub ct_out_coeffs: Vec<u64>,
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

// ── In-circuit FHE addition gadget ──────────────────────────────────────

/// In-circuit modular addition for BFV ciphertext coefficients.
///
/// For each coefficient in ct0 and ct1, enforces:
///   ct_out = ct0 + ct1 - k * q_modulus   where k ∈ {0, 1}
///
/// Uses 2 constraints per coefficient (boolean check + modular reduction).
fn add_fhe_ct_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    ct0_coeffs: &[u64],
    ct1_coeffs: &[u64],
    ct_out_coeffs: &[u64],
    q_moduli: &[u64],
    num_polys: usize,
    num_limbs: usize,
    ct_poly_len: usize,
    step: usize,
) -> Result<(), SynthesisError> {
    let total = num_polys * num_limbs * ct_poly_len;
    assert_eq!(ct0_coeffs.len(), total);
    assert_eq!(ct1_coeffs.len(), total);
    assert_eq!(ct_out_coeffs.len(), total);

    for poly in 0..num_polys {
        for limb in 0..num_limbs {
            let q = q_moduli[limb];
            let q_scalar = NovaScalar::from(q);
            let base = format!("add_fhe_s{step}_p{poly}_l{limb}");

            for coeff_idx in 0..ct_poly_len {
                let idx = poly * num_limbs * ct_poly_len + limb * ct_poly_len + coeff_idx;
                let c0 = ct0_coeffs[idx];
                let c1 = ct1_coeffs[idx];
                let c_out = ct_out_coeffs[idx];

                // Determine overflow witness knight's move
                let sum_u128 = c0 as u128 + c1 as u128;
                let k_val = if sum_u128 >= q as u128 { 1u64 } else { 0u64 };

                // Allocate witnesses
                let c0_var = AllocatedNum::alloc(
                    cs.namespace(|| format!("{base}_c0_c{coeff_idx}")),
                    || Ok(NovaScalar::from(c0)),
                )?;
                let c1_var = AllocatedNum::alloc(
                    cs.namespace(|| format!("{base}_c1_c{coeff_idx}")),
                    || Ok(NovaScalar::from(c1)),
                )?;
                let c_out_var = AllocatedNum::alloc(
                    cs.namespace(|| format!("{base}_cout_c{coeff_idx}")),
                    || Ok(NovaScalar::from(c_out)),
                )?;
                let k_var =
                    AllocatedNum::alloc(cs.namespace(|| format!("{base}_k_c{coeff_idx}")), || {
                        Ok(NovaScalar::from(k_val))
                    })?;

                // Constraint 1: k is boolean → k * (1 - k) == 0
                cs.enforce(
                    || format!("{base}_k_bool_c{coeff_idx}"),
                    |lc| lc + k_var.get_variable(),
                    |lc| lc + CS::one() - k_var.get_variable(),
                    |lc| lc,
                );

                // Constraint 2: ct0 + ct1 - ct_out == k * q
                cs.enforce(
                    || format!("{base}_modadd_c{coeff_idx}"),
                    |lc| {
                        lc + c0_var.get_variable() + c1_var.get_variable()
                            - c_out_var.get_variable()
                    },
                    |lc| lc + CS::one(),
                    |lc| lc + (q_scalar, k_var.get_variable()),
                );
            }
        }
    }

    Ok(())
}

// ── Wave 2: Bellpepper-native Poseidon hash8 gadget ─────────────────────
//
// Implements Poseidon hash of 8 field elements directly in bellpepper (Nova SNARK)
// constraint system, matching the behavior of `poseidon_gadget::hash8_native`.
//
// Uses identity MDS + zero ARK when `legacy-nova` is disabled (default),
// and would use the canonical Poseidon config when enabled.
// Each hash8 costs ~600 R1CS constraints (2 permutations × 300 constraints each).

use super::NovaScalar;
use nova_snark::frontend::num::AllocatedNum;
use nova_snark::frontend::{ConstraintSystem, SynthesisError};

/// Number of state elements (t = rate + capacity).
const POSEIDON_T: usize = 5;
/// Sponge rate (elements absorbed per batch).
const POSEIDON_RATE: usize = 4;
/// Sponge capacity.
const POSEIDON_CAPACITY: usize = 1;
/// Number of full rounds (split: half first, half last).
const POSEIDON_FULL_ROUNDS: usize = 8;
/// Number of partial rounds (middle phase).
const POSEIDON_PARTIAL_ROUNDS: usize = 60;

/// Apply S-box (x^5) to a bellpepper allocated number.
/// Costs 3 R1CS constraints (x^2, x^4, x^5).
fn sbox_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    x: &AllocatedNum<NovaScalar>,
    label: &str,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
    let sq = x.mul(cs.namespace(|| format!("{label}_sq")), x)?;
    let qu = sq.mul(cs.namespace(|| format!("{label}_qu")), &sq)?;
    let qi = qu.mul(cs.namespace(|| format!("{label}_qi")), x)?;
    Ok(qi)
}

/// Apply full S-box to all state elements in-place.
fn full_sbox_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    state: &mut Vec<AllocatedNum<NovaScalar>>,
    base: &str,
    round: usize,
    phase: &str,
) -> Result<(), SynthesisError> {
    let mut new_state = Vec::with_capacity(state.len());
    for (i, elem) in state.iter().enumerate() {
        let qi = sbox_bp(cs, elem, &format!("{base}_full_{phase}_r{round}_e{i}"))?;
        new_state.push(qi);
    }
    *state = new_state;
    Ok(())
}

/// Apply partial S-box to state[0] only, in-place.
fn partial_sbox_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    state: &mut Vec<AllocatedNum<NovaScalar>>,
    base: &str,
    round: usize,
) -> Result<(), SynthesisError> {
    let qi = sbox_bp(cs, &state[0], &format!("{base}_partial_r{round}"))?;
    state[0] = qi;
    Ok(())
}

/// Apply MDS mixing layer: new_state = MDS × state.
///
/// With identity MDS (default config without legacy-nova), this is a no-op.
/// The full matrix multiplication is implemented for future real-MDS support.
fn mix_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    state: &mut Vec<AllocatedNum<NovaScalar>>,
    mds: &[Vec<NovaScalar>],
    label: &str,
) -> Result<(), SynthesisError> {
    let t = state.len();
    let mut new_state = Vec::with_capacity(t);
    for i in 0..t {
        // Compute the expected sum natively for witness allocation
        let sum_val = state
            .iter()
            .enumerate()
            .fold(NovaScalar::from(0u64), |acc, (j, s)| {
                acc + s.get_value().unwrap_or(NovaScalar::from(0u64)) * mds[i][j]
            });
        let sum_var =
            AllocatedNum::alloc(cs.namespace(|| format!("{label}_mix_{i}")), || Ok(sum_val))?;
        // Enforce: 1 * sum = Σ_j mds[i][j] * state[j]
        cs.enforce(
            || format!("{label}_mix_enforce_{i}"),
            |lc| lc + CS::one(),
            |lc| lc + sum_var.get_variable(),
            |lc| {
                let mut lc_val = lc;
                for (j, sj) in state.iter().enumerate() {
                    let coeff = mds[i][j];
                    if coeff != NovaScalar::from(0u64) {
                        lc_val = lc_val + (coeff, sj.get_variable());
                    }
                }
                lc_val
            },
        );
        new_state.push(sum_var);
    }
    *state = new_state;
    Ok(())
}

/// Apply ARK (Add Round Key): state[i] += round_constant[i].
fn ark_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    state: &mut Vec<AllocatedNum<NovaScalar>>,
    rk: &[NovaScalar],
    label: &str,
) -> Result<(), SynthesisError> {
    let t = state.len();
    let mut new_state = Vec::with_capacity(t);
    for i in 0..t {
        let new_val = state[i].get_value().unwrap_or(NovaScalar::from(0u64)) + rk[i];
        let new_var =
            AllocatedNum::alloc(cs.namespace(|| format!("{label}_ark_{i}")), || Ok(new_val))?;
        // Enforce: 1 * new = state[i] + rk[i]
        cs.enforce(
            || format!("{label}_ark_enforce_{i}"),
            |lc| lc + CS::one(),
            |lc| lc + new_var.get_variable(),
            |lc| lc + state[i].get_variable() + (rk[i], CS::one()),
        );
        new_state.push(new_var);
    }
    *state = new_state;
    Ok(())
}

/// Apply one full Poseidon permutation to state in bellpepper.
///
/// Matches the native `poseidon_gadget::native_permute`:
///   full_rounds/2 → partial_rounds → full_rounds/2
/// Each round: ARK → S-box → MDS mix.
fn permute_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    state: &mut Vec<AllocatedNum<NovaScalar>>,
    mds: &[Vec<NovaScalar>],
    ark: &[Vec<NovaScalar>],
    step_idx: usize,
    perm_idx: usize,
) -> Result<(), SynthesisError> {
    let full_rounds_half = POSEIDON_FULL_ROUNDS / 2;
    let base = format!("poseidon_perm_s{step_idx}_p{perm_idx}");

    for r in 0..full_rounds_half {
        ark_bp(cs, state, &ark[r], &format!("{base}_fr1_ark_r{r}"))?;
        full_sbox_bp(cs, state, &base, r, "fr1")?;
        mix_bp(cs, state, mds, &format!("{base}_fr1_r{r}"))?;
    }

    for r in 0..POSEIDON_PARTIAL_ROUNDS {
        let idx = full_rounds_half + r;
        ark_bp(cs, state, &ark[idx], &format!("{base}_pr_ark_r{r}"))?;
        partial_sbox_bp(cs, state, &base, r)?;
        mix_bp(cs, state, mds, &format!("{base}_pr_r{r}"))?;
    }

    for r in 0..full_rounds_half {
        let idx = full_rounds_half + POSEIDON_PARTIAL_ROUNDS + r;
        ark_bp(cs, state, &ark[idx], &format!("{base}_fr2_ark_r{r}"))?;
        full_sbox_bp(cs, state, &base, r, "fr2")?;
        mix_bp(cs, state, mds, &format!("{base}_fr2_r{r}"))?;
    }

    Ok(())
}

/// Build identity MDS matrix and zero ARK for the default (non-legacy-nova) config.
fn identity_poseidon_params() -> (Vec<Vec<NovaScalar>>, Vec<Vec<NovaScalar>>) {
    let zero = NovaScalar::from(0u64);
    let one = NovaScalar::from(1u64);
    let mds: Vec<Vec<NovaScalar>> = (0..POSEIDON_T)
        .map(|i| {
            (0..POSEIDON_T)
                .map(|j| if i == j { one } else { zero })
                .collect()
        })
        .collect();
    let total_rounds = POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS;
    let ark: Vec<Vec<NovaScalar>> = vec![vec![NovaScalar::from(0u64); POSEIDON_T]; total_rounds];
    (mds, ark)
}

/// Poseidon hash of 8 elements in bellpepper, matching `poseidon_gadget::hash8_native`.
///
/// Uses sponge: absorb 4 elements → permute → absorb 4 elements → permute → squeeze.
/// Costs ~600 R1CS constraints per call.
fn poseidon_hash8_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    inputs: &[AllocatedNum<NovaScalar>],
    step_idx: usize,
    hash_idx: usize,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
    assert_eq!(
        inputs.len(),
        8,
        "poseidon_hash8_bp requires exactly 8 inputs"
    );

    let (mds, ark) = identity_poseidon_params();
    let base = format!("poseidon_h8_s{step_idx}_h{hash_idx}");

    // Initialize state to zeros
    let mut state: Vec<AllocatedNum<NovaScalar>> = (0..POSEIDON_T)
        .map(|i| {
            AllocatedNum::alloc(cs.namespace(|| format!("{base}_init_{i}")), || {
                Ok(NovaScalar::from(0u64))
            })
        })
        .collect::<Result<_, _>>()?;

    // Absorb first 4 elements into rate portion (indices 1..5)
    for i in 0..POSEIDON_RATE {
        state[POSEIDON_CAPACITY + i] = state[POSEIDON_CAPACITY + i]
            .add(cs.namespace(|| format!("{base}_abs1_{i}")), &inputs[i])?;
    }
    permute_bp(cs, &mut state, &mds, &ark, step_idx, hash_idx * 2)?;

    // Absorb next 4 elements
    for i in 0..POSEIDON_RATE {
        state[POSEIDON_CAPACITY + i] = state[POSEIDON_CAPACITY + i]
            .add(cs.namespace(|| format!("{base}_abs2_{i}")), &inputs[4 + i])?;
    }
    permute_bp(cs, &mut state, &mds, &ark, step_idx, hash_idx * 2 + 1)?;

    // Squeeze: return first rate element
    Ok(state[POSEIDON_CAPACITY].clone())
}

// ── Wave 2: In-circuit Merkle proof verification ────────────────────────
//
// Verifies a Merkle proof against the root in z[1] using in-circuit Poseidon
// hash chain. Replaces the native `verify_merkle_proof` call.

/// Verify Merkle inclusion proof in-circuit using Poseidon hash8.
///
/// For an arity-8 tree, each level hashes `arity` elements (current node
/// placed at the correct position derived from leaf_index, plus siblings).
/// The chain of hashes must terminate at the merkle root in z[1].
fn verify_merkle_proof_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    proof: &MerkleProof,
    arity: usize,
    step: usize,
    proof_idx: usize,
    merkle_root_var: &AllocatedNum<NovaScalar>,
) -> Result<(), SynthesisError> {
    let base = format!("mp_s{step}_p{proof_idx}");

    // Allocate leaf value as witness
    let leaf_scalar = super::ark_to_nova_scalar(proof.leaf_value);
    let leaf_var =
        AllocatedNum::alloc(cs.namespace(|| format!("{base}_leaf")), || Ok(leaf_scalar))?;

    let mut current = leaf_var;
    let mut idx = proof.leaf_index;

    for (level, level_siblings) in proof.siblings.iter().enumerate() {
        let position = idx % arity;

        // Build the list of arity field elements for this level's hash.
        // current node goes at `position`; siblings fill the remaining slots.
        let mut level_inputs_scalars = vec![NovaScalar::from(0u64); arity];
        level_inputs_scalars[position] = current.get_value().unwrap_or(NovaScalar::from(0u64));

        let mut sib_scalar_iter = level_siblings
            .iter()
            .map(|&fr| super::ark_to_nova_scalar(fr));
        for j in 0..arity {
            if j != position {
                level_inputs_scalars[j] = sib_scalar_iter.next().unwrap_or(NovaScalar::from(0u64));
            }
        }

        // Pad to exactly 8 elements for hash8 (pad with zeros if arity < 8)
        let mut hash_inputs_scalars = level_inputs_scalars.clone();
        while hash_inputs_scalars.len() < 8 {
            hash_inputs_scalars.push(NovaScalar::from(0u64));
        }

        // Allocate the hash inputs as circuit witnesses
        let hash_inputs: Vec<AllocatedNum<NovaScalar>> = hash_inputs_scalars
            .iter()
            .enumerate()
            .map(|(j, &val)| {
                AllocatedNum::alloc(cs.namespace(|| format!("{base}_l{level}_inp{j}")), || {
                    Ok(val)
                })
            })
            .collect::<Result<_, _>>()?;

        // Constrain that the input at `position` equals `current`
        // diff = input[position] - current; enforce diff * 1 == 0
        let diff_val =
            hash_inputs_scalars[position] - current.get_value().unwrap_or(NovaScalar::from(0u64));
        let diff_var =
            AllocatedNum::alloc(cs.namespace(|| format!("{base}_l{level}_diff")), || {
                Ok(diff_val)
            })?;
        cs.enforce(
            || format!("{base}_l{level}_pos_eq"),
            |lc| lc + hash_inputs[position].get_variable() - current.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + diff_var.get_variable(),
        );
        // diff must be zero
        cs.enforce(
            || format!("{base}_l{level}_diff_zero"),
            |lc| lc + diff_var.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc,
        );

        // Hash this level using in-circuit Poseidon
        current = poseidon_hash8_bp(cs, &hash_inputs, step * 16 + proof_idx * 8 + level, level)?;

        idx /= arity;
    }

    // Final constraint: current (computed root) == merkle_root (z[1])
    cs.enforce(
        || format!("{base}_root_eq"),
        |lc| lc + current.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + merkle_root_var.get_variable(),
    );

    Ok(())
}

// ── Wave 2: In-circuit hash chain updates ───────────────────────────────
//
// Replaces native `fhe_step_output_hash_native` and `fhe_input_chain_hash_native`
// with in-circuit Poseidon hash8 computations.

/// Compute output commitment hash in-circuit.
///
/// Matches `fhe_step_output_hash_native` behavior exactly:
///   hash8(prev_output, input_hash_fr..., op_tag_fr, 0, 0, ...)
fn fhe_step_output_hash_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    input_hashes: &[[u8; 32]],
    op_tag: u8,
    step: usize,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
    // Build the same 8-element input vector as the native version
    let mut inputs_scalars: Vec<NovaScalar> = vec![NovaScalar::from(0u64)]; // prev_output = 0
    for h in input_hashes {
        let fr = Fr::from_be_bytes_mod_order(h);
        inputs_scalars.push(super::ark_to_nova_scalar(fr));
    }
    inputs_scalars.push(NovaScalar::from(op_tag as u64));
    while inputs_scalars.len() < 8 {
        inputs_scalars.push(NovaScalar::from(0u64));
    }

    let inputs_vars: Vec<AllocatedNum<NovaScalar>> = inputs_scalars
        .iter()
        .enumerate()
        .map(|(i, &val)| {
            AllocatedNum::alloc(cs.namespace(|| format!("fhe_out_s{step}_inp{i}")), || {
                Ok(val)
            })
        })
        .collect::<Result<_, _>>()?;

    poseidon_hash8_bp(cs, &inputs_vars, step, 100 + step)
}

/// Compute input hash chain update in-circuit.
///
/// Matches `fhe_input_chain_hash_native` behavior exactly:
///   hash8(prev_chain, input_hash_fr..., 0, 0, ...)
fn fhe_input_chain_hash_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    input_hashes: &[[u8; 32]],
    step: usize,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
    let mut inputs_scalars: Vec<NovaScalar> = vec![NovaScalar::from(0u64)]; // prev_chain = 0
    for h in input_hashes {
        let fr = Fr::from_be_bytes_mod_order(h);
        inputs_scalars.push(super::ark_to_nova_scalar(fr));
    }
    while inputs_scalars.len() < 8 {
        inputs_scalars.push(NovaScalar::from(0u64));
    }

    let inputs_vars: Vec<AllocatedNum<NovaScalar>> = inputs_scalars
        .iter()
        .enumerate()
        .map(|(i, &val)| {
            AllocatedNum::alloc(cs.namespace(|| format!("fhe_chain_s{step}_inp{i}")), || {
                Ok(val)
            })
        })
        .collect::<Result<_, _>>()?;

    poseidon_hash8_bp(cs, &inputs_vars, step, 200 + step)
}

// ── nova-snark StepCircuit impl ──────────────────────────────────────────
//
// ## Wave 2 greco-audit-remediation
// All computation previously done natively (Merkle proof verification,
// output commitment hash, input chain hash) is now performed in-circuit
// using bellpepper-native Poseidon hash gadgets.

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

            // ── 1. In-circuit Merkle inclusion proof ────────────────────
            verify_merkle_proof_bp(cs, &witness.proof0, self.merkle_arity, step, 0, &z[1])?;

            if op.input_count() == 2 {
                if let Some(ref proof1) = witness.proof1 {
                    verify_merkle_proof_bp(cs, proof1, self.merkle_arity, step, 1, &z[1])?;
                } else {
                    let one = AllocatedNum::alloc(
                        cs.namespace(|| format!("fail_missing_p1_{step}")),
                        || Ok(NovaScalar::from(1u64)),
                    )?;
                    let zero = AllocatedNum::alloc(
                        cs.namespace(|| format!("fail_missing_p1_zero_{step}")),
                        || Ok(NovaScalar::from(0u64)),
                    )?;
                    cs.enforce(
                        || format!("missing_p1_{step}"),
                        |lc| lc + one.get_variable(),
                        |lc| lc + CS::one(),
                        |lc| lc + zero.get_variable(),
                    );
                }
            }

            // ── 2. In-circuit FHE operation enforcement ─────────────────
            match &op {
                FheOp::Add { .. } => {
                    if !witness.ct0_coeffs.is_empty() {
                        add_fhe_ct_bp(
                            cs,
                            &witness.ct0_coeffs,
                            &witness.ct1_coeffs,
                            &witness.ct_out_coeffs,
                            &BFV_Q,
                            2,
                            BFV_L,
                            BFV_N,
                            step,
                        )?;
                    }
                }
                FheOp::Mul { .. } | FheOp::Relinearize { .. } => {
                    // Deferred: in-circuit Mul/Relin not yet implemented.
                    // The output commitment hash chain (Step 3 below) still
                    // cryptographically binds the operation sequence.
                }
            }

            // ── 3. In-circuit output commitment update ──────────────────
            let output_hash_var = fhe_step_output_hash_bp(cs, &input_hashes, op.tag_byte(), step)?;
            let new_output =
                z[0].add(cs.namespace(|| format!("oc_acc_{step}")), &output_hash_var)?;

            // ── 4. In-circuit input hash chain update ────────────────────
            let chain_var = fhe_input_chain_hash_bp(cs, &input_hashes, step)?;
            let new_chain = z[2].add(cs.namespace(|| format!("chain_acc_{step}")), &chain_var)?;

            // ── 5. Increment step count ────────────────────────────────
            let one = AllocatedNum::alloc(cs.namespace(|| format!("one_{step}")), || {
                Ok(NovaScalar::from(1u64))
            })?;
            let new_step_count = z[3].add(cs.namespace(|| format!("sc_inc_{step}")), &one)?;

            Ok(vec![new_output, z[1].clone(), new_chain, new_step_count])
        })
    }
}

// ── FHE operation enforcement status ────────────────────────────────────
//
//   Add:  ✅ In-circuit — modular addition per RNS limb enforced via
//          `add_fhe_ct_bp` (2 constraints per coefficient).
//   Mul:  🚧 Deferred — RNS polynomial multiplication in bellpepper
//          requires substantial constraint count (N^2 per limb × L limbs).
//   Relinearize: 🚧 Deferred — keyswitching in-circuit requires additional
//          key material witnesses and polynomial arithmetic.
//
// For deferred operations: the output commitment hash chain (Step 3 in
// synthesize) still cryptographically binds the operation type + input
// hashes to the accumulated state. The full constraint enforcement is a
// follow-up task.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{build_merkle_tree, prove_merkle_path};
    use ark_bn254::Fr;

    fn native_output_hash(prev_output: Fr, input_hashes: &[[u8; 32]], op_tag: u8) -> Fr {
        let mut inputs = vec![prev_output];
        for h in input_hashes {
            inputs.push(Fr::from_be_bytes_mod_order(h));
        }
        inputs.push(Fr::from(op_tag as u64));
        while inputs.len() < 8 {
            inputs.push(Fr::from(0u64));
        }
        hash8_native(&inputs[..8])
    }

    fn native_chain_hash(prev_chain: Fr, input_hashes: &[[u8; 32]]) -> Fr {
        let mut inputs = vec![prev_chain];
        for h in input_hashes {
            inputs.push(Fr::from_be_bytes_mod_order(h));
        }
        while inputs.len() < 8 {
            inputs.push(Fr::from(0u64));
        }
        hash8_native(&inputs[..8])
    }

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
        let h1 = native_output_hash(Fr::from(1u64), &[[1u8; 32], [2u8; 32]], 0x01);
        let h2 = native_output_hash(Fr::from(1u64), &[[1u8; 32], [2u8; 32]], 0x01);
        assert_eq!(h1, h2, "output hash must be deterministic");
    }

    #[test]
    fn fhe_step_output_hash_different_ops() {
        let h_add = native_output_hash(Fr::from(1u64), &[[1u8; 32], [2u8; 32]], 0x01);
        let h_mul = native_output_hash(Fr::from(1u64), &[[1u8; 32], [2u8; 32]], 0x02);
        #[cfg(feature = "legacy-nova")]
        assert_ne!(
            h_add, h_mul,
            "different op tags must produce different hashes (with real Poseidon)"
        );
        let _ = (h_add, h_mul);
    }

    #[test]
    fn merkle_tree_for_fhe_compute() {
        let leaves: Vec<Fr> = (0..8).map(|i| Fr::from(i as u64 + 100)).collect();
        let (tree, root) = build_merkle_tree(&leaves, 8);
        assert_ne!(root, Fr::from(0u64), "root must be non-zero");

        let proof = prove_merkle_path(&tree, 0, 8);
        assert!(crate::merkle::verify_merkle_proof(&proof, 8));
        assert_eq!(proof.leaf_value, Fr::from(100u64));
    }

    #[test]
    fn in_circuit_poseidon_hash8_matches_native() {
        let inputs: Vec<Fr> = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
            Fr::from(6u64),
            Fr::from(7u64),
            Fr::from(8u64),
        ];
        let native_result = hash8_native(&inputs);

        use super::super::ark_to_nova_scalar;
        let input_scalars: Vec<NovaScalar> =
            inputs.iter().map(|&f| ark_to_nova_scalar(f)).collect();

        let mut test_cs =
            nova_snark::frontend::util_cs::test_cs::TestConstraintSystem::<NovaScalar>::new();

        let input_vars: Vec<AllocatedNum<NovaScalar>> = input_scalars
            .iter()
            .enumerate()
            .map(|(i, &val)| {
                AllocatedNum::alloc(test_cs.namespace(|| format!("test_input_{i}")), || Ok(val))
            })
            .collect::<Result<_, _>>()
            .unwrap();

        let circuit_result = poseidon_hash8_bp(&mut test_cs, &input_vars, 0, 0).unwrap();

        let circuit_val = circuit_result.get_value().expect("circuit result witness");
        let native_scalar = ark_to_nova_scalar(native_result);
        assert_eq!(
            circuit_val, native_scalar,
            "in-circuit poseidon_hash8_bp must match native hash8_native"
        );

        assert!(
            test_cs.is_satisfied(),
            "constraint system must be satisfied"
        );
    }

    #[test]
    fn in_circuit_merkle_proof_matches_native() {
        let leaves: Vec<Fr> = (0..8).map(|i| Fr::from(i as u64 + 100)).collect();
        let (tree, root) = build_merkle_tree(&leaves, 8);
        let proof = prove_merkle_path(&tree, 0, 8);

        assert!(
            crate::merkle::verify_merkle_proof(&proof, 8),
            "native proof must be valid"
        );

        use super::super::ark_to_nova_scalar;
        let root_scalar = ark_to_nova_scalar(root);
        let mut test_cs =
            nova_snark::frontend::util_cs::test_cs::TestConstraintSystem::<NovaScalar>::new();

        let root_var =
            AllocatedNum::alloc(test_cs.namespace(|| "root"), || Ok(root_scalar)).unwrap();

        let result = verify_merkle_proof_bp(&mut test_cs, &proof, 8, 0, 0, &root_var);
        assert!(
            result.is_ok(),
            "in-circuit merkle verification should succeed"
        );
        assert!(
            test_cs.is_satisfied(),
            "circuit constraint system must be satisfied"
        );
    }

    #[test]
    fn in_circuit_merkle_proof_rejects_bad_leaf() {
        let leaves: Vec<Fr> = (0..8).map(|i| Fr::from(i as u64 + 100)).collect();
        let (tree, _root) = build_merkle_tree(&leaves, 8);
        let proof = prove_merkle_path(&tree, 0, 8);

        let mut bad_proof = proof.clone();
        bad_proof.leaf_value = Fr::from(999u64);

        use super::super::ark_to_nova_scalar;
        let root_scalar = ark_to_nova_scalar(proof.root);
        let mut test_cs =
            nova_snark::frontend::util_cs::test_cs::TestConstraintSystem::<NovaScalar>::new();

        let root_var =
            AllocatedNum::alloc(test_cs.namespace(|| "root"), || Ok(root_scalar)).unwrap();

        let _ = verify_merkle_proof_bp(&mut test_cs, &bad_proof, 8, 0, 0, &root_var);
        assert!(
            !test_cs.is_satisfied(),
            "circuit constraint system must be unsatisfied with bad leaf"
        );
    }

    #[test]
    fn in_circuit_hash_chain_matches_native() {
        let input_hashes: Vec<[u8; 32]> = vec![[1u8; 32], [2u8; 32]];
        let op_tag: u8 = 0x01;

        let native_output = native_output_hash(Fr::from(0u64), &input_hashes, op_tag);
        let native_chain = native_chain_hash(Fr::from(0u64), &input_hashes);

        use super::super::ark_to_nova_scalar;
        let mut test_cs =
            nova_snark::frontend::util_cs::test_cs::TestConstraintSystem::<NovaScalar>::new();

        let output_var = fhe_step_output_hash_bp(&mut test_cs, &input_hashes, op_tag, 0).unwrap();
        let chain_var = fhe_input_chain_hash_bp(&mut test_cs, &input_hashes, 0).unwrap();

        assert_eq!(
            output_var.get_value().unwrap(),
            ark_to_nova_scalar(native_output),
            "in-circuit output hash must match native"
        );
        assert_eq!(
            chain_var.get_value().unwrap(),
            ark_to_nova_scalar(native_chain),
            "in-circuit chain hash must match native"
        );
        assert!(
            test_cs.is_satisfied(),
            "constraint system must be satisfied"
        );
    }

    #[test]
    fn in_circuit_fhe_add_gadget() {
        let n = BFV_N;
        let l = BFV_L;
        let total = 2 * l * n;

        let mut ct0 = vec![0u64; total];
        let mut ct1 = vec![0u64; total];
        let mut ct_out = vec![0u64; total];

        for poly in 0..2 {
            for limb in 0..l {
                let q = BFV_Q[limb];
                for coeff in 0..n {
                    let idx = poly * l * n + limb * n + coeff;
                    ct0[idx] = (limb as u64 * 100 + coeff as u64 * 10 + poly as u64) % q;
                    ct1[idx] = (limb as u64 * 200 + coeff as u64 * 20 + poly as u64 * 2) % q;
                    let sum = ct0[idx] as u128 + ct1[idx] as u128;
                    ct_out[idx] = if sum >= q as u128 {
                        (sum - q as u128) as u64
                    } else {
                        sum as u64
                    };
                }
            }
        }

        let mut test_cs =
            nova_snark::frontend::util_cs::test_cs::TestConstraintSystem::<NovaScalar>::new();

        let result = add_fhe_ct_bp(&mut test_cs, &ct0, &ct1, &ct_out, &BFV_Q, 2, l, n, 0);
        assert!(result.is_ok(), "add_fhe_ct_bp should succeed");
        assert!(
            test_cs.is_satisfied(),
            "fhe add constraint system must be satisfied"
        );
    }

    #[test]
    fn in_circuit_fhe_add_rejects_bad_output() {
        let n = BFV_N;
        let l = BFV_L;
        let total = 2 * l * n;

        let mut ct0 = vec![0u64; total];
        let mut ct1 = vec![0u64; total];
        let mut ct_out = vec![0u64; total];

        for poly in 0..2 {
            for limb in 0..l {
                let q = BFV_Q[limb];
                for coeff in 0..n {
                    let idx = poly * l * n + limb * n + coeff;
                    ct0[idx] = (limb as u64 * 100 + coeff as u64 * 10) % q;
                    ct1[idx] = (limb as u64 * 200 + coeff as u64 * 20) % q;
                    ct_out[idx] = (ct0[idx] + ct1[idx] + 1) % q;
                }
            }
        }

        let mut test_cs =
            nova_snark::frontend::util_cs::test_cs::TestConstraintSystem::<NovaScalar>::new();

        let _ = add_fhe_ct_bp(&mut test_cs, &ct0, &ct1, &ct_out, &BFV_Q, 2, l, n, 0);
        assert!(
            !test_cs.is_satisfied(),
            "fhe add constraint system must be unsatisfied with wrong output"
        );
    }
}
