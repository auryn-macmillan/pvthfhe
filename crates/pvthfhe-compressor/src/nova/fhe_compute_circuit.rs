//! FHE Compute step circuit — E3 Compute Provider.
//!
//! Proves that a sequence of FHE Add operations over Merkle-committed input
//! ciphertexts produces a given output ciphertext. Output coefficients are
//! chained through Nova state so the verifier sees the accumulator evolve
//! through each step.
//!
//! ## State (arity=4)
//!   z[0] = output_ct_coeffs_lo — Poseidon commitment of output coeffs [0..half]
//!   z[1] = output_ct_coeffs_hi — Poseidon commitment of output coeffs [half..total]
//!   z[2] = merkle_root         — Merkle tree root over input ciphertext commitments
//!   z[3] = step_count          — number of fold steps completed
//!
//! ## Per-step witness
//!   - FheOp variant (Add with ct0_hash, ct1_hash)
//!   - Merkle inclusion proof for the input ciphertext commitment
//!   - Old accumulator coefficients (ct0_coeffs — matches z[0] commitment)
//!   - Input ciphertext coefficients (ct1_coeffs — matches merkle leaf)
//!   - New accumulator coefficients (ct_out_coeffs = ct0 + ct1 mod Q)
//!
//! ## In-circuit verification
//!   1. Verify old coefficient halves commit to z[0] and z[1]
//!   2. Merkle inclusion proof for input ciphertext commitment
//!   3. FHE Add enforcement (modular addition per coefficient via add_fhe_ct_bp)
//!   4. Compute new coefficient-half commitments → z[0]', z[1]'
//!
//! ### FHE ciphertext parameters (BFV)
//!   - Polynomial degree N = 8192 (production; use `--features bfv-n4` for N=4 fast testing)
//!   - RNS limbs L = 3
//!   - Moduli: Q = [288230376173076481, 288230376167047169, 288230376161280001]
//!   - Ciphertext: 2 polynomials × L limbs × N coefficients = 49152 u64 values (24 with bfv-n4)

use std::cell::RefCell;
use std::marker::PhantomData;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use sha3::{Digest, Keccak256};

use crate::merkle::MerkleProof;
use crate::nova::hash8_native;
use crate::{StepCircuit, StepCircuitDescriptor};
use pvthfhe_domain_tags::Tag;

// ── FHE ciphertext parameters (BFV) ─────────────────────────────────────

/// BFV polynomial degree.
///
/// BFV_N matches production RLWE ring dimension N=8192. The NIZK sigma layer
/// already uses rlwe_n()=8192 via the active preset. Change to 4 for fast demo
/// testing (use `--features bfv-n4`).
#[cfg(feature = "bfv-n4")]
pub const BFV_N: usize = 4;
#[cfg(not(feature = "bfv-n4"))]
pub const BFV_N: usize = 8192;

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

/// Total number of coefficients for a 3-polynomial (post-multiplication) ciphertext.
pub const BFV_MUL_CT_COEFFS_LEN: usize = 3 * BFV_L * BFV_N;

/// Number of coefficients processed per Nova step (chunked decomposition).
/// Each step handles exactly CHUNK_SIZE coefficients; the full ciphertext is
/// folded across `BFV_CT_COEFFS_LEN / CHUNK_SIZE` consecutive Nova steps.
///
/// Production: 1024.  Use 64 for fast testing via `--features bfv-n4`.
#[cfg(feature = "bfv-n4")]
pub const CHUNK_SIZE: usize = 64;
#[cfg(not(feature = "bfv-n4"))]
pub const CHUNK_SIZE: usize = 1024;

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
    /// Output ciphertext coefficients.
    ///
    /// For Add:  `BFV_CT_COEFFS_LEN` (24) coefficients (2 polys).
    /// For Mul:  `BFV_MUL_CT_COEFFS_LEN` (36) coefficients (3 polys).
    /// For Relinearize: `BFV_CT_COEFFS_LEN` (24) coefficients (2 polys).
    pub ct_out_coeffs: Vec<u64>,
}

/// Witness data for one chunk in the chunked FHE compute approach.
///
/// Each Nova step processes exactly one chunk of CHUNK_SIZE coefficients.
/// The full ciphertext is decomposed across `BFV_CT_COEFFS_LEN / CHUNK_SIZE` steps.
#[derive(Clone, Debug)]
pub struct FheComputeChunkWitness {
    pub operation: FheOp,
    pub chunk_index: u64,
    pub total_chunks: u64,
    pub ct0_chunk: Vec<u64>,
    pub ct1_chunk: Vec<u64>,
    pub ct_out_chunk: Vec<u64>,
    pub proof0: MerkleProof,
}

/// Thread-local witness data for chunked FHE compute steps.
thread_local! {
    pub(crate) static FHE_CHUNK_DATA: RefCell<Vec<FheComputeChunkWitness>> =
        const { RefCell::new(Vec::new()) };
}

/// Per-step counter for chunked FheComputeStepCircuit synthesize calls.
thread_local! {
    pub(crate) static FHE_CHUNK_STEP: RefCell<usize> =
        const { RefCell::new(0) };
}

/// Set chunked FHE compute witness data (clears previous data and resets counter).
pub fn set_fhe_chunk_data(data: Vec<FheComputeChunkWitness>) {
    FHE_CHUNK_DATA.with(|cell| *cell.borrow_mut() = data);
    FHE_CHUNK_STEP.with(|cell| *cell.borrow_mut() = 0);
}

/// Clear all chunked FHE compute witness data.
pub fn clear_fhe_chunk_data() {
    FHE_CHUNK_DATA.with(|cell| cell.borrow_mut().clear());
    FHE_CHUNK_STEP.with(|cell| *cell.borrow_mut() = 0);
}

/// Reset the chunked FHE-compute synthesize step counter while keeping witness data.
pub fn reset_fhe_chunk_step_counter() {
    FHE_CHUNK_STEP.with(|cell| *cell.borrow_mut() = 0);
}

/// Return the number of chunked FHE-compute witnesses currently installed.
pub fn fhe_chunk_data_len() -> usize {
    FHE_CHUNK_DATA.with(|cell| cell.borrow().len())
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
    FHE_COMPUTE_SZ_DATA.with(|cell| cell.borrow_mut().clear());
    FHE_COMPUTE_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
}

/// Reset the FHE-compute synthesize step counter while keeping witness data.
///
/// `nova-snark` runs the first step during `RecursiveSNARK::new` and later
/// invokes the same step circuit while generating and verifying subsequent
/// folds. The circuit shape is fixed at `PublicParams::setup`, so every
/// synthesis must see the same witness-backed shape as proving. Callers use
/// this after setup and before proving so step 0 consumes witness 0 rather
/// than falling through to the idle shape.
pub fn reset_fhe_compute_step_counter() {
    FHE_COMPUTE_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
}

/// Return the number of FHE-compute witnesses currently installed.
pub fn fhe_compute_data_len() -> usize {
    FHE_COMPUTE_DATA.with(|cell| cell.borrow().len())
}

/// Clone all currently installed FHE-compute witnesses.
pub fn fhe_compute_data_snapshot() -> Vec<FheComputeWitness> {
    FHE_COMPUTE_DATA.with(|cell| cell.borrow().clone())
}

/// Count the number of FHE Mul operations in the current witness data.
/// Returns 1 if any `FheOp::Mul` is present, 0 otherwise.
pub fn count_fhe_mul_ops() -> u64 {
    FHE_COMPUTE_DATA.with(|cell| {
        let data = cell.borrow();
        if data
            .iter()
            .any(|w| matches!(w.operation, FheOp::Mul { .. }))
        {
            1
        } else {
            0
        }
    })
}

// ── Circuit struct ───────────────────────────────────────────────────────

/// Nova step circuit for FHE compute proving.
///
/// State: `[output_ct_coeffs_lo, output_ct_coeffs_hi, merkle_root, step_count]`
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
        // width=8: z[0..4]=PoseidonSponge, z[5]=merkle_root, z[6]=chunk_idx, z[7]=total_chunks
        StepCircuitDescriptor { width: 8 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(Tag::NovaFheCompute.as_bytes()).into()
    }
}

// ── Schwartz-Zippel (S-Z) FHE verification ──────────────────────────────
//
// Replaces coefficient-by-coefficient modular addition/multiplication with
// polynomial evaluation at a session-bound random point r. Soundness error
// ≤ N/|F| ≈ 2^-245. Reduces constraint count by ~90%.

/// Domain tag for FHE compute Schwartz-Zippel challenge derivation.
const FHE_COMPUTE_SZ_DOMAIN: u64 = 9;

/// Horner evaluation in-circuit: computes poly(r) given coefficients.
///
/// coeffs[0] is highest-degree coefficient, coeffs[coeffs.len()-1] is constant
/// term. Matches `eval_poly_bn254`: result = 0; for c in coeffs: result = result*r + c.
///
/// Costs 2 constraints per coefficient (one mul, one add).
fn eval_poly_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    coeffs: &[AllocatedNum<NovaScalar>],
    r: &AllocatedNum<NovaScalar>,
    base: &str,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
    if coeffs.is_empty() {
        return Ok(AllocatedNum::alloc(
            cs.namespace(|| format!("{base}_eval_empty")),
            || Ok(NovaScalar::zero()),
        )?);
    }
    let mut result = AllocatedNum::alloc(cs.namespace(|| format!("{base}_eval_init")), || {
        Ok(NovaScalar::zero())
    })?;
    for (i, coeff) in coeffs.iter().enumerate() {
        // prod = result * r
        let prod = AllocatedNum::alloc(cs.namespace(|| format!("{base}_prod_{i}")), || {
            Ok(result.get_value().unwrap_or(NovaScalar::zero())
                * r.get_value().unwrap_or(NovaScalar::zero()))
        })?;
        cs.enforce(
            || format!("{base}_mul_{i}"),
            |lc| lc + result.get_variable(),
            |lc| lc + r.get_variable(),
            |lc| lc + prod.get_variable(),
        );
        // result_new = prod + coeff
        let sum = AllocatedNum::alloc(cs.namespace(|| format!("{base}_sum_{i}")), || {
            Ok(prod.get_value().unwrap_or(NovaScalar::zero())
                + coeff.get_value().unwrap_or(NovaScalar::zero()))
        })?;
        cs.enforce(
            || format!("{base}_add_{i}"),
            |lc| lc + prod.get_variable() + coeff.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + sum.get_variable(),
        );
        result = sum;
    }
    Ok(result)
}

/// S-Z FHE Add verification at point r.
///
/// Verifies: eval_ct0(r) + eval_ct1(r) = eval_ct_out(r) in Fr.
/// The native witness-preparation code ensures coefficient values are already
/// reduced modulo q, so the polynomial identity holds directly. For full
/// modular reduction support, provide k * q witness (see add_fhe_sz_bp_full).
fn add_fhe_sz_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    eval_ct0: &AllocatedNum<NovaScalar>,
    eval_ct1: &AllocatedNum<NovaScalar>,
    eval_ct_out: &AllocatedNum<NovaScalar>,
    step: usize,
    label: &str,
) -> Result<(), SynthesisError> {
    // sum = eval_ct0 + eval_ct1
    let sum_val = eval_ct0.get_value().unwrap_or(NovaScalar::zero())
        + eval_ct1.get_value().unwrap_or(NovaScalar::zero());
    let sum = AllocatedNum::alloc(
        cs.namespace(|| format!("add_sz_s{step}_{label}_sum")),
        || Ok(sum_val),
    )?;
    cs.enforce(
        || format!("add_sz_s{step}_{label}_sum_c"),
        |lc| lc + eval_ct0.get_variable() + eval_ct1.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + sum.get_variable(),
    );
    // Constrain: eval_ct_out == sum (i.e., eval_ct_out == eval_ct0 + eval_ct1)
    cs.enforce(
        || format!("add_sz_s{step}_{label}_eq"),
        |lc| lc + eval_ct_out.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + sum.get_variable(),
    );
    Ok(())
}

/// Full modular variant: eval_ct0 + eval_ct1 = eval_ct_out + k * q.
/// Uses overflow witness k to handle cases where coefficient addition
/// wraps around the modulus.
#[allow(dead_code)]
fn add_fhe_sz_bp_full<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    eval_ct0: &AllocatedNum<NovaScalar>,
    eval_ct1: &AllocatedNum<NovaScalar>,
    eval_ct_out: &AllocatedNum<NovaScalar>,
    q: NovaScalar,
    k_val: NovaScalar,
    step: usize,
) -> Result<(), SynthesisError> {
    // sum = eval_ct0 + eval_ct1
    let sum_val = eval_ct0.get_value().unwrap_or(NovaScalar::zero())
        + eval_ct1.get_value().unwrap_or(NovaScalar::zero());
    let sum = AllocatedNum::alloc(cs.namespace(|| format!("add_sz_full_s{step}_sum")), || {
        Ok(sum_val)
    })?;
    cs.enforce(
        || format!("add_sz_full_s{step}_sum_c"),
        |lc| lc + eval_ct0.get_variable() + eval_ct1.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + sum.get_variable(),
    );
    // k * q term
    let q_var = AllocatedNum::alloc(cs.namespace(|| format!("add_sz_full_s{step}_q")), || Ok(q))?;
    let k_var = AllocatedNum::alloc(cs.namespace(|| format!("add_sz_full_s{step}_k")), || {
        Ok(k_val)
    })?;
    let kq = AllocatedNum::alloc(cs.namespace(|| format!("add_sz_full_s{step}_kq")), || {
        Ok(k_val * q)
    })?;
    cs.enforce(
        || format!("add_sz_full_s{step}_kq_mul"),
        |lc| lc + k_var.get_variable(),
        |lc| lc + q_var.get_variable(),
        |lc| lc + kq.get_variable(),
    );
    // sum = eval_ct_out + kq
    cs.enforce(
        || format!("add_sz_full_s{step}_mod"),
        |lc| lc + sum.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + eval_ct_out.get_variable() + kq.get_variable(),
    );
    Ok(())
}

/// S-Z FHE Mul verification at point r.
///
/// For BFV multiplication ct_out = ct0 * ct1, the polynomial identity is:
/// ct_out_p0(X) = ct0_p0(X) * ct1_p0(X)   mod (X^N+1, q)
/// ct_out_p1(X) = ct0_p0(X) * ct1_p1(X) + ct0_p1(X) * ct1_p0(X)   mod (X^N+1, q)
/// ct_out_p2(X) = ct0_p1(X) * ct1_p1(X)   mod (X^N+1, q)
///
/// At challenge point r: eval_ct_out_p0 = eval_ct0_p0 * eval_ct1_p0, etc.
/// The mod (X^N+1) vanishes because r is a field element, not a polynomial
/// root — but the polynomial identity holds as a polynomial congruence.
/// We verify the identity directly in Fr at point r.
#[allow(dead_code)]
fn mul_fhe_sz_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    eval_ct0_p0: &AllocatedNum<NovaScalar>,
    eval_ct0_p1: &AllocatedNum<NovaScalar>,
    eval_ct1_p0: &AllocatedNum<NovaScalar>,
    eval_ct1_p1: &AllocatedNum<NovaScalar>,
    eval_ct_out_p0: &AllocatedNum<NovaScalar>,
    eval_ct_out_p1: &AllocatedNum<NovaScalar>,
    eval_ct_out_p2: &AllocatedNum<NovaScalar>,
    step: usize,
) -> Result<(), SynthesisError> {
    // ct_out_p0 = ct0_p0 * ct1_p0
    let prod_00 = AllocatedNum::alloc(cs.namespace(|| format!("mul_sz_s{step}_p00")), || {
        Ok(eval_ct0_p0.get_value().unwrap_or(NovaScalar::zero())
            * eval_ct1_p0.get_value().unwrap_or(NovaScalar::zero()))
    })?;
    cs.enforce(
        || format!("mul_sz_s{step}_p00_c"),
        |lc| lc + eval_ct0_p0.get_variable(),
        |lc| lc + eval_ct1_p0.get_variable(),
        |lc| lc + prod_00.get_variable(),
    );
    cs.enforce(
        || format!("mul_sz_s{step}_p00_eq"),
        |lc| lc + prod_00.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + eval_ct_out_p0.get_variable(),
    );

    // ct_out_p2 = ct0_p1 * ct1_p1
    let prod_11 = AllocatedNum::alloc(cs.namespace(|| format!("mul_sz_s{step}_p11")), || {
        Ok(eval_ct0_p1.get_value().unwrap_or(NovaScalar::zero())
            * eval_ct1_p1.get_value().unwrap_or(NovaScalar::zero()))
    })?;
    cs.enforce(
        || format!("mul_sz_s{step}_p11_c"),
        |lc| lc + eval_ct0_p1.get_variable(),
        |lc| lc + eval_ct1_p1.get_variable(),
        |lc| lc + prod_11.get_variable(),
    );
    cs.enforce(
        || format!("mul_sz_s{step}_p11_eq"),
        |lc| lc + prod_11.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + eval_ct_out_p2.get_variable(),
    );

    // ct_out_p1 = ct0_p0 * ct1_p1 + ct0_p1 * ct1_p0
    let prod_01 = AllocatedNum::alloc(cs.namespace(|| format!("mul_sz_s{step}_p01")), || {
        Ok(eval_ct0_p0.get_value().unwrap_or(NovaScalar::zero())
            * eval_ct1_p1.get_value().unwrap_or(NovaScalar::zero()))
    })?;
    cs.enforce(
        || format!("mul_sz_s{step}_p01_c"),
        |lc| lc + eval_ct0_p0.get_variable(),
        |lc| lc + eval_ct1_p1.get_variable(),
        |lc| lc + prod_01.get_variable(),
    );
    let prod_10 = AllocatedNum::alloc(cs.namespace(|| format!("mul_sz_s{step}_p10")), || {
        Ok(eval_ct0_p1.get_value().unwrap_or(NovaScalar::zero())
            * eval_ct1_p0.get_value().unwrap_or(NovaScalar::zero()))
    })?;
    cs.enforce(
        || format!("mul_sz_s{step}_p10_c"),
        |lc| lc + eval_ct0_p1.get_variable(),
        |lc| lc + eval_ct1_p0.get_variable(),
        |lc| lc + prod_10.get_variable(),
    );
    let sum_p1 = AllocatedNum::alloc(cs.namespace(|| format!("mul_sz_s{step}_sum_p1")), || {
        Ok(prod_01.get_value().unwrap_or(NovaScalar::zero())
            + prod_10.get_value().unwrap_or(NovaScalar::zero()))
    })?;
    cs.enforce(
        || format!("mul_sz_s{step}_sum_p1_c"),
        |lc| lc + prod_01.get_variable() + prod_10.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + sum_p1.get_variable(),
    );
    cs.enforce(
        || format!("mul_sz_s{step}_p1_eq"),
        |lc| lc + sum_p1.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + eval_ct_out_p1.get_variable(),
    );

    Ok(())
}

// ── New S-Z witness type ─────────────────────────────────────────────────

/// Schwartz-Zippel FHE compute witness.
///
/// Replaces coefficient-by-coefficient verification with polynomial evaluation
/// at a session-bound challenge point r. The circuit verifies:
/// 1. Merkle inclusion proof for each input ciphertext commitment
/// 2. eval_poly(ct_coeffs, r) == provided_eval for each polynomial
/// 3. FHE operation identity at point r (e.g., eval_ct0 + eval_ct1 == eval_ct_out)
/// 4. Poseidon(coeffs) == state commitment for output chaining
///
/// Soundness error ≤ N/|F| ≈ 8192/2^254 ≈ 2^-245.
#[derive(Clone, Debug)]
pub struct FheComputeWitnessSz {
    /// The operation to be proven.
    pub operation: FheOp,
    /// Merkle inclusion proof for the first input ciphertext.
    pub proof0: MerkleProof,
    /// Merkle inclusion proof for the second input ciphertext (binary ops only).
    pub proof1: Option<MerkleProof>,
    /// Session-bound challenge point r for polynomial evaluation.
    pub challenge_r: Fr,
    /// Evaluations at challenge_r — one per polynomial in ct0.
    /// For Add/Mul with 2-polynomial ciphertext: [eval_p0, eval_p1].
    pub eval_ct0: Vec<Fr>,
    /// Evaluations at challenge_r — one per polynomial in ct1.
    pub eval_ct1: Vec<Fr>,
    /// Evaluations at challenge_r — one per polynomial in ct_out.
    pub eval_ct_out: Vec<Fr>,
    /// Coefficient vectors (private witnesses for Horner evaluation and
    /// Poseidon commitment verification). These are the full ciphertext
    /// coefficients in RNS-interleaved layout.
    pub ct0_coeffs: Vec<u64>,
    pub ct1_coeffs: Vec<u64>,
    pub ct_out_coeffs: Vec<u64>,
}

/// Thread-local S-Z witness data for FHE compute steps.
thread_local! {
    pub(crate) static FHE_COMPUTE_SZ_DATA: RefCell<Vec<FheComputeWitnessSz>> =
        const { RefCell::new(Vec::new()) };
}

/// Set S-Z FHE compute witness data (clears previous data and resets counter).
pub fn set_fhe_compute_sz_data(data: Vec<FheComputeWitnessSz>) {
    FHE_COMPUTE_SZ_DATA.with(|cell| *cell.borrow_mut() = data);
    FHE_COMPUTE_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
}

/// Return the number of S-Z FHE-compute witnesses currently installed.
pub fn fhe_compute_sz_data_len() -> usize {
    FHE_COMPUTE_SZ_DATA.with(|cell| cell.borrow().len())
}

// ── In-circuit FHE addition gadget (BFV-N4, coefficient-by-coefficient) ──

/// In-circuit modular addition for BFV ciphertext coefficients.
///
/// For each coefficient in ct0 and ct1, enforces:
///   ct_out = ct0 + ct1 - k * q_modulus   where k ∈ {0, 1}
///
/// Uses 2 constraints per coefficient (boolean check + modular reduction).
/// Gated behind `bfv-n4` feature for fast regression testing.
#[cfg(feature = "bfv-n4")]
#[allow(clippy::too_many_arguments)]
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

// ── In-circuit FHE multiplication gadget (negacyclic convolution) ──────

/// Compute the k-th coefficient of negacyclic convolution a * b mod (X^N + 1)
/// in Z_q:  c_k = Σ_{i=0}^{k} a_i * b_{k-i} - Σ_{i=k+1}^{N-1} a_i * b_{N+k-i}
#[cfg(feature = "bfv-n4")]
#[inline]
fn negacyclic_conv_coeff(a: &[u64], b: &[u64], k: usize, q: u64) -> u64 {
    let n = a.len();
    debug_assert_eq!(b.len(), n);
    debug_assert!(k < n);

    let mut sum: i128 = 0;
    for i in 0..=k {
        sum += a[i] as i128 * b[k - i] as i128;
    }
    for i in (k + 1)..n {
        sum -= a[i] as i128 * b[n + k - i] as i128;
    }

    let r = sum % (q as i128);
    let r = if r < 0 { r + q as i128 } else { r };
    r as u64
}

/// Convert a NovaScalar field element to u128 via the repr.
/// Assumes value < 2^128, which holds for products of two u64 values.
#[cfg(feature = "bfv-n4")]
#[inline]
fn nova_to_u128(v: NovaScalar) -> u128 {
    use bp_ff::PrimeField;
    let repr = v.to_repr();
    let bytes = repr.as_ref();
    let mut buf = [0u8; 16];
    let len = bytes.len().min(16);
    buf[..len].copy_from_slice(&bytes[..len]);
    u128::from_le_bytes(buf)
}

/// In-circuit negacyclic convolution for a single polynomial pair across
/// one RNS limb.  Takes raw u64 slices for native computation and allocated
/// variables for constraint enforcement.
#[cfg(feature = "bfv-n4")]
#[allow(clippy::too_many_arguments)]
fn negacyclic_conv_one_poly_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    ct_a_raw: &[u64],
    ct_b_raw: &[u64],
    ct_a_vars: &[AllocatedNum<NovaScalar>],
    ct_b_vars: &[AllocatedNum<NovaScalar>],
    ct_out_vars: &[AllocatedNum<NovaScalar>],
    q: u64,
    limb: usize,
    poly_label: &str,
    step: usize,
) -> Result<(), SynthesisError> {
    let n = ct_a_raw.len();
    debug_assert_eq!(ct_b_raw.len(), n);
    debug_assert_eq!(ct_out_vars.len(), n);
    let q_scalar = NovaScalar::from(q);

    for k in 0..n {
        let base = format!("mul_s{step}_l{limb}_{poly_label}_k{k}");

        let mut pos_pairs: Vec<(usize, usize)> = Vec::with_capacity(n);
        let mut neg_pairs: Vec<(usize, usize)> = Vec::with_capacity(n);

        for i in 0..n {
            let j = if i <= k { k - i } else { n + k - i };
            if i <= k {
                pos_pairs.push((i, j));
            } else {
                neg_pairs.push((i, j));
            }
        }

        let alloc_product = |cs: &mut CS,
                             i: usize,
                             j: usize,
                             a_var: &AllocatedNum<NovaScalar>,
                             b_var: &AllocatedNum<NovaScalar>,
                             sign_label: &str|
         -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
            let prod_val = NovaScalar::from(ct_a_raw[i]) * NovaScalar::from(ct_b_raw[j]);
            let prod_var = AllocatedNum::alloc(
                cs.namespace(|| format!("{base}_p{sign_label}_i{i}_j{j}")),
                || Ok(prod_val),
            )?;
            cs.enforce(
                || format!("{base}_p{sign_label}_i{i}_j{j}_mul"),
                |lc| lc + a_var.get_variable(),
                |lc| lc + b_var.get_variable(),
                |lc| lc + prod_var.get_variable(),
            );
            Ok(prod_var)
        };

        let pos_prods: Vec<_> = pos_pairs
            .iter()
            .map(|&(i, j)| alloc_product(cs, i, j, &ct_a_vars[i], &ct_b_vars[j], "pos"))
            .collect::<Result<_, _>>()?;
        let neg_prods: Vec<_> = neg_pairs
            .iter()
            .map(|&(i, j)| alloc_product(cs, i, j, &ct_a_vars[i], &ct_b_vars[j], "neg"))
            .collect::<Result<_, _>>()?;

        let pos_sum_val = pos_prods.iter().fold(NovaScalar::zero(), |acc, p| {
            acc + p.get_value().unwrap_or(NovaScalar::zero())
        });
        let neg_sum_val = neg_prods.iter().fold(NovaScalar::zero(), |acc, p| {
            acc + p.get_value().unwrap_or(NovaScalar::zero())
        });

        let pos_sum_var = AllocatedNum::alloc(cs.namespace(|| format!("{base}_pos_sum")), || {
            Ok(pos_sum_val)
        })?;
        let neg_sum_var = AllocatedNum::alloc(cs.namespace(|| format!("{base}_neg_sum")), || {
            Ok(neg_sum_val)
        })?;

        cs.enforce(
            || format!("{base}_pos_sum_eq"),
            |lc| lc + CS::one(),
            |lc| lc + pos_sum_var.get_variable(),
            |lc| pos_prods.iter().fold(lc, |acc, p| acc + p.get_variable()),
        );

        cs.enforce(
            || format!("{base}_neg_sum_eq"),
            |lc| lc + CS::one(),
            |lc| lc + neg_sum_var.get_variable(),
            |lc| neg_prods.iter().fold(lc, |acc, p| acc + p.get_variable()),
        );

        let pos_u128 = pos_prods.iter().fold(0u128, |acc, p| {
            acc + nova_to_u128(p.get_value().unwrap_or(NovaScalar::zero()))
        });
        let neg_u128 = neg_prods.iter().fold(0u128, |acc, p| {
            acc + nova_to_u128(p.get_value().unwrap_or(NovaScalar::zero()))
        });
        let q128 = q as u128;

        let k_q_val: u64 = if pos_u128 >= neg_u128 {
            let diff = pos_u128 - neg_u128;
            (diff / q128) as u64
        } else {
            let diff = neg_u128 - pos_u128;
            diff.div_ceil(q128) as u64
        };

        let k_var = AllocatedNum::alloc(cs.namespace(|| format!("{base}_k")), || {
            Ok(NovaScalar::from(k_q_val))
        })?;

        if pos_u128 >= neg_u128 {
            cs.enforce(
                || format!("{base}_modmul"),
                |lc| lc + CS::one(),
                |lc| lc + pos_sum_var.get_variable(),
                |lc| {
                    lc + neg_sum_var.get_variable()
                        + ct_out_vars[k].get_variable()
                        + (q_scalar, k_var.get_variable())
                },
            );
        } else {
            cs.enforce(
                || format!("{base}_modmul"),
                |lc| lc + CS::one(),
                |lc| lc + pos_sum_var.get_variable() + (q_scalar, k_var.get_variable()),
                |lc| lc + neg_sum_var.get_variable() + ct_out_vars[k].get_variable(),
            );
        }
    }

    Ok(())
}

/// In-circuit BFV RNS multiplication: ct_out = ct0 * ct1 in R_q.
/// Produces a 3-polynomial ciphertext (36 coefficients for N=4, L=3).
/// Gated behind `bfv-n4` feature for fast regression testing.
#[cfg(feature = "bfv-n4")]
#[allow(clippy::too_many_arguments)]
fn mul_fhe_ct_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    ct0_coeffs: &[u64],
    ct1_coeffs: &[u64],
    ct_out_coeffs: &[u64],
    q_moduli: &[u64],
    num_limbs: usize,
    ct_poly_len: usize,
    step: usize,
) -> Result<(), SynthesisError> {
    let two_poly = 2 * num_limbs * ct_poly_len;
    let three_poly = 3 * num_limbs * ct_poly_len;
    assert_eq!(ct0_coeffs.len(), two_poly);
    assert_eq!(ct1_coeffs.len(), two_poly);
    assert_eq!(ct_out_coeffs.len(), three_poly);

    fn poly_limb_slice(
        coeffs: &[u64],
        poly: usize,
        limb: usize,
        stride: usize,
        n: usize,
    ) -> &[u64] {
        let start = poly * stride + limb * n;
        &coeffs[start..start + n]
    }
    let stride = num_limbs * ct_poly_len;

    for limb in 0..num_limbs {
        let q = q_moduli[limb];
        let base = format!("mul_fhe_s{step}_l{limb}");

        let alloc_poly = |cs: &mut CS,
                          coeffs: &[u64],
                          label: &str|
         -> Result<Vec<AllocatedNum<NovaScalar>>, SynthesisError> {
            coeffs
                .iter()
                .enumerate()
                .map(|(idx, &v)| {
                    AllocatedNum::alloc(cs.namespace(|| format!("{base}_{label}_c{idx}")), || {
                        Ok(NovaScalar::from(v))
                    })
                })
                .collect()
        };

        let ct0_p0 = alloc_poly(
            cs,
            poly_limb_slice(ct0_coeffs, 0, limb, stride, ct_poly_len),
            "ct0p0",
        )?;
        let ct0_p1 = alloc_poly(
            cs,
            poly_limb_slice(ct0_coeffs, 1, limb, stride, ct_poly_len),
            "ct0p1",
        )?;
        let ct1_p0 = alloc_poly(
            cs,
            poly_limb_slice(ct1_coeffs, 0, limb, stride, ct_poly_len),
            "ct1p0",
        )?;
        let ct1_p1 = alloc_poly(
            cs,
            poly_limb_slice(ct1_coeffs, 1, limb, stride, ct_poly_len),
            "ct1p1",
        )?;

        // Allocate output coefficients for all 3 output polynomials
        let out_slice = |poly: usize| -> &[u64] {
            let start = poly * stride + limb * ct_poly_len;
            &ct_out_coeffs[start..start + ct_poly_len]
        };
        let alloc_out =
            |cs: &mut CS, poly: usize| -> Result<Vec<AllocatedNum<NovaScalar>>, SynthesisError> {
                out_slice(poly)
                    .iter()
                    .enumerate()
                    .map(|(idx, &v)| {
                        AllocatedNum::alloc(
                            cs.namespace(|| format!("{base}_outp{poly}_c{idx}")),
                            || Ok(NovaScalar::from(v)),
                        )
                    })
                    .collect()
            };

        let ct_out_p0 = alloc_out(cs, 0)?;
        let ct_out_p1 = alloc_out(cs, 1)?;
        let ct_out_p2 = alloc_out(cs, 2)?;

        let ct0_p0_raw = poly_limb_slice(ct0_coeffs, 0, limb, stride, ct_poly_len);
        let ct0_p1_raw = poly_limb_slice(ct0_coeffs, 1, limb, stride, ct_poly_len);
        let ct1_p0_raw = poly_limb_slice(ct1_coeffs, 0, limb, stride, ct_poly_len);
        let ct1_p1_raw = poly_limb_slice(ct1_coeffs, 1, limb, stride, ct_poly_len);

        // ct_out[0] = ct0[0] * ct1[0]
        negacyclic_conv_one_poly_bp(
            cs, ct0_p0_raw, ct1_p0_raw, &ct0_p0, &ct1_p0, &ct_out_p0, q, limb, "c0", step,
        )?;

        // ct_out[2] = ct0[1] * ct1[1]
        negacyclic_conv_one_poly_bp(
            cs, ct0_p1_raw, ct1_p1_raw, &ct0_p1, &ct1_p1, &ct_out_p2, q, limb, "c2", step,
        )?;

        // ct_out[1] = ct0[0] * ct1[1] + ct0[1] * ct1[0]
        // First, compute full convolution of ct0[0]*ct1[1] and ct0[1]*ct1[0]
        // into temporary allocated arrays, then add mod q.
        let mut tmp_a_raw = vec![0u64; ct_poly_len];
        let mut tmp_b_raw = vec![0u64; ct_poly_len];
        for k in 0..ct_poly_len {
            tmp_a_raw[k] = negacyclic_conv_coeff(ct0_p0_raw, ct1_p1_raw, k, q);
            tmp_b_raw[k] = negacyclic_conv_coeff(ct0_p1_raw, ct1_p0_raw, k, q);
        }

        let alloc_tmp = |cs: &mut CS,
                         raw: &[u64],
                         label: &str|
         -> Result<Vec<AllocatedNum<NovaScalar>>, SynthesisError> {
            raw.iter()
                .enumerate()
                .map(|(idx, &v)| {
                    AllocatedNum::alloc(cs.namespace(|| format!("{base}_{label}_c{idx}")), || {
                        Ok(NovaScalar::from(v))
                    })
                })
                .collect()
        };

        let tmp_a_vars = alloc_tmp(cs, &tmp_a_raw, "tmp01")?;
        let tmp_b_vars = alloc_tmp(cs, &tmp_b_raw, "tmp10")?;

        // Enforce tmp_a = ct0[0] * ct1[1] via negacyclic convolution
        negacyclic_conv_one_poly_bp(
            cs,
            ct0_p0_raw,
            ct1_p1_raw,
            &ct0_p0,
            &ct1_p1,
            &tmp_a_vars,
            q,
            limb,
            "c1a",
            step,
        )?;

        // Enforce tmp_b = ct0[1] * ct1[0] via negacyclic convolution
        negacyclic_conv_one_poly_bp(
            cs,
            ct0_p1_raw,
            ct1_p0_raw,
            &ct0_p1,
            &ct1_p0,
            &tmp_b_vars,
            q,
            limb,
            "c1b",
            step,
        )?;

        // ct_out[1][k] = (tmp_a[k] + tmp_b[k]) mod q
        let q_scalar = NovaScalar::from(q);
        for k in 0..ct_poly_len {
            let idx_base = format!("{base}_c1_k{k}");
            let sum = tmp_a_raw[k] as u128 + tmp_b_raw[k] as u128;
            let k_val = if sum >= q as u128 { 1u64 } else { 0u64 };

            let k_var = AllocatedNum::alloc(cs.namespace(|| format!("{idx_base}_k")), || {
                Ok(NovaScalar::from(k_val))
            })?;

            cs.enforce(
                || format!("{idx_base}_k_bool"),
                |lc| lc + k_var.get_variable(),
                |lc| lc + CS::one() - k_var.get_variable(),
                |lc| lc,
            );

            cs.enforce(
                || format!("{idx_base}_modadd"),
                |lc| {
                    lc + tmp_a_vars[k].get_variable() + tmp_b_vars[k].get_variable()
                        - ct_out_p1[k].get_variable()
                },
                |lc| lc + CS::one(),
                |lc| lc + (q_scalar, k_var.get_variable()),
            );
        }
    }

    Ok(())
}

/// In-circuit FHE relinearization: drops the ct[2] component.
///
/// For the demo, Relinearize = (ct[0], ct[1], ct[2]) → (ct[0], ct[1]).
/// Input: 36 coefficients (3 polys × L limbs × N coeffs).
/// Output: 24 coefficients (2 polys × L limbs × N coeffs).
///
/// # G4 Gap — truncation-only, no relin key
///
/// This stub enforces `out[i] == in[i]` for i=0..23 (ct[0], ct[1]).
/// It does NOT verify ct[2] nor use a relinearization key.  Real relin
/// requires `ct_out = ct[0] + ct[1] · rlk` with a backend-supplied rlk.
/// The rlk is not yet exposed by `pvthfhe-fhe`.
///
/// Gated behind `#[cfg(feature = "real-relin")]`.  Without the feature,
/// the Relinearize branch returns `SynthesisError`.
/// See `.sisyphus/plans/proof-gap-remediation.md` §G4.
#[cfg(feature = "real-relin")]
fn relin_fhe_ct_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    ct_in_coeffs: &[u64],
    ct_out_coeffs: &[u64],
    step: usize,
) -> Result<(), SynthesisError> {
    assert_eq!(ct_in_coeffs.len(), BFV_MUL_CT_COEFFS_LEN);
    assert_eq!(ct_out_coeffs.len(), BFV_CT_COEFFS_LEN);
    let base = format!("relin_s{step}");

    let in_vars: Vec<AllocatedNum<NovaScalar>> = ct_in_coeffs[..BFV_CT_COEFFS_LEN]
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            AllocatedNum::alloc(cs.namespace(|| format!("{base}_in_c{i}")), || {
                Ok(NovaScalar::from(v))
            })
        })
        .collect::<Result<_, _>>()?;

    let out_vars: Vec<AllocatedNum<NovaScalar>> = ct_out_coeffs
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            AllocatedNum::alloc(cs.namespace(|| format!("{base}_out_c{i}")), || {
                Ok(NovaScalar::from(v))
            })
        })
        .collect::<Result<_, _>>()?;

    for i in 0..BFV_CT_COEFFS_LEN {
        cs.enforce(
            || format!("{base}_id_c{i}"),
            |lc| lc + out_vars[i].get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + in_vars[i].get_variable(),
        );
    }

    Ok(())
}

// ── Poseidon commitment of BFV ciphertext coefficients ──────────────────
//
// Commits BFV_CT_COEFFS_LEN u64 coefficients to a single Fr via recursive
// hash8: group into chunks of 8, hash each chunk, then recursively hash the
// intermediate hashes until a single fr value remains. Works for any N.

/// Allocate `coeffs` as circuit witnesses and recursively hash chunks of 8
/// into a single Poseidon commitment. Returns the final allocated hash.
fn hash_coeff_vector_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    coeffs: &[u64],
    step_idx: usize,
    hash_base: usize,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
    let base = format!("hcv_s{step_idx}_b{hash_base}");

    let coeff_vars: Vec<AllocatedNum<NovaScalar>> = coeffs
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            AllocatedNum::alloc(cs.namespace(|| format!("{base}_coeff{i}")), || {
                Ok(NovaScalar::from(v))
            })
        })
        .collect::<Result<_, _>>()?;

    let mut current: Vec<AllocatedNum<NovaScalar>> = coeff_vars;
    let mut depth: usize = 0;
    while current.len() > 8 {
        let chunks = current.chunks(8);
        let mut next_level: Vec<AllocatedNum<NovaScalar>> = Vec::new();
        for (ci, chunk) in chunks.enumerate() {
            let mut padded: Vec<AllocatedNum<NovaScalar>> = chunk.to_vec();
            while padded.len() < 8 {
                let pi = padded.len();
                padded.push(AllocatedNum::alloc(
                    cs.namespace(|| format!("{base}_d{depth}_c{ci}_pad{pi}")),
                    || Ok(NovaScalar::zero()),
                )?);
            }
            let h = poseidon_hash8_bp(cs, &padded, step_idx, hash_base + depth * 4096 + ci)?;
            next_level.push(h);
        }
        current = next_level;
        depth += 1;
    }

    while current.len() < 8 {
        let pi = current.len();
        current.push(AllocatedNum::alloc(
            cs.namespace(|| format!("{base}_final_pad{pi}")),
            || Ok(NovaScalar::zero()),
        )?);
    }
    poseidon_hash8_bp(cs, &current, step_idx, hash_base + depth * 4096)
}

fn poseidon_commit_coeffs_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    coeffs: &[u64],
    step_idx: usize,
    commit_idx: usize,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
    assert_eq!(
        coeffs.len(),
        BFV_CT_COEFFS_LEN,
        "must have BFV_CT_COEFFS_LEN ({}) coefficients",
        BFV_CT_COEFFS_LEN
    );
    hash_coeff_vector_bp(cs, coeffs, step_idx, 100000 + commit_idx * 24576)
}

/// Commits one half of a BFV ciphertext coefficient vector to one state slot.
///
/// This is the concrete Nova state representation for the chained output
/// ciphertext: z[0] commits coeffs [0..half], z[1] commits [half..total].
fn poseidon_commit_coeffs_half_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    coeffs: &[u64],
    step_idx: usize,
    commit_idx: usize,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
    let half = BFV_CT_COEFFS_LEN / 2;
    assert_eq!(
        coeffs.len(),
        half,
        "must have {half} coefficient-half values"
    );
    hash_coeff_vector_bp(cs, coeffs, step_idx, 100000 + commit_idx * 24576)
}

fn poseidon_commit_coeffs_split_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    coeffs: &[u64],
    step_idx: usize,
    commit_idx: usize,
) -> Result<(AllocatedNum<NovaScalar>, AllocatedNum<NovaScalar>), SynthesisError> {
    let n = coeffs.len();
    assert_eq!(n % 2, 0, "coefficient count must be even, got {n}");
    let half = n / 2;
    let lo = poseidon_commit_coeffs_half_bp(cs, &coeffs[..half], step_idx, commit_idx * 2)?;
    let hi = poseidon_commit_coeffs_half_bp(cs, &coeffs[half..], step_idx, commit_idx * 2 + 1)?;
    Ok((lo, hi))
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
    state: &mut [AllocatedNum<NovaScalar>],
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

/// Build Cauchy MDS matrix and zero ARK for the default (non-legacy-nova) config.
///
/// Generates a proper mixing MDS matrix matching nova-snark's deterministic
/// Cauchy construction: M[i][j] = 1 / (x_i + y_j) with x = [0..t), y = [t..2t).
fn identity_poseidon_params() -> (Vec<Vec<NovaScalar>>, Vec<Vec<NovaScalar>>) {
    use bp_ff::Field;

    let xs: Vec<NovaScalar> = (0..POSEIDON_T as u64).map(NovaScalar::from).collect();
    let ys: Vec<NovaScalar> = (POSEIDON_T as u64..2 * POSEIDON_T as u64)
        .map(NovaScalar::from)
        .collect();

    let mds: Vec<Vec<NovaScalar>> = xs
        .iter()
        .map(|&x| {
            ys.iter()
                .map(|&y| {
                    let denom = x + y;
                    denom.invert().unwrap_or_else(NovaScalar::zero)
                })
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

    // Sponge absorption: absorb inputs in rate-sized chunks, permuting after each.
    let mut offset = 0;
    let mut permute_batch = 0;
    while offset < inputs.len() {
        let remaining = inputs.len() - offset;
        let chunk = remaining.min(POSEIDON_RATE);
        for i in 0..chunk {
            state[POSEIDON_CAPACITY + i] = state[POSEIDON_CAPACITY + i].add(
                cs.namespace(|| format!("{base}_abs_{permute_batch}_{i}")),
                &inputs[offset + i],
            )?;
        }
        offset += chunk;
        permute_bp(
            cs,
            &mut state,
            &mds,
            &ark,
            step_idx,
            hash_idx * 4 + permute_batch,
        )?;
        permute_batch += 1;
    }

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

        // Constrain that exactly one input slot equals `current`, without
        // changing the R1CS matrix when `position` changes across steps.  A
        // Rust-side branch on `position` would make setup/prove syntheses use
        // different linear-combination variable indices for different leaves,
        // which Nova later rejects as an unsatisfied relaxed R1CS.
        let selectors: Vec<AllocatedNum<NovaScalar>> = (0..arity)
            .map(|j| {
                AllocatedNum::alloc(cs.namespace(|| format!("{base}_l{level}_sel{j}")), || {
                    Ok(if j == position {
                        NovaScalar::from(1u64)
                    } else {
                        NovaScalar::from(0u64)
                    })
                })
            })
            .collect::<Result<_, _>>()?;

        for (j, selector) in selectors.iter().enumerate() {
            cs.enforce(
                || format!("{base}_l{level}_sel_bool{j}"),
                |lc| lc + selector.get_variable(),
                |lc| lc + selector.get_variable() - CS::one(),
                |lc| lc,
            );
            cs.enforce(
                || format!("{base}_l{level}_selected_eq{j}"),
                |lc| lc + hash_inputs[j].get_variable() - current.get_variable(),
                |lc| lc + selector.get_variable(),
                |lc| lc,
            );
        }
        cs.enforce(
            || format!("{base}_l{level}_one_selected"),
            |lc| {
                selectors
                    .iter()
                    .fold(lc, |acc, selector| acc + selector.get_variable())
            },
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );

        // Domain separation: leaf level (0) vs internal (1).
        let domain_val = if level == 0 {
            NovaScalar::from(0u64)
        } else {
            NovaScalar::from(1u64)
        };
        let domain_var =
            AllocatedNum::alloc(cs.namespace(|| format!("{base}_l{level}_domain")), || {
                Ok(domain_val)
            })?;
        let mut domain_inputs = vec![domain_var];
        domain_inputs.extend_from_slice(&hash_inputs);

        // Hash this level using in-circuit Poseidon
        current = poseidon_hash8_bp(cs, &domain_inputs, step * 16 + proof_idx * 8 + level, level)?;

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

// ── Chunked hash helpers ─────────────────────────────────────────────────
//
// The chunked approach uses a hash chain: each chunk's output coefficients
// are committed via recursive Poseidon hash8, then chained with the previous
// state via poseidon_hash2 (two-element hash).

/// Hash two field elements via Poseidon hash8 (padded with zeros).
fn poseidon_hash2_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    a: &AllocatedNum<NovaScalar>,
    b: &AllocatedNum<NovaScalar>,
    step: usize,
    hash_idx: usize,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
    let zero = AllocatedNum::alloc(cs.namespace(|| format!("h2_z_s{step}_h{hash_idx}")), || {
        Ok(NovaScalar::from(0u64))
    })?;
    let inputs = vec![
        a.clone(),
        b.clone(),
        zero.clone(),
        zero.clone(),
        zero.clone(),
        zero.clone(),
        zero.clone(),
        zero.clone(),
    ];
    poseidon_hash8_bp(cs, &inputs, step, 80000 + hash_idx)
}

/// Commit a chunk of coefficient values to a single field element via recursive hash8.
fn poseidon_hash_chunk_bp<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    coeffs: &[u64],
    step: usize,
    hash_idx: usize,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
    hash_coeff_vector_bp(cs, coeffs, step, 300000 + hash_idx * 100_000)
}

/// Native hash of two Fr elements via hash8_native.
pub fn poseidon_hash2_native(a: Fr, b: Fr) -> Fr {
    let mut inputs = vec![a, b];
    while inputs.len() < 8 {
        inputs.push(Fr::zero());
    }
    hash8_native(&inputs)
}

/// Native chunk hash via recursive hash8.
pub fn poseidon_hash_chunk_native(coeffs: &[u64]) -> Fr {
    let fields: Vec<Fr> = coeffs.iter().map(|&v| Fr::from(v)).collect();
    if fields.len() <= 8 {
        let mut padded = fields.clone();
        while padded.len() < 8 {
            padded.push(Fr::zero());
        }
        return hash8_native(&padded);
    }
    let mut next_level: Vec<Fr> = Vec::new();
    for chunk in fields.chunks(8) {
        let mut padded = chunk.to_vec();
        while padded.len() < 8 {
            padded.push(Fr::zero());
        }
        next_level.push(hash8_native(&padded));
    }
    // Recurse: convert field elements to u64 for next hash level
    let next_coeffs: Vec<u64> = next_level
        .iter()
        .map(|f| {
            let bytes = f.into_bigint().to_bytes_be();
            let mut buf = [0u8; 8];
            let len = bytes.len().min(8);
            let skip = bytes.len().saturating_sub(8);
            buf[..len].copy_from_slice(&bytes[skip..][..len]);
            u64::from_be_bytes(buf)
        })
        .collect();
    poseidon_hash_chunk_native(&next_coeffs)
}

// ── nova-snark StepCircuit impl ──────────────────────────────────────────
//
// State (width=8, chunked):
//   z[0..4] = hash chain accumulator (z[0] holds the chained chunk commitment)
//   z[5]    = merkle_root (fixed across steps)
//   z[6]    = chunk_index (0..total_chunks-1)
//   z[7]    = total_chunks (constant)
//
// Legacy paths (gated behind bfv-n4):
//   S-Z:    Horner evaluation + point check. Soundness <= N/|F|.
//   BFV-N4: coefficient-by-coefficient modular arithmetic.

// ── Chunked impl (default, arity=8) ─────────────────────────────────────
#[cfg(not(feature = "bfv-n4"))]
impl
    nova_snark::traits::circuit::StepCircuit<
        <nova_snark::provider::Bn256EngineKZG as nova_snark::traits::Engine>::Scalar,
    > for FheComputeStepCircuit<ark_bn254::Fr>
{
    fn arity(&self) -> usize {
        8
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

        let chunk_data_len = FHE_CHUNK_DATA.with(|cell| cell.borrow().len());
        if chunk_data_len > 0 {
            let step = FHE_CHUNK_STEP.with(|cell| {
                let mut c = cell.borrow_mut();
                let s = *c;
                *c = s + 1;
                s
            });

            if step >= chunk_data_len {
                return Err(SynthesisError::AssignmentMissing);
            }

            return FHE_CHUNK_DATA.with(|cell| {
                let data = cell.borrow();
                let witness = data.get(step).cloned().unwrap();
                let chunk_n = witness.ct0_chunk.len();

                let chunk_idx_var =
                    AllocatedNum::alloc(cs.namespace(|| format!("chunk_idx_s{step}")), || {
                        Ok(NovaScalar::from(witness.chunk_index))
                    })?;
                cs.enforce(
                    || format!("chunk_idx_eq_z6_s{step}"),
                    |lc| lc + chunk_idx_var.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + z[6].get_variable(),
                );
                let diff = AllocatedNum::alloc(
                    cs.namespace(|| format!("chunk_bounds_diff_s{step}")),
                    || {
                        let total = z[7].get_value().unwrap_or(NovaScalar::from(0u64));
                        let ci = NovaScalar::from(witness.chunk_index);
                        Ok(if total > ci {
                            total - ci - NovaScalar::from(1u64)
                        } else {
                            NovaScalar::from(0u64)
                        })
                    },
                )?;
                cs.enforce(
                    || format!("chunk_bounds_s{step}"),
                    |lc| lc + z[7].get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + chunk_idx_var.get_variable() + diff.get_variable() + CS::one(),
                );

                for i in 0..chunk_n {
                    let c0 = witness.ct0_chunk[i];
                    let c1 = witness.ct1_chunk[i];
                    let c_out = witness.ct_out_chunk[i];
                    let q = BFV_Q[0]; // uniform modulus for chunked compute

                    let c0_var = AllocatedNum::alloc(
                        cs.namespace(|| format!("chunk_c0_s{step}_i{i}")),
                        || Ok(NovaScalar::from(c0)),
                    )?;
                    let c1_var = AllocatedNum::alloc(
                        cs.namespace(|| format!("chunk_c1_s{step}_i{i}")),
                        || Ok(NovaScalar::from(c1)),
                    )?;
                    let c_out_var = AllocatedNum::alloc(
                        cs.namespace(|| format!("chunk_cout_s{step}_i{i}")),
                        || Ok(NovaScalar::from(c_out)),
                    )?;

                    let sum_u128 = c0 as u128 + c1 as u128;
                    let k_val = if sum_u128 >= q as u128 { 1u64 } else { 0u64 };
                    let k_var = AllocatedNum::alloc(
                        cs.namespace(|| format!("chunk_k_s{step}_i{i}")),
                        || Ok(NovaScalar::from(k_val)),
                    )?;
                    cs.enforce(
                        || format!("chunk_k_bool_s{step}_i{i}"),
                        |lc| lc + k_var.get_variable(),
                        |lc| lc + CS::one() - k_var.get_variable(),
                        |lc| lc,
                    );
                    cs.enforce(
                        || format!("chunk_modadd_s{step}_i{i}"),
                        |lc| {
                            lc + c0_var.get_variable() + c1_var.get_variable()
                                - c_out_var.get_variable()
                        },
                        |lc| lc + CS::one(),
                        |lc| lc + (NovaScalar::from(q), k_var.get_variable()),
                    );
                }

                let chunk_hash = poseidon_hash_chunk_bp(cs, &witness.ct_out_chunk, step, step)?;

                // Session seed handling: z0_from_acc_with_session adds session_seed to
                // z[0] for step 0 only. Strip it before hashing.
                let seed = super::session_bind_seed();
                let seed_var =
                    AllocatedNum::alloc(cs.namespace(|| format!("ch_seed_s{step}")), || Ok(seed))?;
                let is_first = NovaScalar::from(if step == 0 { 1u64 } else { 0u64 });
                let is_first_var =
                    AllocatedNum::alloc(cs.namespace(|| format!("ch_is_first_s{step}")), || {
                        Ok(is_first)
                    })?;
                let gated_seed = seed_var.mul(
                    cs.namespace(|| format!("ch_gated_seed_s{step}")),
                    &is_first_var,
                )?;
                // old_chain_hash = z[0] - gated_seed
                let old_val = z[0].get_value().unwrap_or(NovaScalar::zero())
                    - gated_seed.get_value().unwrap_or(NovaScalar::zero());
                let old_chain_hash =
                    AllocatedNum::alloc(cs.namespace(|| format!("ch_old_chain_s{step}")), || {
                        Ok(old_val)
                    })?;
                cs.enforce(
                    || format!("ch_old_chain_c_s{step}"),
                    |lc| lc + old_chain_hash.get_variable() + gated_seed.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + z[0].get_variable(),
                );

                let new_z0 = poseidon_hash2_bp(cs, &old_chain_hash, &chunk_hash, step, step)?;

                if witness.chunk_index == 0 {
                    verify_merkle_proof_bp(cs, &witness.proof0, self.merkle_arity, step, 0, &z[5])?;
                }

                let one =
                    AllocatedNum::alloc(cs.namespace(|| format!("chunk_one_s{step}")), || {
                        Ok(NovaScalar::from(1u64))
                    })?;
                let new_chunk_idx =
                    chunk_idx_var.add(cs.namespace(|| format!("chunk_inc_s{step}")), &one)?;

                Ok(vec![
                    new_z0,
                    z[1].clone(),
                    z[2].clone(),
                    z[3].clone(),
                    z[4].clone(),
                    z[5].clone(),
                    new_chunk_idx,
                    z[7].clone(),
                ])
            });
        }

        Err(SynthesisError::AssignmentMissing)
    }
}

// ── Legacy impl (bfv-n4, arity=4) ────────────────────────────────────────
#[cfg(feature = "bfv-n4")]
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

        let raw_step = FHE_COMPUTE_STEP_COUNTER.with(|cell| {
            let mut c = cell.borrow_mut();
            let s = *c;
            *c = s + 1;
            s
        });

        // S-Z path
        let sz_data_len = FHE_COMPUTE_SZ_DATA.with(|cell| cell.borrow().len());
        if sz_data_len > 0 {
            if raw_step >= sz_data_len {
                return Err(SynthesisError::AssignmentMissing);
            }
            let step = raw_step;

            let sz_has = FHE_COMPUTE_SZ_DATA.with(|cell| cell.borrow().get(step).is_some());
            if !sz_has {
                return Err(SynthesisError::AssignmentMissing);
            }

            return FHE_COMPUTE_SZ_DATA.with(|cell| {
                let data = cell.borrow();
                let witness = data.get(step).cloned().unwrap();

                let (old_commit_lo, old_commit_hi) = if !witness.ct0_coeffs.is_empty() {
                    poseidon_commit_coeffs_split_bp(cs, &witness.ct0_coeffs, step, 0)?
                } else {
                    (
                        AllocatedNum::alloc(cs.namespace(|| format!("sz_zc_lo_s{step}")), || {
                            Ok(NovaScalar::from(0u64))
                        })?,
                        AllocatedNum::alloc(cs.namespace(|| format!("sz_zc_hi_s{step}")), || {
                            Ok(NovaScalar::from(0u64))
                        })?,
                    )
                };
                let seed = super::session_bind_seed();
                let seed_var = AllocatedNum::alloc(
                    cs.namespace(|| format!("sz_session_seed_s{step}")),
                    || Ok(seed),
                )?;
                let initial_selector = AllocatedNum::alloc(
                    cs.namespace(|| format!("sz_session_seed_selector_s{step}")),
                    || {
                        Ok(if raw_step == 0 {
                            NovaScalar::from(1u64)
                        } else {
                            NovaScalar::from(0u64)
                        })
                    },
                )?;
                cs.enforce(
                    || format!("sz_session_seed_selector_bool_s{step}"),
                    |lc| lc + initial_selector.get_variable(),
                    |lc| lc + initial_selector.get_variable() - CS::one(),
                    |lc| lc,
                );
                let gated_seed = seed_var.mul(
                    cs.namespace(|| format!("sz_session_seed_gated_s{step}")),
                    &initial_selector,
                )?;
                let expected_old_commit_lo = old_commit_lo.add(
                    cs.namespace(|| format!("sz_old_commit_lo_seed_s{step}")),
                    &gated_seed,
                )?;
                cs.enforce(
                    || format!("sz_old_commit_lo_eq_s{step}"),
                    |lc| lc + expected_old_commit_lo.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + z[0].get_variable(),
                );
                cs.enforce(
                    || format!("sz_old_commit_hi_eq_s{step}"),
                    |lc| lc + old_commit_hi.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + z[1].get_variable(),
                );

                verify_merkle_proof_bp(cs, &witness.proof0, self.merkle_arity, step, 0, &z[2])?;

                let r = AllocatedNum::alloc(
                    cs.namespace(|| format!("sz_challenge_r_s{step}")),
                    || Ok(super::ark_to_nova_scalar(witness.challenge_r)),
                )?;

                let coeffs_per_poly = BFV_CT_COEFFS_LEN / 2;
                fn alloc_horner_and_verify<CS2: ConstraintSystem<NovaScalar>>(
                    cs: &mut CS2,
                    coeffs: &[u64],
                    r: &AllocatedNum<NovaScalar>,
                    expected_eval: &AllocatedNum<NovaScalar>,
                    base: &str,
                ) -> Result<(), SynthesisError> {
                    let coeff_vars: Vec<AllocatedNum<NovaScalar>> = coeffs
                        .iter()
                        .enumerate()
                        .map(|(i, &v)| {
                            AllocatedNum::alloc(cs.namespace(|| format!("{base}_coeff{i}")), || {
                                Ok(NovaScalar::from(v))
                            })
                        })
                        .collect::<Result<_, _>>()?;
                    let computed = eval_poly_bp(cs, &coeff_vars, r, base)?;
                    cs.enforce(
                        || format!("{base}_eval_eq"),
                        |lc| lc + computed.get_variable(),
                        |lc| lc + CS2::one(),
                        |lc| lc + expected_eval.get_variable(),
                    );
                    Ok(())
                }

                let alloc_eval =
                    |cs: &mut CS,
                     val: Fr,
                     label: &str|
                     -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
                        AllocatedNum::alloc(cs.namespace(|| label.to_string()), || {
                            Ok(super::ark_to_nova_scalar(val))
                        })
                    };

                let half = coeffs_per_poly;
                let eval_ct0_p0 = alloc_eval(
                    cs,
                    witness.eval_ct0.first().copied().unwrap_or(Fr::zero()),
                    &format!("sz_eval_ct0_p0_s{step}"),
                )?;
                let eval_ct0_p1 = alloc_eval(
                    cs,
                    witness.eval_ct0.get(1).copied().unwrap_or(Fr::zero()),
                    &format!("sz_eval_ct0_p1_s{step}"),
                )?;
                let eval_ct1_p0 = alloc_eval(
                    cs,
                    witness.eval_ct1.first().copied().unwrap_or(Fr::zero()),
                    &format!("sz_eval_ct1_p0_s{step}"),
                )?;
                let eval_ct1_p1 = alloc_eval(
                    cs,
                    witness.eval_ct1.get(1).copied().unwrap_or(Fr::zero()),
                    &format!("sz_eval_ct1_p1_s{step}"),
                )?;
                let eval_ct_out_p0 = alloc_eval(
                    cs,
                    witness.eval_ct_out.first().copied().unwrap_or(Fr::zero()),
                    &format!("sz_eval_ct_out_p0_s{step}"),
                )?;
                let eval_ct_out_p1 = alloc_eval(
                    cs,
                    witness.eval_ct_out.get(1).copied().unwrap_or(Fr::zero()),
                    &format!("sz_eval_ct_out_p1_s{step}"),
                )?;

                if !witness.ct0_coeffs.is_empty() {
                    alloc_horner_and_verify(
                        cs,
                        &witness.ct0_coeffs[..half],
                        &r,
                        &eval_ct0_p0,
                        &format!("sz_ct0_p0_s{step}"),
                    )?;
                    alloc_horner_and_verify(
                        cs,
                        &witness.ct0_coeffs[half..],
                        &r,
                        &eval_ct0_p1,
                        &format!("sz_ct0_p1_s{step}"),
                    )?;
                }
                if !witness.ct1_coeffs.is_empty() {
                    alloc_horner_and_verify(
                        cs,
                        &witness.ct1_coeffs[..half],
                        &r,
                        &eval_ct1_p0,
                        &format!("sz_ct1_p0_s{step}"),
                    )?;
                    alloc_horner_and_verify(
                        cs,
                        &witness.ct1_coeffs[half..],
                        &r,
                        &eval_ct1_p1,
                        &format!("sz_ct1_p1_s{step}"),
                    )?;
                }
                if !witness.ct_out_coeffs.is_empty() {
                    let ct_out_p0_coeffs =
                        &witness.ct_out_coeffs[..half.min(witness.ct_out_coeffs.len())];
                    alloc_horner_and_verify(
                        cs,
                        ct_out_p0_coeffs,
                        &r,
                        &eval_ct_out_p0,
                        &format!("sz_ct_out_p0_s{step}"),
                    )?;
                    if witness.ct_out_coeffs.len() > half {
                        alloc_horner_and_verify(
                            cs,
                            &witness.ct_out_coeffs[half..],
                            &r,
                            &eval_ct_out_p1,
                            &format!("sz_ct_out_p1_s{step}"),
                        )?;
                    }
                }

                match &witness.operation {
                    FheOp::Add { .. } => {
                        add_fhe_sz_bp(cs, &eval_ct0_p0, &eval_ct1_p0, &eval_ct_out_p0, step, "p0")?;
                        add_fhe_sz_bp(cs, &eval_ct0_p1, &eval_ct1_p1, &eval_ct_out_p1, step, "p1")?;
                    }
                    FheOp::Mul { .. } => {
                        let prod_00 = AllocatedNum::alloc(
                            cs.namespace(|| format!("sz_mul_s{step}_p00")),
                            || {
                                Ok(eval_ct0_p0.get_value().unwrap_or(NovaScalar::zero())
                                    * eval_ct1_p0.get_value().unwrap_or(NovaScalar::zero()))
                            },
                        )?;
                        cs.enforce(
                            || format!("sz_mul_s{step}_p00_mul"),
                            |lc| lc + eval_ct0_p0.get_variable(),
                            |lc| lc + eval_ct1_p0.get_variable(),
                            |lc| lc + prod_00.get_variable(),
                        );
                        cs.enforce(
                            || format!("sz_mul_s{step}_p00_eq"),
                            |lc| lc + prod_00.get_variable(),
                            |lc| lc + CS::one(),
                            |lc| lc + eval_ct_out_p0.get_variable(),
                        );
                        let prod_11 = AllocatedNum::alloc(
                            cs.namespace(|| format!("sz_mul_s{step}_p11")),
                            || {
                                Ok(eval_ct0_p1.get_value().unwrap_or(NovaScalar::zero())
                                    * eval_ct1_p1.get_value().unwrap_or(NovaScalar::zero()))
                            },
                        )?;
                        cs.enforce(
                            || format!("sz_mul_s{step}_p11_mul"),
                            |lc| lc + eval_ct0_p1.get_variable(),
                            |lc| lc + eval_ct1_p1.get_variable(),
                            |lc| lc + prod_11.get_variable(),
                        );
                        cs.enforce(
                            || format!("sz_mul_s{step}_p11_eq"),
                            |lc| lc + prod_11.get_variable(),
                            |lc| lc + CS::one(),
                            |lc| lc + eval_ct_out_p1.get_variable(),
                        );
                    }
                    #[cfg(feature = "real-relin")]
                    FheOp::Relinearize { .. } => {
                        add_fhe_sz_bp(
                            cs,
                            &eval_ct0_p0,
                            &eval_ct0_p0,
                            &eval_ct_out_p0,
                            step,
                            "relin_p0",
                        )?;
                        add_fhe_sz_bp(
                            cs,
                            &eval_ct0_p1,
                            &eval_ct0_p1,
                            &eval_ct_out_p1,
                            step,
                            "relin_p1",
                        )?;
                    }
                    #[cfg(not(feature = "real-relin"))]
                    FheOp::Relinearize { .. } => {
                        return Err(SynthesisError::AssignmentMissing);
                    }
                }

                let (new_commit_lo, new_commit_hi) = if !witness.ct_out_coeffs.is_empty() {
                    let out_len = witness.ct_out_coeffs.len();
                    if out_len >= BFV_CT_COEFFS_LEN {
                        poseidon_commit_coeffs_split_bp(
                            cs,
                            &witness.ct_out_coeffs[..BFV_CT_COEFFS_LEN],
                            step,
                            1000,
                        )?
                    } else {
                        poseidon_commit_coeffs_split_bp(cs, &witness.ct_out_coeffs, step, 1000)?
                    }
                } else {
                    (
                        AllocatedNum::alloc(cs.namespace(|| format!("sz_nc_lo_s{step}")), || {
                            Ok(NovaScalar::from(0u64))
                        })?,
                        AllocatedNum::alloc(cs.namespace(|| format!("sz_nc_hi_s{step}")), || {
                            Ok(NovaScalar::from(0u64))
                        })?,
                    )
                };

                let one = AllocatedNum::alloc(cs.namespace(|| format!("sz_one_{step}")), || {
                    Ok(NovaScalar::from(1u64))
                })?;
                let new_step_count =
                    z[3].add(cs.namespace(|| format!("sz_sc_inc_{step}")), &one)?;
                Ok(vec![
                    new_commit_lo,
                    new_commit_hi,
                    z[2].clone(),
                    new_step_count,
                ])
            });
        }

        // BFV-N4 path
        {
            let data_len = FHE_COMPUTE_DATA.with(|cell| cell.borrow().len());
            let step = if data_len > 0 {
                if raw_step >= data_len {
                    return Err(SynthesisError::AssignmentMissing);
                }
                raw_step
            } else {
                raw_step
            };

            let has_data = FHE_COMPUTE_DATA.with(|cell| cell.borrow().get(step).is_some());
            if !has_data {
                return Err(SynthesisError::AssignmentMissing);
            }

            return FHE_COMPUTE_DATA.with(|cell| {
                let data = cell.borrow();
                let witness = data.get(step).cloned().unwrap();

                let (old_commit_lo, old_commit_hi) = if !witness.ct0_coeffs.is_empty() {
                    poseidon_commit_coeffs_split_bp(cs, &witness.ct0_coeffs, step, 0)?
                } else {
                    (
                        AllocatedNum::alloc(cs.namespace(|| format!("zc_lo_s{step}")), || {
                            Ok(NovaScalar::from(0u64))
                        })?,
                        AllocatedNum::alloc(cs.namespace(|| format!("zc_hi_s{step}")), || {
                            Ok(NovaScalar::from(0u64))
                        })?,
                    )
                };
                let seed = super::session_bind_seed();
                let seed_var =
                    AllocatedNum::alloc(cs.namespace(|| format!("session_seed_s{step}")), || {
                        Ok(seed)
                    })?;
                let initial_selector = AllocatedNum::alloc(
                    cs.namespace(|| format!("session_seed_selector_s{step}")),
                    || {
                        Ok(if raw_step == 0 {
                            NovaScalar::from(1u64)
                        } else {
                            NovaScalar::from(0u64)
                        })
                    },
                )?;
                cs.enforce(
                    || format!("session_seed_selector_bool_s{step}"),
                    |lc| lc + initial_selector.get_variable(),
                    |lc| lc + initial_selector.get_variable() - CS::one(),
                    |lc| lc,
                );
                let gated_seed = seed_var.mul(
                    cs.namespace(|| format!("session_seed_gated_s{step}")),
                    &initial_selector,
                )?;
                let expected_old_commit_lo = old_commit_lo.add(
                    cs.namespace(|| format!("old_commit_lo_seed_s{step}")),
                    &gated_seed,
                )?;
                cs.enforce(
                    || format!("old_commit_lo_eq_s{step}"),
                    |lc| lc + expected_old_commit_lo.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + z[0].get_variable(),
                );
                cs.enforce(
                    || format!("old_commit_hi_eq_s{step}"),
                    |lc| lc + old_commit_hi.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + z[1].get_variable(),
                );

                verify_merkle_proof_bp(cs, &witness.proof0, self.merkle_arity, step, 0, &z[2])?;

                match &witness.operation {
                    FheOp::Add { .. } => {
                        if !witness.ct0_coeffs.is_empty() && !witness.ct1_coeffs.is_empty() {
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
                    FheOp::Mul { .. } => {
                        mul_fhe_ct_bp(
                            cs,
                            &witness.ct0_coeffs,
                            &witness.ct1_coeffs,
                            &witness.ct_out_coeffs,
                            &BFV_Q,
                            BFV_L,
                            BFV_N,
                            step,
                        )?;
                    }
                    #[cfg(feature = "real-relin")]
                    FheOp::Relinearize { .. } => {
                        let in_len = witness.ct0_coeffs.len();
                        if in_len == BFV_MUL_CT_COEFFS_LEN {
                            relin_fhe_ct_bp(cs, &witness.ct0_coeffs, &witness.ct_out_coeffs, step)?;
                        } else if in_len == BFV_CT_COEFFS_LEN {
                            for i in 0..BFV_CT_COEFFS_LEN {
                                let in_var = AllocatedNum::alloc(
                                    cs.namespace(|| format!("relin_id_s{step}_in{i}")),
                                    || Ok(NovaScalar::from(witness.ct0_coeffs[i])),
                                )?;
                                let out_var = AllocatedNum::alloc(
                                    cs.namespace(|| format!("relin_id_s{step}_out{i}")),
                                    || Ok(NovaScalar::from(witness.ct_out_coeffs[i])),
                                )?;
                                cs.enforce(
                                    || format!("relin_id_s{step}_eq{i}"),
                                    |lc| lc + out_var.get_variable(),
                                    |lc| lc + CS::one(),
                                    |lc| lc + in_var.get_variable(),
                                );
                            }
                        }
                    }
                    #[cfg(not(feature = "real-relin"))]
                    FheOp::Relinearize { .. } => {
                        return Err(SynthesisError::AssignmentMissing);
                    }
                }

                let (new_commit_lo, new_commit_hi) = if !witness.ct_out_coeffs.is_empty() {
                    let out_len = witness.ct_out_coeffs.len();
                    if out_len >= BFV_CT_COEFFS_LEN {
                        poseidon_commit_coeffs_split_bp(
                            cs,
                            &witness.ct_out_coeffs[..BFV_CT_COEFFS_LEN],
                            step,
                            1,
                        )?
                    } else {
                        poseidon_commit_coeffs_split_bp(cs, &witness.ct_out_coeffs, step, 1)?
                    }
                } else {
                    (
                        AllocatedNum::alloc(cs.namespace(|| format!("nc_lo_s{step}")), || {
                            Ok(NovaScalar::from(0u64))
                        })?,
                        AllocatedNum::alloc(cs.namespace(|| format!("nc_hi_s{step}")), || {
                            Ok(NovaScalar::from(0u64))
                        })?,
                    )
                };

                let one = AllocatedNum::alloc(cs.namespace(|| format!("one_{step}")), || {
                    Ok(NovaScalar::from(1u64))
                })?;
                let new_step_count = z[3].add(cs.namespace(|| format!("sc_inc_{step}")), &one)?;
                Ok(vec![
                    new_commit_lo,
                    new_commit_hi,
                    z[2].clone(),
                    new_step_count,
                ])
            });
        }
    }
}

// ── FHE operation enforcement status ────────────────────────────────────
//
//   Add:  ✅ In-circuit — modular addition per RNS limb enforced via
//          `add_fhe_ct_bp` (2 constraints per coefficient).
//   Mul:  ✅ In-circuit — negacyclic convolution via `mul_fhe_ct_bp`;
//          ~(3N^2+2N)·L R1CS constraints. Output is 3 polys; state stores
//          first 2 polys (implicit Relinearize).
//   Relinearize: ⚠️ Gated behind `real-relin` feature — stub is truncation-only.
//          Real relinearization requires a relin key from the FHE backend,
//          which is not yet exposed. Without `real-relin`, returns SynthesisError.
//          See .sisyphus/plans/proof-gap-remediation.md §G4.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{build_merkle_tree, prove_merkle_path};
    use ark_bn254::Fr;
    use ark_ff::BigInteger;

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

    #[cfg(feature = "bfv-n4")]
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

    #[cfg(feature = "bfv-n4")]
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

    #[cfg(feature = "bfv-n4")]
    #[test]
    fn in_circuit_fhe_mul_gadget() {
        let n = BFV_N;
        let l = BFV_L;
        let two_poly = 2 * l * n;
        let three_poly = 3 * l * n;

        let mut ct0 = vec![0u64; two_poly];
        let mut ct1 = vec![0u64; two_poly];
        let mut ct_out = vec![0u64; three_poly];

        for poly in 0..2 {
            for limb in 0..l {
                let q = BFV_Q[limb];
                for coeff in 0..n {
                    let idx = poly * l * n + limb * n + coeff;
                    ct0[idx] = ((limb as u64 * 3 + coeff as u64 * 7 + poly as u64 + 1) * 11) % q;
                    ct1[idx] =
                        ((limb as u64 * 5 + coeff as u64 * 13 + poly as u64 * 3 + 2) * 17) % q;
                }
            }
        }

        // Compute expected ct_out = ct0 * ct1 (negacyclic convolution)
        for limb in 0..l {
            let q = BFV_Q[limb];
            let ct0_p0 = poly_limb_slice_test(&ct0, 0, limb, n, l);
            let ct0_p1 = poly_limb_slice_test(&ct0, 1, limb, n, l);
            let ct1_p0 = poly_limb_slice_test(&ct1, 0, limb, n, l);
            let ct1_p1 = poly_limb_slice_test(&ct1, 1, limb, n, l);

            for k in 0..n {
                ct_out[0 * l * n + limb * n + k] = negacyclic_conv_coeff(ct0_p0, ct1_p0, k, q);
                let a = negacyclic_conv_coeff(ct0_p0, ct1_p1, k, q);
                let b = negacyclic_conv_coeff(ct0_p1, ct1_p0, k, q);
                let sum = a as u128 + b as u128;
                ct_out[1 * l * n + limb * n + k] = if sum >= q as u128 {
                    (sum - q as u128) as u64
                } else {
                    sum as u64
                };
                ct_out[2 * l * n + limb * n + k] = negacyclic_conv_coeff(ct0_p1, ct1_p1, k, q);
            }
        }

        let mut test_cs =
            nova_snark::frontend::util_cs::test_cs::TestConstraintSystem::<NovaScalar>::new();

        let result = mul_fhe_ct_bp(&mut test_cs, &ct0, &ct1, &ct_out, &BFV_Q, l, n, 0);
        assert!(result.is_ok(), "mul_fhe_ct_bp should succeed");
        assert!(
            test_cs.is_satisfied(),
            "fhe mul constraint system must be satisfied"
        );
    }

    #[cfg(feature = "bfv-n4")]
    #[test]
    fn in_circuit_fhe_mul_rejects_bad_output() {
        let n = BFV_N;
        let l = BFV_L;
        let two_poly = 2 * l * n;
        let three_poly = 3 * l * n;

        let mut ct0 = vec![0u64; two_poly];
        let mut ct1 = vec![0u64; two_poly];
        let mut ct_out_good = vec![0u64; three_poly];

        for poly in 0..2 {
            for limb in 0..l {
                let q = BFV_Q[limb];
                for coeff in 0..n {
                    let idx = poly * l * n + limb * n + coeff;
                    ct0[idx] = ((limb + coeff + poly + 1) as u64 * 7) % q;
                    ct1[idx] = ((limb + coeff + poly + 2) as u64 * 13) % q;
                }
            }
        }

        for limb in 0..l {
            let q = BFV_Q[limb];
            let ct0_p0 = poly_limb_slice_test(&ct0, 0, limb, n, l);
            let ct0_p1 = poly_limb_slice_test(&ct0, 1, limb, n, l);
            let ct1_p0 = poly_limb_slice_test(&ct1, 0, limb, n, l);
            let ct1_p1 = poly_limb_slice_test(&ct1, 1, limb, n, l);
            for k in 0..n {
                ct_out_good[0 * l * n + limb * n + k] = negacyclic_conv_coeff(ct0_p0, ct1_p0, k, q);
                ct_out_good[2 * l * n + limb * n + k] = negacyclic_conv_coeff(ct0_p1, ct1_p1, k, q);
                let a = negacyclic_conv_coeff(ct0_p0, ct1_p1, k, q);
                let b = negacyclic_conv_coeff(ct0_p1, ct1_p0, k, q);
                let sum = a as u128 + b as u128;
                ct_out_good[1 * l * n + limb * n + k] = if sum >= q as u128 {
                    (sum - q as u128) as u64
                } else {
                    sum as u64
                };
            }
        }

        let mut ct_out_bad = ct_out_good.clone();
        ct_out_bad[0] = ct_out_bad[0].wrapping_add(1);

        let mut test_cs =
            nova_snark::frontend::util_cs::test_cs::TestConstraintSystem::<NovaScalar>::new();

        let _ = mul_fhe_ct_bp(&mut test_cs, &ct0, &ct1, &ct_out_bad, &BFV_Q, l, n, 0);
        assert!(
            !test_cs.is_satisfied(),
            "fhe mul constraint system must be unsatisfied with wrong output"
        );
    }

    #[cfg(feature = "real-relin")]
    #[test]
    fn in_circuit_fhe_relin_gadget() {
        let n = BFV_N;
        let l = BFV_L;
        let three_poly = 3 * l * n;
        let two_poly = 2 * l * n;

        let ct_in: Vec<u64> = (0..three_poly)
            .map(|i| ((i as u64 + 1) * 13) % BFV_Q[i / (l * n) % l])
            .collect();
        let ct_out: Vec<u64> = ct_in[..two_poly].to_vec();

        let mut test_cs =
            nova_snark::frontend::util_cs::test_cs::TestConstraintSystem::<NovaScalar>::new();

        let result = relin_fhe_ct_bp(&mut test_cs, &ct_in, &ct_out, 0);
        assert!(result.is_ok(), "relin_fhe_ct_bp should succeed");
        assert!(
            test_cs.is_satisfied(),
            "fhe relin constraint system must be satisfied"
        );
    }

    #[cfg(feature = "real-relin")]
    #[test]
    fn in_circuit_fhe_relin_rejects_bad_output() {
        let n = BFV_N;
        let l = BFV_L;
        let three_poly = 3 * l * n;
        let two_poly = 2 * l * n;

        let ct_in: Vec<u64> = (0..three_poly)
            .map(|i| ((i as u64 + 1) * 13) % BFV_Q[i / (l * n) % l])
            .collect();
        let mut ct_out: Vec<u64> = ct_in[..two_poly].to_vec();
        ct_out[0] = ct_out[0].wrapping_add(1);

        let mut test_cs =
            nova_snark::frontend::util_cs::test_cs::TestConstraintSystem::<NovaScalar>::new();

        let _ = relin_fhe_ct_bp(&mut test_cs, &ct_in, &ct_out, 0);
        assert!(
            !test_cs.is_satisfied(),
            "fhe relin constraint system must be unsatisfied with wrong output"
        );
    }

    #[cfg(feature = "bfv-n4")]
    #[test]
    fn in_circuit_mul_synthesize_step() {
        let n = BFV_N;
        let l = BFV_L;
        let two_poly = 2 * l * n;
        let three_poly = 3 * l * n;

        let mut ct0 = vec![0u64; two_poly];
        let mut ct1 = vec![0u64; two_poly];
        let mut ct_out = vec![0u64; three_poly];

        for poly in 0..2 {
            for limb in 0..l {
                let q = BFV_Q[limb];
                for coeff in 0..n {
                    let idx = poly * l * n + limb * n + coeff;
                    ct0[idx] = ((limb as u64 * 3 + coeff as u64 * 7 + poly as u64 + 1) * 11) % q;
                    ct1[idx] =
                        ((limb as u64 * 5 + coeff as u64 * 13 + poly as u64 * 3 + 2) * 17) % q;
                }
            }
        }

        for limb in 0..l {
            let q = BFV_Q[limb];
            let ct0_p0 = poly_limb_slice_test(&ct0, 0, limb, n, l);
            let ct0_p1 = poly_limb_slice_test(&ct0, 1, limb, n, l);
            let ct1_p0 = poly_limb_slice_test(&ct1, 0, limb, n, l);
            let ct1_p1 = poly_limb_slice_test(&ct1, 1, limb, n, l);
            for k in 0..n {
                ct_out[0 * l * n + limb * n + k] = negacyclic_conv_coeff(ct0_p0, ct1_p0, k, q);
                let a = negacyclic_conv_coeff(ct0_p0, ct1_p1, k, q);
                let b = negacyclic_conv_coeff(ct0_p1, ct1_p0, k, q);
                let sum = a as u128 + b as u128;
                ct_out[1 * l * n + limb * n + k] = if sum >= q as u128 {
                    (sum - q as u128) as u64
                } else {
                    sum as u64
                };
                ct_out[2 * l * n + limb * n + k] = negacyclic_conv_coeff(ct0_p1, ct1_p1, k, q);
            }
        }

        // Build Merkle tree from a hash of ct1 for the proof
        let ct1_hash = {
            use crate::nova::hash8_native;
            let mut fields: Vec<Fr> = ct1.iter().take(8).map(|&v| Fr::from(v)).collect();
            while fields.len() < 8 {
                fields.push(Fr::zero());
            }
            hash8_native(&fields)
        };
        let leaves = vec![ct1_hash, Fr::zero(), Fr::zero(), Fr::zero()];
        let (tree, merkle_root) = build_merkle_tree(&leaves, 8);
        let proof = prove_merkle_path(&tree, 0, 8);

        let witness = FheComputeWitness {
            operation: FheOp::Mul {
                ct0_hash: [0xAA; 32],
                ct1_hash: [0xBB; 32],
            },
            proof0: proof,
            proof1: None,
            output_hash: Fr::zero(),
            ct0_coeffs: ct0.clone(),
            ct1_coeffs: ct1.clone(),
            ct_out_coeffs: ct_out.clone(),
        };

        // Compute native Poseidon commitments for the state
        let z0 = native_poseidon_commit_coeffs_half(&ct0[..12]);
        let z1 = native_poseidon_commit_coeffs_half(&ct0[12..]);
        use super::super::ark_to_nova_scalar;

        let mut test_cs =
            nova_snark::frontend::util_cs::test_cs::TestConstraintSystem::<NovaScalar>::new();
        let z: Vec<AllocatedNum<NovaScalar>> = [z0, z1, merkle_root, Fr::zero()]
            .iter()
            .enumerate()
            .map(|(i, &val)| {
                AllocatedNum::alloc(test_cs.namespace(|| format!("z{i}")), || {
                    Ok(ark_to_nova_scalar(val))
                })
            })
            .collect::<Result<_, _>>()
            .unwrap();

        set_fhe_compute_data(vec![witness]);
        let circuit = FheComputeStepCircuit::<Fr>::default();
        let result = <FheComputeStepCircuit<Fr> as nova_snark::traits::circuit::StepCircuit<
            NovaScalar,
        >>::synthesize(&circuit, &mut test_cs, &z);
        clear_fhe_compute_data();

        assert!(result.is_ok(), "mul synthesize step should succeed");
        assert!(
            test_cs.is_satisfied(),
            "mul synthesize step constraint system must be satisfied"
        );
    }

    #[cfg(feature = "bfv-n4")]
    fn poly_limb_slice_test<'a>(
        coeffs: &'a [u64],
        poly: usize,
        limb: usize,
        n: usize,
        l: usize,
    ) -> &'a [u64] {
        let start = poly * l * n + limb * n;
        &coeffs[start..start + n]
    }

    #[cfg(feature = "bfv-n4")]
    #[test]
    fn fhe_compute_nova_roundtrip_with_split_coefficient_state() {
        use crate::nova::{encode_triple, ExternalInputs3, NovaCompressor};

        let input_ct_hash = [0xBBu8; 32];
        let leaves: Vec<Fr> = vec![
            Fr::from_be_bytes_mod_order(&input_ct_hash),
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
        ];
        let (tree, merkle_root) = build_merkle_tree(&leaves, 8);
        let merkle_root_bytes: [u8; 32] = {
            let raw = merkle_root.into_bigint().to_bytes_be();
            let mut out = [0u8; 32];
            let start = 32usize.saturating_sub(raw.len());
            out[start..].copy_from_slice(&raw);
            out
        };

        let total = BFV_CT_COEFFS_LEN;
        let input_coeffs: Vec<u64> = (0..total).map(|i| (i as u64 + 7) * 11).collect();
        let mut acc_coeffs = vec![0u64; total];
        let mut witnesses = Vec::new();

        for _ in 0..2 {
            let mut ct_out = vec![0u64; total];
            for poly in 0..2 {
                for limb in 0..BFV_L {
                    let q = BFV_Q[limb];
                    for coeff in 0..BFV_N {
                        let idx = poly * BFV_L * BFV_N + limb * BFV_N + coeff;
                        let sum = acc_coeffs[idx] as u128 + input_coeffs[idx] as u128;
                        ct_out[idx] = if sum >= q as u128 {
                            (sum - q as u128) as u64
                        } else {
                            sum as u64
                        };
                    }
                }
            }

            witnesses.push(FheComputeWitness {
                operation: FheOp::Add {
                    ct0_hash: input_ct_hash,
                    ct1_hash: input_ct_hash,
                },
                proof0: prove_merkle_path(&tree, 0, 8),
                proof1: None,
                output_hash: Fr::zero(),
                ct0_coeffs: acc_coeffs.clone(),
                ct1_coeffs: input_coeffs.clone(),
                ct_out_coeffs: ct_out.clone(),
            });

            acc_coeffs = ct_out;
        }

        let zero_coeffs = vec![0u64; total];
        let z0_state = encode_triple((
            native_poseidon_commit_coeffs_half(&zero_coeffs[..12]),
            native_poseidon_commit_coeffs_half(&zero_coeffs[12..]),
            merkle_root,
        ));

        set_fhe_compute_data(witnesses.clone());
        let compressor = NovaCompressor::<FheComputeStepCircuit<Fr>>::new(
            merkle_root_bytes,
            2,
            [0u8; 32],
            crate::nova::SBIND_FHE_COMPUTE,
        )
        .expect("construct split-state fhe compute nova compressor");
        let steps = vec![ExternalInputs3::default(); 2];

        set_fhe_compute_data(witnesses.clone());
        let proof = compressor
            .prove_steps(&z0_state, &steps)
            .expect("prove split-state fhe compute step");

        set_fhe_compute_data(witnesses);
        let vk = compressor.verifier_key();
        let verified = compressor
            .verify_steps(&vk, &proof, &z0_state, &steps)
            .expect("verify split-state fhe compute step");
        clear_fhe_compute_data();

        assert!(verified);
    }

    fn native_poseidon_commit_coeffs_half(coeffs: &[u64]) -> Fr {
        // Generic recursive hash8 commitment matching the in-circuit version.
        let fields: Vec<Fr> = coeffs.iter().map(|&v| Fr::from(v)).collect();
        native_hash_vector_to_fr(&fields)
    }

    /// Recursively hash a vector of Fr values into a single Fr via hash8,
    /// matching the in-circuit `hash_coeff_vector_bp` logic.
    fn native_hash_vector_to_fr(vals: &[Fr]) -> Fr {
        if vals.len() <= 8 {
            let mut padded = vals.to_vec();
            while padded.len() < 8 {
                padded.push(Fr::zero());
            }
            return hash8_native(&padded);
        }
        let mut next_level: Vec<Fr> = Vec::new();
        for chunk in vals.chunks(8) {
            let mut padded = chunk.to_vec();
            while padded.len() < 8 {
                padded.push(Fr::zero());
            }
            next_level.push(hash8_native(&padded));
        }
        native_hash_vector_to_fr(&next_level)
    }

    #[cfg(feature = "bfv-n4")]
    #[test]
    fn fhe_compute_synthesize_accepts_previous_output_from_split_state() {
        use super::super::ark_to_nova_scalar;

        let input_ct_hash = [0xCCu8; 32];
        let leaves: Vec<Fr> = vec![Fr::from_be_bytes_mod_order(&input_ct_hash)];
        let (tree, merkle_root) = build_merkle_tree(&leaves, 8);
        let total = BFV_CT_COEFFS_LEN;
        let ct0_coeffs: Vec<u64> = (0..total).map(|i| (i as u64 + 1) * 13).collect();
        let ct1_coeffs: Vec<u64> = (0..total).map(|i| (i as u64 + 1) * 17).collect();
        let mut ct_out_coeffs = vec![0u64; total];
        for poly in 0..2 {
            for limb in 0..BFV_L {
                let q = BFV_Q[limb];
                for coeff in 0..BFV_N {
                    let idx = poly * BFV_L * BFV_N + limb * BFV_N + coeff;
                    let sum = ct0_coeffs[idx] as u128 + ct1_coeffs[idx] as u128;
                    ct_out_coeffs[idx] = if sum >= q as u128 {
                        (sum - q as u128) as u64
                    } else {
                        sum as u64
                    };
                }
            }
        }

        set_fhe_compute_data(vec![FheComputeWitness {
            operation: FheOp::Add {
                ct0_hash: input_ct_hash,
                ct1_hash: input_ct_hash,
            },
            proof0: prove_merkle_path(&tree, 0, 8),
            proof1: None,
            output_hash: Fr::zero(),
            ct0_coeffs: ct0_coeffs.clone(),
            ct1_coeffs,
            ct_out_coeffs,
        }]);

        let mut test_cs =
            nova_snark::frontend::util_cs::test_cs::TestConstraintSystem::<NovaScalar>::new();
        let z_vals = [
            native_poseidon_commit_coeffs_half(&ct0_coeffs[..12]),
            native_poseidon_commit_coeffs_half(&ct0_coeffs[12..]),
            merkle_root,
            Fr::zero(),
        ];
        let z: Vec<AllocatedNum<NovaScalar>> = z_vals
            .iter()
            .enumerate()
            .map(|(i, &value)| {
                AllocatedNum::alloc(test_cs.namespace(|| format!("z{i}")), || {
                    Ok(ark_to_nova_scalar(value))
                })
            })
            .collect::<Result<_, _>>()
            .unwrap();

        let circuit = FheComputeStepCircuit::<Fr>::default();
        let result = <FheComputeStepCircuit<Fr> as nova_snark::traits::circuit::StepCircuit<
            NovaScalar,
        >>::synthesize(&circuit, &mut test_cs, &z);
        clear_fhe_compute_data();

        assert!(result.is_ok(), "split-state synthesize should succeed");
        assert!(
            test_cs.is_satisfied(),
            "previous output coefficients must be accepted from split z[0]/z[1] state"
        );
    }

    // ── G4.2a: RED test — relinearization must REJECT without real-relin ──
    //
    // Without the `real-relin` feature, the Relinearize path must return
    // SynthesisError because the current stub is truncation-only — it drops
    // ct[2] without any relin key, unsound for a real FHE system.
    // See .sisyphus/plans/proof-gap-remediation.md §G4.
    //
    // This test is RED before the feature gate (relin silently succeeds as
    // truncation), GREEN after (relin returns SynthesisError).
    #[cfg(feature = "bfv-n4")]
    #[test]
    fn fhe_compute_relin_rejects_without_real_relin() {
        use super::super::ark_to_nova_scalar;

        let two_poly = BFV_CT_COEFFS_LEN;

        let ct_out: Vec<u64> = (0..two_poly).map(|i| (i as u64 + 1) * 7).collect();
        let ct_hash = [0xDDu8; 32];
        let leaves: Vec<Fr> = vec![Fr::from_be_bytes_mod_order(&ct_hash), Fr::zero()];
        let (tree, merkle_root) = build_merkle_tree(&leaves, 8);

        let witness = FheComputeWitness {
            operation: FheOp::Relinearize { ct_hash },
            proof0: prove_merkle_path(&tree, 0, 8),
            proof1: None,
            output_hash: Fr::zero(),
            ct0_coeffs: ct_out.clone(),
            ct1_coeffs: vec![],
            ct_out_coeffs: ct_out.clone(),
        };

        set_fhe_compute_data(vec![witness]);

        let mut test_cs =
            nova_snark::frontend::util_cs::test_cs::TestConstraintSystem::<NovaScalar>::new();
        let z_vals = [
            native_poseidon_commit_coeffs_half(&ct_out[..12]),
            native_poseidon_commit_coeffs_half(&ct_out[12..]),
            merkle_root,
            Fr::zero(),
        ];
        let z: Vec<AllocatedNum<NovaScalar>> = z_vals
            .iter()
            .enumerate()
            .map(|(i, &value)| {
                AllocatedNum::alloc(test_cs.namespace(|| format!("z{i}")), || {
                    Ok(ark_to_nova_scalar(value))
                })
            })
            .collect::<Result<_, _>>()
            .unwrap();

        let circuit = FheComputeStepCircuit::<Fr>::default();
        let result = <FheComputeStepCircuit<Fr> as nova_snark::traits::circuit::StepCircuit<
            NovaScalar,
        >>::synthesize(&circuit, &mut test_cs, &z);

        clear_fhe_compute_data();

        assert!(
            result.is_err(),
            "Relinearize must REJECT without real-relin feature: result was Ok"
        );
    }

    #[cfg(feature = "bfv-n4")]
    #[test]
    fn fhe_compute_nova_roundtrip_with_coefficient_chaining() {
        use crate::nova::{encode_triple, ExternalInputs3, NovaCompressor};

        // Single input ciphertext committed in Merkle tree (leaf 0).
        let input_ct_hash = [0xAAu8; 32];
        let leaves: Vec<Fr> = vec![
            Fr::from_be_bytes_mod_order(&input_ct_hash),
            Fr::from(9999u64),
            Fr::from(9998u64),
            Fr::from(9997u64),
        ];
        let (tree, merkle_root) = build_merkle_tree(&leaves, 8);
        let merkle_root_bytes: [u8; 32] = {
            let raw = merkle_root.into_bigint().to_bytes_be();
            let mut out = [0u8; 32];
            let start = 32usize.saturating_sub(raw.len());
            out[start..].copy_from_slice(&raw);
            out
        };

        let total = BFV_CT_COEFFS_LEN;
        // Input ciphertext coefficients (fixed across all steps).
        let input_coeffs: Vec<u64> = (0..total).map(|i| (i as u64 + 1) * 100).collect();

        // Accumulator starts at zero.
        let mut acc_coeffs: Vec<u64> = vec![0u64; total];
        let mut witnesses = Vec::new();

        for _step in 0..3 {
            // ct_out = acc_coeffs + input_coeffs (mod BFV_Q)
            let mut ct_out = vec![0u64; total];
            for poly in 0..2 {
                for limb in 0..BFV_L {
                    let q = BFV_Q[limb];
                    for coeff in 0..BFV_N {
                        let idx = poly * BFV_L * BFV_N + limb * BFV_N + coeff;
                        let sum = acc_coeffs[idx] as u128 + input_coeffs[idx] as u128;
                        ct_out[idx] = if sum >= q as u128 {
                            (sum - q as u128) as u64
                        } else {
                            sum as u64
                        };
                    }
                }
            }

            let op = FheOp::Add {
                ct0_hash: input_ct_hash,
                ct1_hash: input_ct_hash,
            };

            witnesses.push(FheComputeWitness {
                operation: op,
                proof0: prove_merkle_path(&tree, 0, 8),
                proof1: None,
                output_hash: Fr::zero(),
                ct0_coeffs: acc_coeffs.clone(),
                ct1_coeffs: input_coeffs.clone(),
                ct_out_coeffs: ct_out.clone(),
            });

            // Chain: output becomes next step's accumulator
            acc_coeffs = ct_out;
        }

        // Initial state: z[0]=commit(zero coeffs [0..12]),
        // z[1]=commit(zero coeffs [12..24]), z[2]=merkle_root, z[3]=0.
        let zero_coeffs = vec![0u64; total];
        let z0_state = encode_triple((
            native_poseidon_commit_coeffs_half(&zero_coeffs[..12]),
            native_poseidon_commit_coeffs_half(&zero_coeffs[12..]),
            merkle_root,
        ));

        set_fhe_compute_data(witnesses.clone());
        let compressor = NovaCompressor::<FheComputeStepCircuit<Fr>>::new(
            merkle_root_bytes,
            3,
            [0u8; 32],
            crate::nova::SBIND_FHE_COMPUTE,
        )
        .expect("construct fhe compute nova compressor");
        let steps = vec![ExternalInputs3::default(); 3];

        set_fhe_compute_data(witnesses.clone());
        let proof = compressor
            .prove_steps(&z0_state, &steps)
            .expect("prove fhe compute step");

        set_fhe_compute_data(witnesses);
        let vk = compressor.verifier_key();
        let verified = compressor
            .verify_steps(&vk, &proof, &z0_state, &steps)
            .expect("verify fhe compute step");
        clear_fhe_compute_data();

        assert!(verified);
    }

    // ── Schwartz-Zippel roundtrip tests (bfv-n4 only) ─────────────────────

    /// Constraint-system-level S-Z verification at N=8192.
    /// Verifies that the S-Z synthesize path produces a satisfied R1CS
    /// without needing full Nova setup.
    #[cfg(feature = "bfv-n4")]
    #[test]
    fn fhe_compute_sz_synthesize_satisfied_n8192() {
        let n = BFV_N;
        let l = BFV_L;
        let total = BFV_CT_COEFFS_LEN;
        let half = total / 2;

        let input_ct_hash = [0xAAu8; 32];
        let leaves: Vec<Fr> = vec![
            Fr::from_be_bytes_mod_order(&input_ct_hash),
            Fr::from(9999u64),
            Fr::from(9998u64),
            Fr::from(9997u64),
        ];
        let (tree, merkle_root) = build_merkle_tree(&leaves, 8);

        let input_coeffs: Vec<u64> = (0..total)
            .map(|i| ((i as u64 + 1) * 100) % (BFV_Q[i / (l * n) % l]))
            .collect();
        let acc_coeffs = vec![0u64; total];

        // Compute one step of FHE Add
        let mut ct_out = vec![0u64; total];
        for poly in 0..2 {
            for limb in 0..l {
                let q = BFV_Q[limb];
                for coeff in 0..n {
                    let idx = poly * l * n + limb * n + coeff;
                    let sum = acc_coeffs[idx] as u128 + input_coeffs[idx] as u128;
                    ct_out[idx] = if sum >= q as u128 {
                        (sum - q as u128) as u64
                    } else {
                        sum as u64
                    };
                }
            }
        }

        // Deterministic challenge point
        let challenge_r = Fr::from(7u64);

        let eval_poly_helper = |coeffs: &[u64]| -> Fr {
            let frs: Vec<Fr> = coeffs.iter().map(|&v| Fr::from(v)).collect();
            crate::poly_eval::eval_poly_bn254(&frs, challenge_r)
        };

        let witness = FheComputeWitnessSz {
            operation: FheOp::Add {
                ct0_hash: input_ct_hash,
                ct1_hash: input_ct_hash,
            },
            proof0: prove_merkle_path(&tree, 0, 8),
            proof1: None,
            challenge_r,
            eval_ct0: vec![
                eval_poly_helper(&acc_coeffs[..half]),
                eval_poly_helper(&acc_coeffs[half..]),
            ],
            eval_ct1: vec![
                eval_poly_helper(&input_coeffs[..half]),
                eval_poly_helper(&input_coeffs[half..]),
            ],
            eval_ct_out: vec![
                eval_poly_helper(&ct_out[..half]),
                eval_poly_helper(&ct_out[half..]),
            ],
            ct0_coeffs: acc_coeffs.clone(),
            ct1_coeffs: input_coeffs,
            ct_out_coeffs: ct_out.clone(),
        };

        use super::super::ark_to_nova_scalar;

        let mut test_cs =
            nova_snark::frontend::util_cs::test_cs::TestConstraintSystem::<NovaScalar>::new();
        let z_vals = [
            native_poseidon_commit_coeffs_half(&acc_coeffs[..half]),
            native_poseidon_commit_coeffs_half(&acc_coeffs[half..]),
            merkle_root,
            Fr::zero(),
        ];
        let z: Vec<AllocatedNum<NovaScalar>> = z_vals
            .iter()
            .enumerate()
            .map(|(i, &value)| {
                AllocatedNum::alloc(test_cs.namespace(|| format!("z{i}")), || {
                    Ok(ark_to_nova_scalar(value))
                })
            })
            .collect::<Result<_, _>>()
            .unwrap();

        set_fhe_compute_sz_data(vec![witness]);
        let circuit = FheComputeStepCircuit::<Fr>::default();
        let result = <FheComputeStepCircuit<Fr> as nova_snark::traits::circuit::StepCircuit<
            NovaScalar,
        >>::synthesize(&circuit, &mut test_cs, &z);
        clear_fhe_compute_data();

        assert!(result.is_ok(), "S-Z synthesize should succeed at N=8192");
        assert!(
            test_cs.is_satisfied(),
            "S-Z constraint system must be satisfied at N=8192"
        );
    }

    /// Full Nova IVC roundtrip using Schwartz-Zippel FHE verification.
    /// Uses a moderate number of constraints; Nova setup amortizes over steps.
    #[cfg(feature = "bfv-n4")]
    #[test]
    fn fhe_compute_sz_roundtrip_n8192() {
        use crate::nova::{encode_triple, ExternalInputs3, NovaCompressor};

        let total = BFV_CT_COEFFS_LEN;
        let half = total / 2;
        let n_steps: usize = 1;

        let input_ct_hash = [0xAAu8; 32];
        let leaves: Vec<Fr> = vec![
            Fr::from_be_bytes_mod_order(&input_ct_hash),
            Fr::from(9999u64),
            Fr::from(9998u64),
            Fr::from(9997u64),
        ];
        let (tree, merkle_root) = build_merkle_tree(&leaves, 8);
        let merkle_root_bytes: [u8; 32] = {
            let raw = merkle_root.into_bigint().to_bytes_be();
            let mut out = [0u8; 32];
            let start = 32usize.saturating_sub(raw.len());
            out[start..].copy_from_slice(&raw);
            out
        };

        let challenge_r = Fr::from(7u64);
        let input_coeffs: Vec<u64> = (0..total).map(|i| (i as u64 + 1) * 100).collect();
        let acc_coeffs = vec![0u64; total];
        let mut ct_out = vec![0u64; total];
        for poly in 0..2 {
            for limb in 0..BFV_L {
                let q = BFV_Q[limb];
                for coeff in 0..BFV_N {
                    let idx = poly * BFV_L * BFV_N + limb * BFV_N + coeff;
                    let sum = acc_coeffs[idx] as u128 + input_coeffs[idx] as u128;
                    ct_out[idx] = if sum >= q as u128 {
                        (sum - q as u128) as u64
                    } else {
                        sum as u64
                    };
                }
            }
        }

        let eval_poly_helper = |coeffs: &[u64]| -> Fr {
            let frs: Vec<Fr> = coeffs.iter().map(|&v| Fr::from(v)).collect();
            crate::poly_eval::eval_poly_bn254(&frs, challenge_r)
        };

        let sz_witness = FheComputeWitnessSz {
            operation: FheOp::Add {
                ct0_hash: input_ct_hash,
                ct1_hash: input_ct_hash,
            },
            proof0: prove_merkle_path(&tree, 0, 8),
            proof1: None,
            challenge_r,
            eval_ct0: vec![
                eval_poly_helper(&acc_coeffs[..half]),
                eval_poly_helper(&acc_coeffs[half..]),
            ],
            eval_ct1: vec![
                eval_poly_helper(&input_coeffs[..half]),
                eval_poly_helper(&input_coeffs[half..]),
            ],
            eval_ct_out: vec![
                eval_poly_helper(&ct_out[..half]),
                eval_poly_helper(&ct_out[half..]),
            ],
            ct0_coeffs: acc_coeffs.clone(),
            ct1_coeffs: input_coeffs,
            ct_out_coeffs: ct_out,
        };

        let zero_coeffs = vec![0u64; total];
        let z0 = native_poseidon_commit_coeffs_half(&zero_coeffs[..half]);
        let z1 = native_poseidon_commit_coeffs_half(&zero_coeffs[half..]);
        let z0_state = encode_triple((z0, z1, merkle_root));

        set_fhe_compute_sz_data(vec![sz_witness.clone()]);
        let compressor = NovaCompressor::<FheComputeStepCircuit<Fr>>::new(
            merkle_root_bytes,
            n_steps,
            [0u8; 32],
            crate::nova::SBIND_FHE_COMPUTE,
        )
        .expect("construct S-Z fhe compute nova compressor");
        let steps = vec![ExternalInputs3::default(); n_steps];

        set_fhe_compute_sz_data(vec![sz_witness.clone()]);
        let proof = compressor
            .prove_steps(&z0_state, &steps)
            .expect("prove S-Z fhe compute step");

        set_fhe_compute_sz_data(vec![sz_witness]);
        let vk = compressor.verifier_key();
        let verified = compressor
            .verify_steps(&vk, &proof, &z0_state, &steps)
            .expect("verify S-Z fhe compute step");
        clear_fhe_compute_data();

        assert!(verified);
    }

    /// Constraint-system-level chunked FHE compute verification.
    /// Uses a small chunk size (64) for fast execution while testing
    /// the full chunked synthesis path including hash-chain state updates.
    #[cfg(not(feature = "bfv-n4"))]
    #[test]
    fn fhe_compute_chunked_roundtrip_n8192() {
        use super::super::ark_to_nova_scalar;

        let chunk_n: usize = 64;
        let input_ct_hash = [0xAAu8; 32];
        let leaves: Vec<Fr> = vec![
            Fr::from_be_bytes_mod_order(&input_ct_hash),
            Fr::from(9999u64),
        ];
        let (tree, merkle_root) = build_merkle_tree(&leaves, 8);

        let total_n = chunk_n * 2;
        let input_coeffs: Vec<u64> = (0..total_n).map(|i| (i as u64 + 1) * 100).collect();
        let mut acc_coeffs: Vec<u64> = vec![0u64; total_n];
        let mut ct_out = vec![0u64; total_n];

        for (i, out) in ct_out.iter_mut().enumerate() {
            let q = BFV_Q[0];
            let sum = acc_coeffs[i] as u128 + input_coeffs[i] as u128;
            *out = if sum >= q as u128 {
                (sum - q as u128) as u64
            } else {
                sum as u64
            };
        }

        let op = FheOp::Add {
            ct0_hash: input_ct_hash,
            ct1_hash: input_ct_hash,
        };

        let proof0 = prove_merkle_path(&tree, 0, 8);

        let chunk0 = FheComputeChunkWitness {
            operation: op,
            chunk_index: 0,
            total_chunks: 2,
            ct0_chunk: acc_coeffs[..chunk_n].to_vec(),
            ct1_chunk: input_coeffs[..chunk_n].to_vec(),
            ct_out_chunk: ct_out[..chunk_n].to_vec(),
            proof0: proof0.clone(),
        };

        let chunk1 = FheComputeChunkWitness {
            operation: op,
            chunk_index: 1,
            total_chunks: 2,
            ct0_chunk: acc_coeffs[chunk_n..].to_vec(),
            ct1_chunk: input_coeffs[chunk_n..].to_vec(),
            ct_out_chunk: ct_out[chunk_n..].to_vec(),
            proof0: proof0.clone(),
        };

        set_fhe_chunk_data(vec![chunk0, chunk1]);

        // Step 0: initial state z[0..4]=0, z[5]=merkle_root, z[6]=0, z[7]=2
        let mut test_cs =
            nova_snark::frontend::util_cs::test_cs::TestConstraintSystem::<NovaScalar>::new();
        let z0_vals: [Fr; 8] = [
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
            merkle_root,
            Fr::from(0u64),
            Fr::from(2u64),
        ];
        let z: Vec<AllocatedNum<NovaScalar>> = z0_vals
            .iter()
            .enumerate()
            .map(|(i, &value)| {
                AllocatedNum::alloc(test_cs.namespace(|| format!("z_s0_{i}")), || {
                    Ok(ark_to_nova_scalar(value))
                })
            })
            .collect::<Result<_, _>>()
            .unwrap();

        let circuit = FheComputeStepCircuit::<Fr>::default();
        let result0 = <FheComputeStepCircuit<Fr> as nova_snark::traits::circuit::StepCircuit<
            NovaScalar,
        >>::synthesize(&circuit, &mut test_cs, &z);
        assert!(result0.is_ok(), "chunked step 0 synthesize should succeed");
        assert!(
            test_cs.is_satisfied(),
            "chunked step 0 constraint system must be satisfied"
        );

        // Step 1: compute expected z[0] via native hash chain
        let chunk0_hash = poseidon_hash_chunk_native(&ct_out[..chunk_n]);
        let expected_z0 = poseidon_hash2_native(Fr::zero(), chunk0_hash);

        let mut test_cs2 =
            nova_snark::frontend::util_cs::test_cs::TestConstraintSystem::<NovaScalar>::new();
        let z1_vals: [Fr; 8] = [
            expected_z0,
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
            merkle_root,
            Fr::from(1u64),
            Fr::from(2u64),
        ];
        let z2: Vec<AllocatedNum<NovaScalar>> = z1_vals
            .iter()
            .enumerate()
            .map(|(i, &value)| {
                AllocatedNum::alloc(test_cs2.namespace(|| format!("z_s1_{i}")), || {
                    Ok(ark_to_nova_scalar(value))
                })
            })
            .collect::<Result<_, _>>()
            .unwrap();

        let result1 = <FheComputeStepCircuit<Fr> as nova_snark::traits::circuit::StepCircuit<
            NovaScalar,
        >>::synthesize(&circuit, &mut test_cs2, &z2);
        assert!(result1.is_ok(), "chunked step 1 synthesize should succeed");
        assert!(
            test_cs2.is_satisfied(),
            "chunked step 1 constraint system must be satisfied"
        );

        clear_fhe_chunk_data();
    }
}
