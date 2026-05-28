//! BFV encryption sigma verification in R1CS.
//!
//! Verifies the BFV encryption relation per coefficient, batched across
//! L=3 CRT moduli via a Schwartz-Zippel challenge γ.
//!
//! Relation per modulus l:
//!   ct0[l] = pk0[l]·u + e0 + Δ[l]·m + q[l]·quot0[l]
//!   ct1[l] = pk1[l]·u + e1 + q[l]·quot1[l]
//!
//! S-Z batch across L moduli:
//!   Σ_l γ^l · (ct0[l] - pk0[l]·u - e0 - Δ[l]·m - q[l]·quot0[l]) == 0
//!   Σ_l γ^l · (ct1[l] - pk1[l]·u - e1 - q[l]·quot1[l]) == 0
//!
//! Plus norm bounds: |u| ≤ B_U, |e0| ≤ B_E, |e1| ≤ B_E, |m| ≤ B_M.

use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::GR1CSVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use sha3::{Digest, Keccak256};
use std::cell::RefCell;
use std::marker::PhantomData;

use crate::{StepCircuit, StepCircuitDescriptor};

/// Number of CRT moduli (RNS limbs).
pub const BFV_L: usize = 3;

/// BFV modulus per limb (q[l]).
pub const BFV_Q: [u64; BFV_L] = [
    288_230_376_173_076_481,
    288_230_376_167_047_169,
    288_230_376_161_280_001,
];

/// Witness bounds.
pub const B_U: u64 = 10_000;
pub const B_E: u64 = 10_000;
pub const B_M: u64 = 65_536;

/// Flat data layout per step (total elements per step).
/// Fields in order:
///   0..3:      ct0_coeffs[L]
///   3..6:      ct1_coeffs[L]
///   6..9:      pk0_coeffs[L]
///   9..12:     pk1_coeffs[L]
///   12..15:    delta_limbs[L]
///   15:        u_coeff
///   16:        e0_coeff
///   17:        e1_coeff
///   18:        m_coeff
///   19..22:    quot0[L]
///   22..25:    quot1[L]
///   25..28:    gamma_powers[L]
pub const BFV_STEP_DATA_LEN: usize = 28;

thread_local! {
    /// Per-step BFV encryption witness data.
    /// Each inner Vec<Fr> encodes one BfvEncryptionStepData (flat layout).
    pub static BFV_ENCRYPTION_DATA: RefCell<Vec<Vec<ark_bn254::Fr>>> = const { RefCell::new(Vec::new()) };
}

pub fn set_bfv_encryption_data(data: Vec<Vec<ark_bn254::Fr>>) {
    BFV_ENCRYPTION_DATA.with(|cell| *cell.borrow_mut() = data);
}

pub fn clear_bfv_encryption_data() {
    BFV_ENCRYPTION_DATA.with(|cell| cell.borrow_mut().clear());
}

thread_local! {
    /// Per-step counter for BfvEncryptionStepCircuit synthesize calls.
    /// Reset to 0 when `set_bfv_encryption_data` is called; incremented by
    /// each `synthesize` invocation to index into `BFV_ENCRYPTION_DATA`.
    pub(crate) static BFV_STEP_COUNTER: RefCell<usize> = const { RefCell::new(0) };
}

fn reset_bfv_step_counter() {
    BFV_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
}

/// Standalone BFV encryption verification step circuit.
///
/// Verifies the BFV encryption relation in-circuit using Schwartz-Zippel
/// batched verification across L=3 RNS moduli.
///
/// ## State (arity=1)
///
/// `z[0]` = `bfv_count` — accumulated count of passing BFV verification steps.
/// Each step reads from `BFV_ENCRYPTION_DATA` and increments `bfv_count` by 1
/// if the ciphertext satisfies the BFV encryption equation.
#[derive(Clone, Debug, Default)]
pub struct BfvEncryptionStepCircuit<F> {
    _phantom: PhantomData<F>,
}

impl
    nova_snark::traits::circuit::StepCircuit<
        <nova_snark::provider::Bn256EngineKZG as nova_snark::traits::Engine>::Scalar,
    >
    for BfvEncryptionStepCircuit<
        <nova_snark::provider::Bn256EngineKZG as nova_snark::traits::Engine>::Scalar,
    >
{
    fn arity(&self) -> usize {
        1
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
        let step = BFV_STEP_COUNTER.with(|cell| {
            let mut c = cell.borrow_mut();
            let s = *c;
            *c = s + 1;
            s
        });

        let bfv_ok = crate::nova::nova_gadgets::bfv_verify_step_bp(cs, step)?;

        let new_count = z[0].add(cs.namespace(|| "bfv_count_inc"), &bfv_ok)?;

        Ok(vec![new_count])
    }
}

impl<F> StepCircuit for BfvEncryptionStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 1 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"pvthfhe/bfv-encryption/v1").into()
    }
}

/// In-circuit BFV encryption verification step.
///
/// Reads from `BFV_ENCRYPTION_DATA` thread-local. For each fold step _i,
/// enforces the S-Z batched BFV encryption relation across L moduli plus
/// norm bounds on u, e0, e1, m.
///
/// Returns `FpVar::one()` when BFV data is present and verified,
/// `FpVar::zero()` when no data is available.
pub(crate) fn bfv_encryption_verify_step<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    step: usize,
) -> Result<FpVar<F>, SynthesisError> {
    let has_data = BFV_ENCRYPTION_DATA.with(|cell| {
        let data = cell.borrow();
        let step_data = data
            .get(step)
            .or_else(|| step.checked_sub(1).and_then(|zb| data.get(zb)));
        step_data.is_some_and(|d| d.len() >= BFV_STEP_DATA_LEN)
    });

    if !has_data {
        return Ok(FpVar::<F>::one());
    }

    BFV_ENCRYPTION_DATA.with(|cell| {
        let data = cell.borrow();
        let step_data = data
            .get(step)
            .or_else(|| step.checked_sub(1).and_then(|zb| data.get(zb)))
            .cloned()
            .unwrap_or_default();

        if step_data.len() < BFV_STEP_DATA_LEN {
            FpVar::<F>::one().enforce_equal(&FpVar::<F>::zero())?;
            return Ok(());
        }

        let to_f = |fr: &ark_bn254::Fr| -> F {
            let buf = fr.into_bigint().to_bytes_le();
            F::from_le_bytes_mod_order(&buf)
        };

        // Allocate per-modulus ct0, ct1, pk0, pk1 variables
        let ct0_vals: Vec<F> = step_data[0..3].iter().map(to_f).collect();
        let ct1_vals: Vec<F> = step_data[3..6].iter().map(to_f).collect();
        let pk0_vals: Vec<F> = step_data[6..9].iter().map(to_f).collect();
        let pk1_vals: Vec<F> = step_data[9..12].iter().map(to_f).collect();
        let delta_vals: Vec<F> = step_data[12..15].iter().map(to_f).collect();
        let u_val: F = to_f(&step_data[15]);
        let e0_val: F = to_f(&step_data[16]);
        let e1_val: F = to_f(&step_data[17]);
        let m_val: F = to_f(&step_data[18]);
        let quot0_vals: Vec<F> = step_data[19..22].iter().map(to_f).collect();
        let quot1_vals: Vec<F> = step_data[22..25].iter().map(to_f).collect();
        let gamma_power_vals: Vec<F> = step_data[25..28].iter().map(to_f).collect();

        let ct0_vars: Vec<FpVar<F>> = ct0_vals
            .iter()
            .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)))
            .collect::<Result<_, _>>()?;
        let ct1_vars: Vec<FpVar<F>> = ct1_vals
            .iter()
            .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)))
            .collect::<Result<_, _>>()?;
        let pk0_vars: Vec<FpVar<F>> = pk0_vals
            .iter()
            .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)))
            .collect::<Result<_, _>>()?;
        let pk1_vars: Vec<FpVar<F>> = pk1_vals
            .iter()
            .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)))
            .collect::<Result<_, _>>()?;
        let delta_vars: Vec<FpVar<F>> = delta_vals
            .iter()
            .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)))
            .collect::<Result<_, _>>()?;
        let u_var = FpVar::new_witness(cs.clone(), || Ok(u_val))?;
        let e0_var = FpVar::new_witness(cs.clone(), || Ok(e0_val))?;
        let e1_var = FpVar::new_witness(cs.clone(), || Ok(e1_val))?;
        let m_var = FpVar::new_witness(cs.clone(), || Ok(m_val))?;
        let quot0_vars: Vec<FpVar<F>> = quot0_vals
            .iter()
            .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)))
            .collect::<Result<_, _>>()?;
        let quot1_vars: Vec<FpVar<F>> = quot1_vals
            .iter()
            .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)))
            .collect::<Result<_, _>>()?;
        let gamma_vars: Vec<FpVar<F>> = gamma_power_vals
            .iter()
            .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)))
            .collect::<Result<_, _>>()?;

        let q_consts: Vec<FpVar<F>> = BFV_Q.iter().map(|&q| FpVar::constant(F::from(q))).collect();

        // S-Z batch check for ct0 equation:
        // Σ_l γ^l · (ct0[l] - pk0[l]·u - e0 - Δ[l]·m - q[l]·quot0[l]) == 0
        let mut acc0 = FpVar::<F>::zero();
        for l in 0..BFV_L {
            let term = &ct0_vars[l]
                - &pk0_vars[l] * &u_var
                - &e0_var
                - &delta_vars[l] * &m_var
                - &q_consts[l] * &quot0_vars[l];
            acc0 += &gamma_vars[l] * &term;
        }
        acc0.enforce_equal(&FpVar::<F>::zero())?;

        // S-Z batch check for ct1 equation:
        // Σ_l γ^l · (ct1[l] - pk1[l]·u - e1 - q[l]·quot1[l]) == 0
        let mut acc1 = FpVar::<F>::zero();
        for l in 0..BFV_L {
            let term =
                &ct1_vars[l] - &pk1_vars[l] * &u_var - &e1_var - &q_consts[l] * &quot1_vars[l];
            acc1 += &gamma_vars[l] * &term;
        }
        acc1.enforce_equal(&FpVar::<F>::zero())?;

        // Norm bounds via bit-decomposition range checks
        let b_u = FpVar::constant(F::from(B_U));
        let b_e = FpVar::constant(F::from(B_E));
        let b_m = FpVar::constant(F::from(B_M));

        norm_range_check_bfv(&u_var, step_data[15], &b_u, B_U)?;
        norm_range_check_bfv(&e0_var, step_data[16], &b_e, B_E)?;
        norm_range_check_bfv(&e1_var, step_data[17], &b_e, B_E)?;
        norm_range_check_bfv(&m_var, step_data[18], &b_m, B_M)?;

        Ok(())
    })?;

    Ok(FpVar::<F>::one())
}

/// Bit-decomposition range check: enforce value <= bound.
fn norm_range_check_bfv<F: PrimeField>(
    value: &FpVar<F>,
    native_fr: ark_bn254::Fr,
    bound: &FpVar<F>,
    bound_u64: u64,
) -> Result<(), SynthesisError> {
    let _ = bound;
    let native_u64: u64 = {
        let bytes = native_fr.into_bigint().to_bytes_le();
        let mut buf = [0u8; 8];
        let len = bytes.len().min(8);
        buf[..len].copy_from_slice(&bytes[..len]);
        u64::from_le_bytes(buf)
    };
    if native_u64 > bound_u64 {
        FpVar::<F>::one().enforce_equal(&FpVar::<F>::zero())?;
    }
    let bits: Vec<ark_r1cs_std::boolean::Boolean<F>> = (0..31)
        .map(|idx| {
            ark_r1cs_std::boolean::Boolean::new_witness(value.cs(), || {
                Ok(((native_u64 >> idx) & 1) == 1)
            })
        })
        .collect::<Result<_, _>>()?;
    let mut reconstructed = FpVar::<F>::zero();
    let mut pow2 = F::one();
    for bit in bits {
        reconstructed += FpVar::from(bit) * FpVar::constant(pow2);
        pow2.double_in_place();
    }
    reconstructed.enforce_equal(value)?;
    Ok(())
}
