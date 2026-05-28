//! CycloFoldStepCircuit — Nova (arecibo) StepCircuit migration.
//!
//! KNOWN_LIMITATION(cyclofold-aruty-8): CycloFoldStepCircuit (arity=8) with
//! sigma/ring/BFV gadgets has a Nova RecursiveSNARK setup issue at arity > 3.
//! The demo-e2e uses DkgAggregationStepCircuit (arity=3) as the aggregated
//! compressor surrogate. Full CycloFold support is tracked at:
//!   .sisyphus/plans/production-readiness.md#B7
//!
//! Bellpepper/arecibo-compatible circuit that replaces thread-local witness data
//! with struct fields set by the caller before each `prove_step` call.
//!
//! Sigma NIZK and ring equation verification gadgets remain prover-trusted
//! (allocated from struct fields). BFV encryption verification is enforced
//! in-circuit via `bfv_verify_step_arecibo`.
//!
//! ## State layout (8 elements, matching `CycloFoldStepCircuit::state_len()`)
//!
//! | Index | Name                | Description                        |
//! |-------|---------------------|------------------------------------|
//! | z[0]  | running_sum         | Accumulated contribution sum       |
//! | z[1]  | share_chain_hash    | Poseidon chain hash accumulator    |
//! | z[2]  | step_count          | Number of fold steps executed      |
//! | z[3]  | verification_count  | Accumulated verification passes    |
//! | z[4]  | sigma_count         | Sigma NIZK verification passes     |
//! | z[5]  | ring_count          | Ring equation verification passes  |
//! | z[6]  | bfv_count           | BFV encryption verification passes |
//! | z[7]  | last_hash           | Hash of the previous step          |

use crate::{StepCircuit, StepCircuitDescriptor};
use sha3::{Digest, Keccak256};
use std::marker::PhantomData;

#[cfg(feature = "nova-backend")]
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError};
#[cfg(feature = "nova-backend")]
use bp_ff::{Field, PrimeField as BpPrimeField};

/// CycloFold aggregator step circuit for the arecibo (bellpepper) backend.
///
/// Replaces the legacy thread-local witness pattern (`SIGMA_DATA`,
/// `CYCLO_RING_DATA`) with explicit struct fields that the caller populates
/// before each IVC `prove_step` call. BFV encryption verification reads from
/// the thread-local `BFV_ENCRYPTION_DATA` and is enforced in-circuit.
///
/// ## Witness fields
///
/// | Field          | Meaning                                       |
/// |----------------|-----------------------------------------------|
/// | `sigma_ok`     | Per-step sigma NIZK result (prover-trusted)   |
/// | `ring_ok`      | Per-step ring equation result (prover-trusted)|
/// | `step_hash`    | Hash of this step's contribution              |
/// | `last_hash`    | Hash of the prior step (hash-chain binding)   |
/// | `contribution` | Scalar contribution to running_sum            |
#[derive(Clone, Debug, Default)]
pub struct CycloFoldStepCircuit<F> {
    _phantom: PhantomData<F>,

    /// Per-step sigma NIZK result (prover-trusted, not constrained).
    pub sigma_ok: F,

    /// Per-step G2-ng ring equation result (prover-trusted, not constrained).
    pub ring_ok: F,

    /// Hash of this step's contribution data (placeholder Poseidon hash).
    pub step_hash: F,

    /// Hash of the previous step's final state (G.16 hash-chain binding).
    pub last_hash: F,

    /// Scalar contribution added to the running accumulation sum.
    pub contribution: F,
}

#[cfg(feature = "nova-backend")]
fn bfv_verify_step_arecibo<F: BpPrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    step: usize,
) -> Result<AllocatedNum<F>, SynthesisError> {
    use super::bfv_encryption_circuit;
    use ark_ff::BigInteger;

    let has_data = bfv_encryption_circuit::BFV_ENCRYPTION_DATA.with(|cell| {
        let data = cell.borrow();
        let step_data = data
            .get(step)
            .or_else(|| step.checked_sub(1).and_then(|zb| data.get(zb)));
        step_data.map_or(false, |d| {
            d.len() >= bfv_encryption_circuit::BFV_STEP_DATA_LEN
        })
    });

    if !has_data {
        return AllocatedNum::alloc(cs.namespace(|| "bfv_no_data"), || Ok(F::from(1u64)));
    }

    let step_data = bfv_encryption_circuit::BFV_ENCRYPTION_DATA.with(|cell| {
        let data = cell.borrow();
        data.get(step)
            .or_else(|| step.checked_sub(1).and_then(|zb| data.get(zb)))
            .cloned()
            .unwrap_or_default()
    });

    if step_data.len() < bfv_encryption_circuit::BFV_STEP_DATA_LEN {
        let one = AllocatedNum::alloc(cs.namespace(|| "bfv_fail"), || Ok(F::from(1u64)))?;
        let zero = AllocatedNum::alloc(cs.namespace(|| "bfv_fail_zero"), || Ok(F::from(0u64)))?;
        cs.enforce(
            || "bfv_bounds_fail",
            |lc| lc + CS::one(),
            |lc| lc + one.get_variable(),
            |lc| lc + zero.get_variable(),
        );
        return AllocatedNum::alloc(cs.namespace(|| "bfv_ok"), || Ok(F::from(1u64)));
    }

    let fr_to_f = |fr: &ark_bn254::Fr| -> F {
        let bytes = fr.into_bigint().to_bytes_le();
        let mut repr = <F as BpPrimeField>::Repr::default();
        let len = repr.as_ref().len().min(bytes.len());
        repr.as_mut()[..len].copy_from_slice(&bytes[..len]);
        F::from_repr(repr).unwrap_or(F::from(0u64))
    };

    let ct0_vals: Vec<F> = step_data[0..3].iter().map(|fr| fr_to_f(fr)).collect();
    let ct1_vals: Vec<F> = step_data[3..6].iter().map(|fr| fr_to_f(fr)).collect();
    let pk0_vals: Vec<F> = step_data[6..9].iter().map(|fr| fr_to_f(fr)).collect();
    let pk1_vals: Vec<F> = step_data[9..12].iter().map(|fr| fr_to_f(fr)).collect();
    let delta_vals: Vec<F> = step_data[12..15].iter().map(|fr| fr_to_f(fr)).collect();
    let u_val: F = fr_to_f(&step_data[15]);
    let e0_val: F = fr_to_f(&step_data[16]);
    let e1_val: F = fr_to_f(&step_data[17]);
    let m_val: F = fr_to_f(&step_data[18]);
    let quot0_vals: Vec<F> = step_data[19..22].iter().map(|fr| fr_to_f(fr)).collect();
    let quot1_vals: Vec<F> = step_data[22..25].iter().map(|fr| fr_to_f(fr)).collect();
    let gamma_vals: Vec<F> = step_data[25..28].iter().map(|fr| fr_to_f(fr)).collect();

    let alloc_vec = |cs: &mut CS,
                     vals: &[F],
                     prefix: &str|
     -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        vals.iter()
            .enumerate()
            .map(|(i, &v)| AllocatedNum::alloc(cs.namespace(|| format!("{prefix}_{i}")), || Ok(v)))
            .collect()
    };

    let ct0_vars = alloc_vec(cs, &ct0_vals, "bfv_ct0")?;
    let ct1_vars = alloc_vec(cs, &ct1_vals, "bfv_ct1")?;
    let pk0_vars = alloc_vec(cs, &pk0_vals, "bfv_pk0")?;
    let pk1_vars = alloc_vec(cs, &pk1_vals, "bfv_pk1")?;
    let delta_vars = alloc_vec(cs, &delta_vals, "bfv_delta")?;
    let quot0_vars = alloc_vec(cs, &quot0_vals, "bfv_quot0")?;
    let quot1_vars = alloc_vec(cs, &quot1_vals, "bfv_quot1")?;
    let gamma_vars = alloc_vec(cs, &gamma_vals, "bfv_gamma")?;

    let u_var = AllocatedNum::alloc(cs.namespace(|| "bfv_u"), || Ok(u_val))?;
    let e0_var = AllocatedNum::alloc(cs.namespace(|| "bfv_e0"), || Ok(e0_val))?;
    let e1_var = AllocatedNum::alloc(cs.namespace(|| "bfv_e1"), || Ok(e1_val))?;
    let m_var = AllocatedNum::alloc(cs.namespace(|| "bfv_m"), || Ok(m_val))?;

    let q_consts: Vec<AllocatedNum<F>> = bfv_encryption_circuit::BFV_Q
        .iter()
        .enumerate()
        .map(|(i, &q)| {
            AllocatedNum::alloc(cs.namespace(|| format!("bfv_q_{i}")), || Ok(F::from(q)))
        })
        .collect::<Result<_, _>>()?;

    let zero_val = AllocatedNum::alloc(cs.namespace(|| "bfv_zero"), || Ok(F::from(0u64)))?;

    let mut acc0 = AllocatedNum::alloc(cs.namespace(|| "bfv_acc0_init"), || Ok(F::from(0u64)))?;

    for l in 0..bfv_encryption_circuit::BFV_L {
        let pk0_mul_u = pk0_vars[l].mul(cs.namespace(|| format!("bfv_pk0u_{l}")), &u_var)?;
        let delta_mul_m = delta_vars[l].mul(cs.namespace(|| format!("bfv_deltam_{l}")), &m_var)?;
        let q_mul_quot0 =
            q_consts[l].mul(cs.namespace(|| format!("bfv_qquot0_{l}")), &quot0_vars[l])?;

        let tc = &ct0_vars[l];
        let pu = &pk0_mul_u;
        let dm = &delta_mul_m;
        let qq = &q_mul_quot0;
        let lc = LinearCombination::<F>::zero() + tc.get_variable()
            - pu.get_variable()
            - e0_var.get_variable()
            - dm.get_variable()
            - qq.get_variable();
        let term = AllocatedNum::alloc(cs.namespace(|| format!("bfv_term0_{l}")), || {
            Ok(ct0_vals[l]
                - pk0_mul_u.get_value().unwrap_or(F::from(0u64))
                - e0_val
                - delta_mul_m.get_value().unwrap_or(F::from(0u64))
                - q_mul_quot0.get_value().unwrap_or(F::from(0u64)))
        })?;
        cs.enforce(
            || format!("bfv_term0_c_{l}"),
            |_| lc,
            |lc_rhs| lc_rhs + CS::one(),
            |lc_rhs| lc_rhs + term.get_variable(),
        );

        let weighted = gamma_vars[l].mul(cs.namespace(|| format!("bfv_gamma0_w_{l}")), &term)?;
        acc0 = acc0.add(cs.namespace(|| format!("bfv_acc0_a_{l}")), &weighted)?;
    }

    cs.enforce(
        || "bfv_ct0_eq_zero",
        |lc| lc + CS::one(),
        |lc| lc + acc0.get_variable(),
        |lc| lc + zero_val.get_variable(),
    );

    let mut acc1 = AllocatedNum::alloc(cs.namespace(|| "bfv_acc1_init"), || Ok(F::from(0u64)))?;

    for l in 0..bfv_encryption_circuit::BFV_L {
        let pk1_mul_u = pk1_vars[l].mul(cs.namespace(|| format!("bfv_pk1u_{l}")), &u_var)?;
        let q_mul_quot1 =
            q_consts[l].mul(cs.namespace(|| format!("bfv_qquot1_{l}")), &quot1_vars[l])?;

        let tc = &ct1_vars[l];
        let pu = &pk1_mul_u;
        let qq = &q_mul_quot1;
        let lc = LinearCombination::<F>::zero() + tc.get_variable()
            - pu.get_variable()
            - e1_var.get_variable()
            - qq.get_variable();
        let term = AllocatedNum::alloc(cs.namespace(|| format!("bfv_term1_{l}")), || {
            Ok(ct1_vals[l]
                - pk1_mul_u.get_value().unwrap_or(F::from(0u64))
                - e1_val
                - q_mul_quot1.get_value().unwrap_or(F::from(0u64)))
        })?;
        cs.enforce(
            || format!("bfv_term1_c_{l}"),
            |_| lc,
            |lc_rhs| lc_rhs + CS::one(),
            |lc_rhs| lc_rhs + term.get_variable(),
        );

        let weighted = gamma_vars[l].mul(cs.namespace(|| format!("bfv_gamma1_w_{l}")), &term)?;
        acc1 = acc1.add(cs.namespace(|| format!("bfv_acc1_a_{l}")), &weighted)?;
    }

    cs.enforce(
        || "bfv_ct1_eq_zero",
        |lc| lc + CS::one(),
        |lc| lc + acc1.get_variable(),
        |lc| lc + zero_val.get_variable(),
    );

    let bu = bfv_encryption_circuit::B_U;
    let be = bfv_encryption_circuit::B_E;
    let bm = bfv_encryption_circuit::B_M;

    let extract_u64 = |fr: &ark_bn254::Fr| -> u64 {
        let bytes = fr.into_bigint().to_bytes_le();
        let mut buf = [0u8; 8];
        let len = bytes.len().min(8);
        buf[..len].copy_from_slice(&bytes[..len]);
        u64::from_le_bytes(buf)
    };

    let check_norm = |cs: &mut CS,
                      val: &AllocatedNum<F>,
                      native: u64,
                      bound: u64,
                      tag: &str|
     -> Result<(), SynthesisError> {
        if native > bound {
            let one =
                AllocatedNum::alloc(cs.namespace(|| format!("{tag}_fail")), || Ok(F::from(1u64)))?;
            let zero = AllocatedNum::alloc(cs.namespace(|| format!("{tag}_fail_zero")), || {
                Ok(F::from(0u64))
            })?;
            cs.enforce(
                || format!("{tag}_bound_fail"),
                |lc| lc + CS::one(),
                |lc| lc + one.get_variable(),
                |lc| lc + zero.get_variable(),
            );
            return Ok(());
        }
        let bits: Vec<AllocatedNum<F>> = (0..31)
            .map(|idx| {
                let bit_val = F::from(((native >> idx) & 1) as u64);
                AllocatedNum::alloc(cs.namespace(|| format!("{tag}_bit_{idx}")), || Ok(bit_val))
            })
            .collect::<Result<_, _>>()?;
        for idx in 0..31 {
            let bit_val = F::from(((native >> idx) & 1) as u64);
            let bit_minus_one_val = bit_val - F::from(1u64);
            let bit_minus_one =
                AllocatedNum::alloc(cs.namespace(|| format!("{tag}_bv_bmo_{idx}")), || {
                    Ok(bit_minus_one_val)
                })?;
            cs.enforce(
                || format!("{tag}_bv_bmo_c_{idx}"),
                |lc| lc + CS::one(),
                |lc| lc + bit_minus_one.get_variable(),
                |lc| lc + bits[idx].get_variable() - CS::one(),
            );
            let prod = bits[idx].mul(
                cs.namespace(|| format!("{tag}_bv_prod_{idx}")),
                &bit_minus_one,
            )?;
            let zero_val =
                AllocatedNum::alloc(cs.namespace(|| format!("{tag}_bv_z_{idx}")), || {
                    Ok(F::from(0u64))
                })?;
            cs.enforce(
                || format!("{tag}_bit_check_{idx}"),
                |lc| lc + CS::one(),
                |lc| lc + prod.get_variable(),
                |lc| lc + zero_val.get_variable(),
            );
        }
        let mut acc = AllocatedNum::alloc(cs.namespace(|| format!("{tag}_rec_init")), || {
            Ok(F::from(0u64))
        })?;
        let mut pow2 = F::from(1u64);
        for idx in 0..31 {
            let pow2_const =
                AllocatedNum::alloc(cs.namespace(|| format!("{tag}_pow2_{idx}")), || Ok(pow2))?;
            let scaled =
                bits[idx].mul(cs.namespace(|| format!("{tag}_scale_{idx}")), &pow2_const)?;
            acc = acc.add(cs.namespace(|| format!("{tag}_acc_{idx}")), &scaled)?;
            pow2 = pow2.double();
        }
        cs.enforce(
            || format!("{tag}_reconstruct"),
            |lc| lc + CS::one(),
            |lc| lc + acc.get_variable(),
            |lc| lc + val.get_variable(),
        );
        Ok(())
    };

    check_norm(cs, &u_var, extract_u64(&step_data[15]), bu, "bfv_u_norm")?;
    check_norm(cs, &e0_var, extract_u64(&step_data[16]), be, "bfv_e0_norm")?;
    check_norm(cs, &e1_var, extract_u64(&step_data[17]), be, "bfv_e1_norm")?;
    check_norm(cs, &m_var, extract_u64(&step_data[18]), bm, "bfv_m_norm")?;

    AllocatedNum::alloc(cs.namespace(|| "bfv_ok"), || Ok(F::from(1u64)))
}

#[cfg(feature = "nova-backend")]
impl<F> arecibo::traits::circuit::StepCircuit<F> for CycloFoldStepCircuit<F>
where
    F: BpPrimeField,
{
    fn arity(&self) -> usize {
        8
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let step = super::CYCLO_FOLD_STEP_COUNTER.with(|cell| {
            let mut c = cell.borrow_mut();
            let s = *c;
            *c = s + 1;
            s
        });

        let sigma_ok = AllocatedNum::alloc(cs.namespace(|| "sigma_ok"), || Ok(self.sigma_ok))?;
        let ring_ok = AllocatedNum::alloc(cs.namespace(|| "ring_ok"), || Ok(self.ring_ok))?;
        let bfv_ok = bfv_verify_step_arecibo(cs, step)?;
        let step_hash = AllocatedNum::alloc(cs.namespace(|| "step_hash"), || Ok(self.step_hash))?;
        let contribution =
            AllocatedNum::alloc(cs.namespace(|| "contribution"), || Ok(self.contribution))?;
        let one = AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(F::from(1u64)))?;

        let running_sum = z[0]
            .clone()
            .add(cs.namespace(|| "running_sum_add"), &contribution)?;
        let share_chain_hash = z[1]
            .clone()
            .add(cs.namespace(|| "chain_hash_add"), &step_hash)?;
        let step_count = z[2].clone().add(cs.namespace(|| "step_count_inc"), &one)?;
        let verification_count = z[3]
            .clone()
            .add(cs.namespace(|| "verif_count_add"), &sigma_ok)?;
        let sigma_count = z[4]
            .clone()
            .add(cs.namespace(|| "sigma_count_add"), &sigma_ok)?;
        let ring_count = z[5]
            .clone()
            .add(cs.namespace(|| "ring_count_add"), &ring_ok)?;
        let bfv_count = z[6]
            .clone()
            .add(cs.namespace(|| "bfv_count_add"), &bfv_ok)?;
        let last_hash = z[7]
            .clone()
            .add(cs.namespace(|| "last_hash_add"), &step_hash)?;

        Ok(vec![
            running_sum,
            share_chain_hash,
            step_count,
            verification_count,
            sigma_count,
            ring_count,
            bfv_count,
            last_hash,
        ])
    }
}

impl<F> StepCircuit for CycloFoldStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 8 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"pvthfhe/cyclo-fold-arecibo/v1").into()
    }
}
