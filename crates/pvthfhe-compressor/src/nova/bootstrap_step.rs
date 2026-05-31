use std::cell::RefCell;
use std::marker::PhantomData;

use ark_bn254::Fr as ark_Fr;
use ark_ff::PrimeField;
use nova_snark::frontend::num::AllocatedNum;
use nova_snark::frontend::{ConstraintSystem, SynthesisError};
use sha3::{Digest, Keccak256};

use crate::nova::NovaScalar;
use crate::{StepCircuit, StepCircuitDescriptor};
use pvthfhe_domain_tags::Tag;

use super::monomial_range;

thread_local! {
    pub(crate) static BOOTSTRAP_DATA: RefCell<Vec<BootstrapStepWitness>> =
        const { RefCell::new(Vec::new()) };
}

thread_local! {
    pub(crate) static BOOTSTRAP_STEP_COUNTER: RefCell<usize> =
        const { RefCell::new(0) };
}

#[derive(Clone, Debug, Default)]
pub struct BootstrapStepWitness {
    pub c_eval: u64,
    pub zs_eval: u64,
    pub ze_eval: u64,
    pub t_eval: u64,
    pub di_eval: u64,
    pub ch: i64,
    pub r1_eval: u64,
    pub modulus: u64,
    pub zs_norm_check: u64,
    pub ze_norm_check: u64,
}

pub fn set_bootstrap_data(data: Vec<BootstrapStepWitness>) {
    BOOTSTRAP_DATA.with(|cell| *cell.borrow_mut() = data);
    BOOTSTRAP_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
}

pub fn clear_bootstrap_data() {
    BOOTSTRAP_DATA.with(|cell| cell.borrow_mut().clear());
    BOOTSTRAP_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
}

pub fn reset_bootstrap_step_counter() {
    BOOTSTRAP_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
}

#[derive(Clone, Debug)]
pub struct BootstrapStepCircuit<F> {
    _phantom: PhantomData<F>,
}

impl<F> Default for BootstrapStepCircuit<F> {
    fn default() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<F> BootstrapStepCircuit<F> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<F: PrimeField> StepCircuit for BootstrapStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 1 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(Tag::NovaBootstrapStep.as_bytes()).into()
    }
}

const ZS_BOUND: u64 = 131_072;
const ZE_BOUND: u64 = 131_072;

impl
    nova_snark::traits::circuit::StepCircuit<
        <nova_snark::provider::Bn256EngineKZG as nova_snark::traits::Engine>::Scalar,
    > for BootstrapStepCircuit<ark_Fr>
{
    fn arity(&self) -> usize {
        1
    }

    fn synthesize<CS: ConstraintSystem<NovaScalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<NovaScalar>],
    ) -> Result<Vec<AllocatedNum<NovaScalar>>, SynthesisError> {
        let raw_step = BOOTSTRAP_STEP_COUNTER.with(|cell| {
            let mut c = cell.borrow_mut();
            let s = *c;
            *c = s + 1;
            s
        });

        let step = BOOTSTRAP_DATA.with(|cell| {
            let len = cell.borrow().len();
            if len == 0 {
                raw_step
            } else {
                raw_step % len
            }
        });

        let has_data = BOOTSTRAP_DATA.with(|cell| {
            let data = cell.borrow();
            data.get(step).is_some()
        });

        if !has_data {
            return Ok(vec![z[0].clone()]);
        }

        let w = BOOTSTRAP_DATA.with(|cell| {
            let data = cell.borrow();
            data.get(step).cloned().unwrap_or_default()
        });

        let base = format!("bs_s{step}");

        let c_val = NovaScalar::from(w.c_eval);
        let zs_val = NovaScalar::from(w.zs_eval);
        let ze_val = NovaScalar::from(w.ze_eval);
        let t_val = NovaScalar::from(w.t_eval);
        let di_val = NovaScalar::from(w.di_eval);
        let r1_val = NovaScalar::from(w.r1_eval);

        let ch_val = match w.ch {
            -1 => -NovaScalar::from(1u64),
            0 => NovaScalar::from(0u64),
            1 => NovaScalar::from(1u64),
            _ => return Err(SynthesisError::AssignmentMissing),
        };

        let q_val = NovaScalar::from(w.modulus);

        let c_var = allocate_ns(cs, &format!("{base}_c"), c_val)?;
        let zs_var = allocate_ns(cs, &format!("{base}_zs"), zs_val)?;
        let ze_var = allocate_ns(cs, &format!("{base}_ze"), ze_val)?;
        let t_var = allocate_ns(cs, &format!("{base}_t"), t_val)?;
        let di_var = allocate_ns(cs, &format!("{base}_di"), di_val)?;
        let r1_var = allocate_ns(cs, &format!("{base}_r1"), r1_val)?;
        let ch_var = allocate_ns(cs, &format!("{base}_ch"), ch_val)?;
        let q_var = allocate_ns(cs, &format!("{base}_q"), q_val)?;

        let prod = c_var.mul(cs.namespace(|| format!("{base}_c_zs")), &zs_var)?;
        let lhs = prod.add(cs.namespace(|| format!("{base}_lhs0")), &ze_var)?;
        let ch_di = ch_var.mul(cs.namespace(|| format!("{base}_ch_di")), &di_var)?;
        let t_ch = t_var.add(cs.namespace(|| format!("{base}_t_ch")), &ch_di)?;
        let q_r1 = q_var.mul(cs.namespace(|| format!("{base}_q_r1")), &r1_var)?;
        let rhs = t_ch.add(cs.namespace(|| format!("{base}_rhs0")), &q_r1)?;

        cs.enforce(
            || format!("{base}_sigma_eq"),
            |lc| lc + lhs.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + rhs.get_variable(),
        );

        monomial_range::monomial_range_check_bp(
            cs,
            &zs_var,
            w.zs_norm_check,
            ZS_BOUND,
            &format!("{base}_zs"),
        )?;
        monomial_range::monomial_range_check_bp(
            cs,
            &ze_var,
            w.ze_norm_check,
            ZE_BOUND,
            &format!("{base}_ze"),
        )?;

        let accum_val = NovaScalar::from(
            ((w.c_eval as u128)
                .wrapping_add(w.zs_eval as u128)
                .wrapping_add(w.ze_eval as u128)
                .wrapping_add(w.t_eval as u128)
                .wrapping_add(w.di_eval as u128)
                .wrapping_add(w.r1_eval as u128)
                % (u64::MAX as u128)) as u64,
        );

        let accum = allocate_ns(cs, &format!("{base}_hash_val"), accum_val)?;

        let new_state = z[0].add(cs.namespace(|| format!("{base}_add")), &accum)?;

        Ok(vec![new_state])
    }
}

fn allocate_ns<CS: ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    label: &str,
    value: NovaScalar,
) -> Result<AllocatedNum<NovaScalar>, SynthesisError> {
    AllocatedNum::alloc(cs.namespace(|| label.to_string()), || Ok(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_step_descriptor() {
        let circuit = BootstrapStepCircuit::<ark_Fr>::new();
        assert_eq!(circuit.descriptor().width, 1);
    }

    #[test]
    fn test_bootstrap_step_witness_defaults() {
        let w = BootstrapStepWitness::default();
        assert_eq!(w.c_eval, 0);
        assert_eq!(w.zs_eval, 0);
        assert_eq!(w.ch, 0);
    }
}
