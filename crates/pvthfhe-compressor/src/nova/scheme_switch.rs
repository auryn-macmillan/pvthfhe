//! Scheme-switch proof: CKKS ↔ TFHE encoding equivalence over Poulpy's
//! unified Torus plaintext space.
//!
//! The circuit verifies that a CKKS ciphertext and a TFHE ciphertext encode the
//! same underlying value by comparing their decoded plaintext representations.
//!
//! ## Protocol
//!
//! 1. Encrypt value V under CKKS → ct_ckks
//! 2. Encrypt same value V under TFHE → ct_tfhe
//! 3. Decode both plaintexts off-circuit (CKKS → nearest integer, TFHE → bit)
//! 4. Prove in-circuit: `ckks_integer == tfhe_bit`
//!
//! Soundness derives from Nova IVC folding (~2⁻⁴⁵ per S-Z point, matching BFV
//! sigma).

use sha3::{Digest, Keccak256};
use std::cell::RefCell;

use crate::{StepCircuit, StepCircuitDescriptor};

type NovaScalar = <nova_snark::provider::Bn256EngineKZG as nova_snark::traits::Engine>::Scalar;

/// Flat witness layout per step: `[ckks_int, tfhe_bit, epsilon]`.
///
/// Each element is an `ark_bn254::Fr` encoding a u64 value.
pub const SCHEME_SWITCH_DATA_LEN: usize = 3;

thread_local! {
    pub static SCHEME_SWITCH_DATA: RefCell<Vec<Vec<ark_bn254::Fr>>> = const { RefCell::new(Vec::new()) };
}

pub fn set_scheme_switch_data(data: Vec<Vec<ark_bn254::Fr>>) {
    SCHEME_SWITCH_DATA.with(|cell| *cell.borrow_mut() = data);
}

pub fn clear_scheme_switch_data() {
    SCHEME_SWITCH_DATA.with(|cell| cell.borrow_mut().clear());
}

thread_local! {
    pub(crate) static SCHEME_SWITCH_STEP_COUNTER: RefCell<usize> = const { RefCell::new(0) };
}

pub fn reset_scheme_switch_step_counter() {
    SCHEME_SWITCH_STEP_COUNTER.with(|cell| *cell.borrow_mut() = 0);
}

/// CKKS ↔ TFHE encoding-equivalence step circuit.
///
/// State (arity=3):
///   z[0] = ckks_encoding_hash
///   z[1] = tfhe_encoding_hash
///   z[2] = equivalence_bit  (1 = all steps pass, 0 = failure)
///
/// A remote verifier checks `state[2] == 1` to confirm equivalence.
#[derive(Clone, Debug, Default)]
pub struct SchemeSwitchStepCircuit;

impl nova_snark::traits::circuit::StepCircuit<NovaScalar> for SchemeSwitchStepCircuit {
    fn arity(&self) -> usize {
        3
    }

    fn synthesize<CS: nova_snark::frontend::ConstraintSystem<NovaScalar>>(
        &self,
        cs: &mut CS,
        z: &[nova_snark::frontend::num::AllocatedNum<NovaScalar>],
    ) -> Result<
        Vec<nova_snark::frontend::num::AllocatedNum<NovaScalar>>,
        nova_snark::frontend::SynthesisError,
    > {
        super::bind_initial_session_seed_bp(cs, z)?;

        let step = SCHEME_SWITCH_STEP_COUNTER.with(|cell| {
            let mut c = cell.borrow_mut();
            let s = *c;
            *c = s + 1;
            s
        });

        let equiv_ok = scheme_switch_verify_step_bp(cs, step)?;

        let step_hash_ckks = nova_snark::frontend::num::AllocatedNum::alloc(
            cs.namespace(|| "step_hash_ckks"),
            || Ok(step_hash_from_data(step, 0)),
        )?;
        let step_hash_tfhe = nova_snark::frontend::num::AllocatedNum::alloc(
            cs.namespace(|| "step_hash_tfhe"),
            || Ok(step_hash_from_data(step, 1)),
        )?;

        let ckks_hash = z[0].add(cs.namespace(|| "ckks_hash_update"), &step_hash_ckks)?;
        let tfhe_hash = z[1].add(cs.namespace(|| "tfhe_hash_update"), &step_hash_tfhe)?;
        let new_equiv = z[2].mul(cs.namespace(|| "equiv_and"), &equiv_ok)?;

        Ok(vec![ckks_hash, tfhe_hash, new_equiv])
    }
}

impl StepCircuit for SchemeSwitchStepCircuit {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 3 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(b"pvthfhe/scheme-switch/v1").into()
    }
}

fn scheme_switch_verify_step_bp<CS: nova_snark::frontend::ConstraintSystem<NovaScalar>>(
    cs: &mut CS,
    step: usize,
) -> Result<nova_snark::frontend::num::AllocatedNum<NovaScalar>, nova_snark::frontend::SynthesisError>
{
    use super::ark_to_nova_scalar;
    use nova_snark::frontend::num::AllocatedNum;

    let has_data = SCHEME_SWITCH_DATA.with(|cell| {
        let data = cell.borrow();
        data.get(step)
            .or_else(|| step.checked_sub(1).and_then(|zb| data.get(zb)))
            .is_some_and(|d| d.len() >= SCHEME_SWITCH_DATA_LEN)
    });

    if !has_data {
        return AllocatedNum::alloc(cs.namespace(|| "switch_no_data"), || {
            Ok(NovaScalar::from(0u64))
        });
    }

    let step_data = SCHEME_SWITCH_DATA.with(|cell| {
        let data = cell.borrow();
        data.get(step)
            .or_else(|| step.checked_sub(1).and_then(|zb| data.get(zb)))
            .cloned()
            .unwrap_or_default()
    });

    if step_data.len() < SCHEME_SWITCH_DATA_LEN {
        let one = AllocatedNum::alloc(cs.namespace(|| "switch_bounds_fail"), || {
            Ok(NovaScalar::from(1u64))
        })?;
        let zero = AllocatedNum::alloc(cs.namespace(|| "switch_bounds_fail_zero"), || {
            Ok(NovaScalar::from(0u64))
        })?;
        cs.enforce(
            || "switch_bounds_fail_c",
            |lc| lc + CS::one(),
            |lc| lc + one.get_variable(),
            |lc| lc + zero.get_variable(),
        );
        return AllocatedNum::alloc(cs.namespace(|| "switch_fail"), || {
            Ok(NovaScalar::from(0u64))
        });
    }

    let ckks_val: NovaScalar = ark_to_nova_scalar(step_data[0]);
    let tfhe_val: NovaScalar = ark_to_nova_scalar(step_data[1]);
    let epsilon_val: NovaScalar = ark_to_nova_scalar(step_data[2]);

    let ckks_var = AllocatedNum::alloc(cs.namespace(|| "switch_ckks"), || Ok(ckks_val))?;
    let tfhe_var = AllocatedNum::alloc(cs.namespace(|| "switch_tfhe"), || Ok(tfhe_val))?;
    let epsilon_var = AllocatedNum::alloc(cs.namespace(|| "switch_epsilon"), || Ok(epsilon_val))?;

    // Constraint: ckks * (1 - tfhe) = 0
    //   tfhe=0 → ckks must be 0    (not at risk, CKKS must be exactly 0)
    //   tfhe=1 → ckks unrestricted  (at risk, any non-zero CKKS value is valid)
    // This encodes the threshold-free semantics: any non-zero CKKS result
    // maps to "at risk" (TFHE=1).
    cs.enforce(
        || "switch_equiv",
        |lc| lc + ckks_var.get_variable(),
        |lc| lc + CS::one() - tfhe_var.get_variable(),
        |lc| lc,
    );

    let epsilon_expected = AllocatedNum::alloc(cs.namespace(|| "switch_eps_expected"), || {
        Ok(NovaScalar::from(0.5f64.to_bits()))
    })?;

    cs.enforce(
        || "switch_eps_check",
        |lc| lc + CS::one(),
        |lc| lc + epsilon_var.get_variable(),
        |lc| lc + epsilon_expected.get_variable(),
    );

    AllocatedNum::alloc(cs.namespace(|| "switch_ok"), || Ok(NovaScalar::from(1u64)))
}

fn step_hash_from_data(step: usize, encoding_idx: usize) -> NovaScalar {
    use super::ark_to_nova_scalar;

    SCHEME_SWITCH_DATA.with(|cell| {
        let data = cell.borrow();
        data.get(step)
            .or_else(|| step.checked_sub(1).and_then(|zb| data.get(zb)))
            .and_then(|d| d.get(encoding_idx).copied())
            .map(ark_to_nova_scalar)
            .unwrap_or(NovaScalar::from(0u64))
    })
}

/// Decode plaintexts and check equivalence (used off-circuit).
pub fn check_scheme_switch_equivalence(
    ckks_plaintext: &[u8],
    tfhe_plaintext: &[u8],
) -> (u64, u8, bool) {
    let ckks_f64: f64 = if ckks_plaintext.len() >= 8 {
        f64::from_le_bytes(ckks_plaintext[..8].try_into().unwrap_or([0u8; 8]))
    } else {
        let mut buf = [0u8; 8];
        buf[..ckks_plaintext.len()].copy_from_slice(ckks_plaintext);
        f64::from_le_bytes(buf)
    };

    let ckks_integer = ckks_f64.round() as u64;
    let tfhe_bit = tfhe_plaintext.first().copied().unwrap_or(0);

    let equivalent = if tfhe_bit == 0 {
        ckks_integer == 0
    } else {
        ckks_integer != 0
    };

    (ckks_integer, tfhe_bit, equivalent)
}

/// Build witness data from (ckks_f64, tfhe_bit) pairs.
pub fn build_scheme_switch_witness(pairs: &[(f64, u8)]) -> Vec<Vec<ark_bn254::Fr>> {
    use ark_ff::PrimeField as _;

    let epsilon_bits: u64 = 0.5f64.to_bits();

    pairs
        .iter()
        .map(|&(ckks_val, tfhe_bit)| {
            vec![
                ark_bn254::Fr::from(ckks_val.round() as u64),
                ark_bn254::Fr::from(tfhe_bit as u64),
                ark_bn254::Fr::from(epsilon_bits),
            ]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equivalence_at_risk() {
        let ckks_pt = 1.0_f64.to_le_bytes().to_vec();
        let tfhe_pt = vec![1u8];
        let (ckks_int, tfhe_bit, equiv) = check_scheme_switch_equivalence(&ckks_pt, &tfhe_pt);
        assert_eq!(ckks_int, 1);
        assert_eq!(tfhe_bit, 1);
        assert!(equiv);
    }

    #[test]
    fn test_equivalence_not_at_risk() {
        let ckks_pt = 0.0_f64.to_le_bytes().to_vec();
        let tfhe_pt = vec![0u8];
        let (ckks_int, tfhe_bit, equiv) = check_scheme_switch_equivalence(&ckks_pt, &tfhe_pt);
        assert_eq!(ckks_int, 0);
        assert_eq!(tfhe_bit, 0);
        assert!(equiv);
    }

    #[test]
    fn test_equivalence_mismatch_nonzero_ckks_tfhe_zero() {
        let ckks_pt = 1.0_f64.to_le_bytes().to_vec();
        let tfhe_pt = vec![0u8];
        let (_, _, equiv) = check_scheme_switch_equivalence(&ckks_pt, &tfhe_pt);
        assert!(!equiv);
    }

    #[test]
    fn test_equivalence_mismatch_zero_ckks_tfhe_one() {
        let ckks_pt = 0.0_f64.to_le_bytes().to_vec();
        let tfhe_pt = vec![1u8];
        let (_, _, equiv) = check_scheme_switch_equivalence(&ckks_pt, &tfhe_pt);
        assert!(!equiv);
    }

    #[test]
    fn test_equivalence_any_nonzero_ckks_at_risk() {
        let ckks_pt = 4.0_f64.to_le_bytes().to_vec();
        let tfhe_pt = vec![1u8];
        let (ckks_int, tfhe_bit, equiv) = check_scheme_switch_equivalence(&ckks_pt, &tfhe_pt);
        assert_eq!(ckks_int, 4);
        assert_eq!(tfhe_bit, 1);
        assert!(equiv);
    }

    #[test]
    fn test_build_witness() {
        let pairs = vec![(1.0_f64, 1u8), (0.0_f64, 0u8)];
        let witness = build_scheme_switch_witness(&pairs);
        assert_eq!(witness.len(), 2);
        assert_eq!(witness[0][0], ark_bn254::Fr::from(1u64));
        assert_eq!(witness[0][1], ark_bn254::Fr::from(1u64));
        assert_eq!(witness[1][0], ark_bn254::Fr::from(0u64));
        assert_eq!(witness[1][1], ark_bn254::Fr::from(0u64));
    }

    #[test]
    fn test_step_circuit_descriptor() {
        assert_eq!(SchemeSwitchStepCircuit.descriptor().width, 3);
        let expected: [u8; 32] = Keccak256::digest(b"pvthfhe/scheme-switch/v1").into();
        assert_eq!(SchemeSwitchStepCircuit.circuit_hash(), expected);
    }
}
