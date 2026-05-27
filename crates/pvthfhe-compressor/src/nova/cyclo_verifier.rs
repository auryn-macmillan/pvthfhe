//! M1 ring-equation verification for the Cyclo commitment ring.
//!
//! Provides both native (non-R1CS) and R1CS constraint-based verification
//! functions for the P1 verifier equation: `c·z_s + z_e - t - c·d ≡ 0`
//! over the Cyclo commitment ring R = Z_q[X]/(X^N+1).
//!
//! The native path is used for pre-verification outside the step circuit.
//! The R1CS path (M6) encodes the equation as constraints without
//! multiplications, exploiting the ternary challenge c ∈ {-1, 0, 1}.

use ark_ff::PrimeField;
use ark_r1cs_std::eq::EqGadget;
use ark_relations::gr1cs::SynthesisError;
use pvthfhe_aggregator::folding::{ccs_adapter::CycloVerifierCCS, ring_element::RingElement};

use crate::nova::ring_element_var::RingElementVar;

/// M1 ring-equation verification step (native).
///
/// Checks `c·z_s + z_e - t - c·d ≡ 0` for the Cyclo commitment ring.
/// All values are ring elements in R = Z_q[X]/(X^N+1) where N is
/// determined by the length of `z_s.coeffs`.
///
/// Returns `true` if the equation holds for all coefficients.
///
/// # Parameters
///
/// - `challenge`: ternary challenge `c ∈ {-1, 0, 1}` as a field element
/// - `z_s`: masked secret share (response term)
/// - `z_e`: masked error share (response term)
/// - `t`: public target commitment
/// - `d`: public statement term
pub fn verify_ring_equation<F: PrimeField>(
    challenge: F,
    z_s: &RingElement<F>,
    z_e: &RingElement<F>,
    t: &RingElement<F>,
    d: &RingElement<F>,
) -> bool {
    let verifier = CycloVerifierCCS::new(z_s.coeffs.len(), F::zero(), challenge);
    verifier.verify_native(z_s, z_e, t, d)
}

/// Verify `c·z_s + z_e - t - c·d ≡ 0` in R1CS constraints (M6).
///
/// For ternary challenge `c ∈ {-1, 0, 1}`, no R1CS multiplications are
/// needed — only addition and negation. The function branches on the
/// challenge value and enforces coefficient-wise equality:
///
/// - `c = 1`:  `z_s + z_e` vs `t + d`
/// - `c = -1`: `z_e + d` vs `t + z_s`
/// - `c = 0`:  `z_e` vs `t`
///
/// All `RingElementVar` coefficients must have the same length.
pub fn verify_ring_equation_r1cs<F: PrimeField>(
    challenge: F,
    z_s: &RingElementVar<F>,
    z_e: &RingElementVar<F>,
    t: &RingElementVar<F>,
    d: &RingElementVar<F>,
) -> Result<(), SynthesisError> {
    let n = z_s.n();
    if challenge == F::one() {
        let lhs = z_s.add(z_e);
        let rhs = t.add(d);
        for k in 0..n {
            lhs.coeffs[k].enforce_equal(&rhs.coeffs[k])?;
        }
    } else if challenge == -F::one() {
        let lhs = d.add(z_e);
        let rhs = t.add(z_s);
        for k in 0..n {
            lhs.coeffs[k].enforce_equal(&rhs.coeffs[k])?;
        }
    } else {
        for k in 0..n {
            z_e.coeffs[k].enforce_equal(&t.coeffs[k])?;
        }
    }
    Ok(())
}
