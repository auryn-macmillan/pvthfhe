//! M1 ring-equation verification for the Cyclo commitment ring.
//!
//! Provides a native (non-R1CS) verification function for the P1 verifier
//! equation: `c·z_s + z_e - t - c·d ≡ 0` over the Cyclo commitment ring
//! R = Z_q[X]/(X^256+1).
//!
//! This is used for pre-verification outside the step circuit. The actual
//! R1CS constraint encoding (converting RingElement operations to FpVar
//! operations) is deferred to M2.

use ark_ff::PrimeField;
use pvthfhe_aggregator::folding::{ccs_adapter::CycloVerifierCCS, ring_element::RingElement};

/// M1 ring-equation verification step.
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
