//! R1CS constraint tests for the Cyclo ring equation verifier (M6).
//!
//! Verifies that `c·z_s + z_e - t - c·d ≡ 0` is correctly encoded
//! as R1CS constraints for ternary challenges c ∈ {-1, 0, 1}.
//!
//! Also tests the native `verify_ring_equation` that gates pipeline acceptance
//! in Track B mode (W1: close p2-m6 ring eq gap).

use ark_bn254::Fr;
use ark_ff::{One, PrimeField, Zero};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSystem, ConstraintSystemRef};
use pvthfhe_aggregator::folding::ring_element::RingElement;
use pvthfhe_compressor::sonobe::cyclo_verifier::verify_ring_equation;
use pvthfhe_compressor::sonobe::cyclo_verifier::verify_ring_equation_r1cs;
use pvthfhe_compressor::sonobe::ring_element_var::RingElementVar;

fn make_element<F: PrimeField>(vals: &[u64], cs: ConstraintSystemRef<F>) -> RingElementVar<F> {
    let coeffs: Vec<FpVar<F>> = vals
        .iter()
        .map(|&v| FpVar::new_witness(cs.clone(), || Ok(F::from(v))).unwrap())
        .collect();
    RingElementVar { coeffs }
}

#[test]
fn r1cs_honest_witness_passes() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    // c=1, z_s=[1], z_e=[2], t=[3], d=[0] → 1+2-3-0=0 ✓
    let zs = make_element(&[1], cs.clone());
    let ze = make_element(&[2], cs.clone());
    let t = make_element(&[3], cs.clone());
    let d = make_element(&[0], cs.clone());
    assert!(verify_ring_equation_r1cs(Fr::from(1u64), &zs, &ze, &t, &d).is_ok());
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn r1cs_wrong_witness_fails() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let zs = make_element(&[1], cs.clone());
    let ze = make_element(&[2], cs.clone());
    // t=9 makes equation 1+2-9-0=-6 ≠ 0
    let t = make_element(&[9], cs.clone());
    let d = make_element(&[0], cs.clone());
    // verify_ring_equation_r1cs adds constraints but returns Ok even if
    // the constraints are unsatisfiable — the cs.is_satisfied() check catches it
    assert!(verify_ring_equation_r1cs(Fr::from(1u64), &zs, &ze, &t, &d).is_ok());
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn r1cs_challenge_minus_one() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    // c=-1: -z_s + z_e - t + d = 0 → -1 + 2 - 3 + 2 = 0 ✓
    let zs = make_element(&[1], cs.clone());
    let ze = make_element(&[2], cs.clone());
    let t = make_element(&[3], cs.clone());
    let d = make_element(&[2], cs.clone());
    assert!(verify_ring_equation_r1cs(-Fr::one(), &zs, &ze, &t, &d).is_ok());
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn r1cs_challenge_zero() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    // c=0: z_e - t = 0 → 5 - 5 = 0 ✓
    let zs = make_element(&[99], cs.clone());
    let ze = make_element(&[5], cs.clone());
    let t = make_element(&[5], cs.clone());
    let d = make_element(&[0], cs.clone());
    assert!(verify_ring_equation_r1cs(Fr::zero(), &zs, &ze, &t, &d).is_ok());
    assert!(cs.is_satisfied().unwrap());
}

// ── Native verify_ring_equation tests (W1: pipeline gating) ──

fn make_native_element<F: PrimeField>(vals: &[u64]) -> RingElement<F> {
    RingElement {
        coeffs: vals.iter().map(|&v| F::from(v)).collect(),
    }
}

#[test]
fn native_honest_ring_equation_passes() {
    // c=1, z_s=[1,2], z_e=[3,4], t=[4,6], d=[0,0] → 1+3-4-0=0, 2+4-6-0=0 ✓
    let c = Fr::from(1u64);
    let zs = make_native_element(&[1, 2]);
    let ze = make_native_element(&[3, 4]);
    let t = make_native_element(&[4, 6]);
    let d = make_native_element(&[0, 0]);
    assert!(verify_ring_equation(c, &zs, &ze, &t, &d));
}

#[test]
fn native_broken_ring_equation_fails() {
    // c=1, z_s=[1], z_e=[2], t=[9], d=[0] → 1+2-9-0=-6 ≠ 0 ✗
    let c = Fr::from(1u64);
    let zs = make_native_element(&[1]);
    let ze = make_native_element(&[2]);
    let t = make_native_element(&[9]);
    let d = make_native_element(&[0]);
    assert!(!verify_ring_equation(c, &zs, &ze, &t, &d),
        "native ring equation must reject broken equation (W1: p2-m6 gap closure)");
}

#[test]
fn native_challenge_minus_one_honest() {
    // c=-1: -z_s + z_e - t + d = 0 → -2+5-3+0=0 ✓
    let c = -Fr::one();
    let zs = make_native_element(&[2]);
    let ze = make_native_element(&[5]);
    let t = make_native_element(&[3]);
    let d = make_native_element(&[0]);
    assert!(verify_ring_equation(c, &zs, &ze, &t, &d));
}

#[test]
fn native_challenge_minus_one_broken() {
    // c=-1: -z_s + z_e - t + d ≠ 0 → corrupt z_e
    let c = -Fr::one();
    let zs = make_native_element(&[2]);
    let ze = make_native_element(&[99]);
    let t = make_native_element(&[3]);
    let d = make_native_element(&[0]);
    assert!(!verify_ring_equation(c, &zs, &ze, &t, &d));
}

#[test]
fn native_challenge_zero_honest() {
    // c=0: z_e - t = 0 → 7-7=0 ✓
    let c = Fr::zero();
    let zs = make_native_element(&[99]); // ignored
    let ze = make_native_element(&[7]);
    let t = make_native_element(&[7]);
    let d = make_native_element(&[0]); // c·d = 0
    assert!(verify_ring_equation(c, &zs, &ze, &t, &d));
}

#[test]
fn native_challenge_zero_broken() {
    // c=0: z_e ≠ t → reject
    let c = Fr::zero();
    let zs = make_native_element(&[1]);
    let ze = make_native_element(&[7]);
    let t = make_native_element(&[8]);
    let d = make_native_element(&[0]);
    assert!(!verify_ring_equation(c, &zs, &ze, &t, &d));
}
