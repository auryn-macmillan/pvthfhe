//! P2-M1.5: RED tests for Cyclo CCS adapter (RingElement + CycloVerifierCCS).
#![allow(missing_docs, clippy::unwrap_used)]

use ark_bn254::Fr;
use pvthfhe_aggregator::folding::{ccs_adapter::CycloVerifierCCS, ring_element::RingElement};

fn fr(i: i64) -> Fr {
    if i >= 0 {
        Fr::from(i as u64)
    } else {
        -Fr::from((-i) as u64)
    }
}

#[test]
fn ring_add_identity() {
    let n = 256;
    let a = RingElement {
        coeffs: vec![fr(1); n],
    };
    let zero = RingElement::zero(n);
    assert_eq!(a.add(&zero), a);
}

#[test]
fn ring_mul_commutative() {
    let n = 256;
    let a = RingElement {
        coeffs: vec![fr(2); n],
    };
    let b = RingElement {
        coeffs: vec![fr(3); n],
    };
    assert_eq!(a.mul(&b), b.mul(&a));
}

#[test]
fn ring_mul_by_challenge_scalar() {
    let n = 256;
    let a = RingElement {
        coeffs: vec![fr(1); n],
    };
    let b = RingElement {
        coeffs: vec![fr(2); n],
    };
    let c = fr(3);
    // (a+b)*c == a*c + b*c
    assert_eq!(a.add(&b).scale(c), a.scale(c).add(&b.scale(c)));
}

#[test]
fn verifier_accepts_honest_witness() {
    let n = 256;
    let challenge = fr(1);
    let s = RingElement {
        coeffs: vec![fr(42); n],
    };
    let e = RingElement {
        coeffs: vec![fr(7); n],
    };
    let d = s.clone();
    // Build t such that c·s + e - t - c·d = 0
    // = 1·s + e - t - 1·d = e - t (since s=d)
    // So set t = e
    let t = e.clone();
    let z_s = s;
    let z_e = e;
    let verifier = CycloVerifierCCS::new(n, fr(0), challenge);
    assert!(verifier.verify_native(&z_s, &z_e, &t, &d));
}

#[test]
fn verifier_rejects_wrong_witness() {
    let n = 256;
    let challenge = fr(1);
    let s = RingElement {
        coeffs: vec![fr(42); n],
    };
    let e = RingElement {
        coeffs: vec![fr(7); n],
    };
    let d = RingElement {
        coeffs: vec![fr(99); n],
    }; // WRONG share
    let t = e.clone();
    let verifier = CycloVerifierCCS::new(n, fr(0), challenge);
    assert!(!verifier.verify_native(&s, &e, &t, &d));
}

#[test]
fn verifier_rejects_wrong_challenge() {
    let n = 256;
    let s = RingElement {
        coeffs: vec![fr(2); n],
    };
    let d = RingElement {
        coeffs: vec![fr(3); n],
    }; // d != s
    let e = RingElement {
        coeffs: vec![fr(5); n],
    };
    // Build t for honest challenge c=1: t = 1*s + e - 1*d = 2+5-3 = 4
    let t = RingElement {
        coeffs: vec![fr(4); n],
    };
    let verifier = CycloVerifierCCS::new(n, fr(0), fr(2)); // wrong challenge (should be 1)
    assert!(!verifier.verify_native(&s, &e, &t, &d));
}

#[test]
fn ring_element_norm_inf() {
    let n = 256;
    let mut coeffs = vec![fr(0); n];
    coeffs[100] = fr(99);
    coeffs[200] = fr(42);
    let r = RingElement { coeffs };
    assert_eq!(r.norm_inf(), fr(99));
}
