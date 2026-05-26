use ark_bn254::Fr;
use pvthfhe_aggregator::folding::norm::*;
use pvthfhe_aggregator::folding::ring_element::RingElement;

fn fr(i: i64) -> Fr {
    if i >= 0 {
        Fr::from(i as u64)
    } else {
        -Fr::from((-i) as u64)
    }
}

#[test]
fn norm_accepts_short_witness() {
    let n = 256;
    let s = RingElement {
        coeffs: vec![fr(5); n],
    };
    assert!(enforce_norm_inf(&s, fr(1024), "s").is_ok());
}

#[test]
fn norm_rejects_large_witness() {
    let n = 256;
    let s = RingElement {
        coeffs: vec![fr(9999); n],
    };
    assert!(enforce_norm_inf(&s, fr(1024), "s").is_err());
}

#[test]
fn norm_boundary() {
    let n = 256;
    let s = RingElement {
        coeffs: vec![fr(1024); n],
    };
    assert!(enforce_norm_inf(&s, fr(1024), "s").is_ok());
}

#[test]
fn full_validation_rejects_large_error() {
    let n = 256;
    let s = RingElement {
        coeffs: vec![fr(42); n],
    };
    let e = RingElement {
        coeffs: vec![fr(100); n],
    };
    let zs = RingElement {
        coeffs: vec![fr(100); n],
    };
    let ze = RingElement {
        coeffs: vec![fr(100); n],
    };
    assert!(validate_folding_witness(&s, &e, &zs, &ze, fr(1024), fr(16), fr(2049)).is_err());
}

#[test]
fn full_validation_accepts_matching_zs_ze() {
    let n = 256;
    let s = RingElement {
        coeffs: vec![fr(42); n],
    };
    let e = RingElement {
        coeffs: vec![fr(7); n],
    };
    let zs = RingElement {
        coeffs: s.coeffs.clone(),
    };
    let ze = RingElement {
        coeffs: e.coeffs.clone(),
    };
    assert!(validate_folding_witness(&s, &e, &zs, &ze, fr(1024), fr(16), fr(2049)).is_ok());
}
