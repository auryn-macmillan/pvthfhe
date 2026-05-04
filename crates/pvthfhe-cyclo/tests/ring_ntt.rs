//! Integration tests for `ring.rs`: NTT, pointwise multiplication, and norms
//! over `R_{q_commit} = Z_{q_commit}[X]/(X^256+1)`.
//!
//! These tests are initially **RED** (no implementation), then turn **GREEN**
//! after the real implementation is committed.

use pvthfhe_cyclo::ring::{
    norm_inf, norm_sq, ntt_forward, ntt_inverse, ntt_mul, RqPoly, PHI_COMMIT, Q_COMMIT,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

/// Samples a random `RqPoly` with coefficients in `[0, Q_COMMIT)`.
fn random_poly(rng: &mut ChaCha20Rng) -> RqPoly {
    let coeffs: Vec<u64> = (0..PHI_COMMIT).map(|_| rng.next_u64() % Q_COMMIT).collect();
    RqPoly(coeffs)
}

/// Schoolbook negacyclic multiplication in `Z_q[X]/(X^256+1)`.
///
/// Used as the reference implementation to verify NTT-based multiplication.
fn schoolbook_mul(a: &RqPoly, b: &RqPoly) -> RqPoly {
    let mut raw = vec![0i128; PHI_COMMIT];
    for i in 0..PHI_COMMIT {
        for j in 0..PHI_COMMIT {
            let prod = (a.0[i] as i128) * (b.0[j] as i128);
            if i + j < PHI_COMMIT {
                raw[i + j] += prod;
            } else {
                raw[i + j - PHI_COMMIT] -= prod;
            }
        }
    }
    let q = Q_COMMIT as i128;
    let coeffs = raw
        .iter()
        .map(|&r| {
            let v = r.rem_euclid(q);
            v as u64
        })
        .collect();
    RqPoly(coeffs)
}

#[test]
fn ntt_roundtrip_500() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    for i in 0..500 {
        let p = random_poly(&mut rng);
        let p_ntt = ntt_forward(&p).unwrap_or_else(|e| panic!("ntt_forward failed at {i}: {e}"));
        let p_back =
            ntt_inverse(&p_ntt).unwrap_or_else(|e| panic!("ntt_inverse failed at {i}: {e}"));
        assert_eq!(p.0, p_back.0, "NTT round-trip failed for polynomial {i}");
    }
}

#[test]
fn ntt_mul_vs_schoolbook_500() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    for i in 0..500 {
        let a = random_poly(&mut rng);
        let b = random_poly(&mut rng);
        let ntt_result = ntt_mul(&a, &b).unwrap_or_else(|e| panic!("ntt_mul failed at {i}: {e}"));
        let ref_result = schoolbook_mul(&a, &b);
        assert_eq!(ntt_result.0, ref_result.0, "NTT mul mismatch at index {i}");
    }
}

#[test]
fn norm_inf_500() {
    let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
    for _ in 0..500 {
        let p = random_poly(&mut rng);
        let ni = norm_inf(&p);
        assert!(ni <= Q_COMMIT / 2, "norm_inf {ni} > Q_COMMIT/2");
        let expected =
            p.0.iter()
                .map(|&c| {
                    let neg = Q_COMMIT - c;
                    if neg < c {
                        neg
                    } else {
                        c
                    }
                })
                .max()
                .unwrap_or(0);
        assert_eq!(ni, expected, "norm_inf mismatch");
    }
}

#[test]
fn norm_sq_500() {
    let mut rng = ChaCha20Rng::from_seed([19u8; 32]);
    for _ in 0..500 {
        let p = random_poly(&mut rng);
        let ns = norm_sq(&p);
        let expected: u128 =
            p.0.iter()
                .map(|&c| {
                    let neg = Q_COMMIT - c;
                    let cc = if neg < c { neg } else { c } as u128;
                    cc * cc
                })
                .sum();
        assert_eq!(ns, expected, "norm_sq mismatch");
    }
}

#[test]
fn norm_inf_zero_poly() {
    let p = RqPoly::zero();
    assert_eq!(norm_inf(&p), 0);
    assert_eq!(norm_sq(&p), 0);
}
