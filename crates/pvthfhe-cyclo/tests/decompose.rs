//! RED tests for the gadget/balanced decomposition module.
//!
//! These tests validate decompose_base_B, recompose_base_B,
//! decompose_rqpoly_base_B, and recompose_rqpoly_base_B.

use pvthfhe_cyclo::decompose::{
    decompose_base_B, decompose_rqpoly_base_B, recompose_base_B, recompose_rqpoly_base_B,
};
use pvthfhe_cyclo::ring::{norm_inf, RqPoly, PHI_COMMIT, Q_COMMIT};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

/// Sample a random RqPoly with coefficients in [0, Q_COMMIT).
fn random_poly(rng: &mut ChaCha20Rng) -> RqPoly {
    let coeffs: Vec<u64> = (0..PHI_COMMIT).map(|_| rng.next_u64() % Q_COMMIT).collect();
    RqPoly(coeffs)
}

// ── decompose_base_B / recompose_base_B ─────────────────────────────────────

/// RED: decompose then recompose a coefficient vector should return the original.
#[test]
fn decompose_recompose_roundtrip_coeffs() {
    let mut rng = ChaCha20Rng::from_seed([17u8; 32]);
    let coeffs: Vec<u64> = (0..PHI_COMMIT)
        .map(|_| rng.next_u64() % Q_COMMIT)
        .collect();
    let b: u64 = 2;
    let k: usize = 50; // enough digits for 50-bit coefficients in base 2
    let digits = decompose_base_B(&coeffs, b, k);
    let recomposed = recompose_base_B(&digits, b);
    assert_eq!(
        coeffs, recomposed,
        "decompose_base_B → recompose_base_B roundtrip must preserve original coefficients"
    );
}

/// RED: every digit in the decomposition must be strictly less than base b.
#[test]
fn decompose_bounds_base2() {
    let mut rng = ChaCha20Rng::from_seed([18u8; 32]);
    let coeffs: Vec<u64> = (0..PHI_COMMIT)
        .map(|_| rng.next_u64() % Q_COMMIT)
        .collect();
    let b: u64 = 2;
    let k: usize = 50;
    let digits = decompose_base_B(&coeffs, b, k);
    assert_eq!(digits.len(), k, "must produce exactly k digit vectors");
    for (i, digit_vec) in digits.iter().enumerate() {
        for &d in digit_vec.iter() {
            assert!(
                d < b,
                "digit {d} in vector {i} exceeds base bound b={b}"
            );
        }
    }
}

/// RED: decompose with base > 2 also respects bounds.
#[test]
fn decompose_bounds_base4() {
    let mut rng = ChaCha20Rng::from_seed([19u8; 32]);
    let coeffs: Vec<u64> = (0..PHI_COMMIT)
        .map(|_| rng.next_u64() % Q_COMMIT)
        .collect();
    let b: u64 = 4;
    let k: usize = 25; // base-4 needs 25 digits for 50-bit
    let digits = decompose_base_B(&coeffs, b, k);
    let recomposed = recompose_base_B(&digits, b);
    assert_eq!(
        coeffs, recomposed,
        "base-4 roundtrip must preserve original coefficients"
    );
    for (i, digit_vec) in digits.iter().enumerate() {
        for &d in digit_vec.iter() {
            assert!(
                d < b,
                "digit {d} in vector {i} exceeds base bound b={b}"
            );
        }
    }
}

// ── decompose_rqpoly_base_B / recompose_rqpoly_base_B ──────────────────────

/// RED: decompose_rqpoly_base_B → recompose_rqpoly_base_B roundtrip.
#[test]
fn decompose_recompose_rqpoly_roundtrip() {
    let mut rng = ChaCha20Rng::from_seed([20u8; 32]);
    let poly = random_poly(&mut rng);
    let b: u64 = 2;
    let k: usize = 50;
    let parts = decompose_rqpoly_base_B(&poly, b, k);
    let recomposed = recompose_rqpoly_base_B(&parts, b);
    assert_eq!(
        poly.0, recomposed.0,
        "decompose_rqpoly_base_B → recompose_rqpoly_base_B roundtrip must preserve original polynomial"
    );
}

/// RED: each decomposed RqPoly part must have ∞-norm < b.
#[test]
fn decompose_rqpoly_bounds() {
    let mut rng = ChaCha20Rng::from_seed([21u8; 32]);
    let poly = random_poly(&mut rng);
    let b: u64 = 2;
    let k: usize = 50;
    let parts = decompose_rqpoly_base_B(&poly, b, k);
    for (i, part) in parts.iter().enumerate() {
        let ni = norm_inf(part);
        assert!(
            ni < b,
            "decomposed part {i} has ∞-norm {ni}, must be < {b}"
        );
    }
}

/// RED: decomposing the zero polynomial gives all-zero parts.
#[test]
fn decompose_zero_rqpoly() {
    let poly = RqPoly::zero();
    let b: u64 = 2;
    let k: usize = 50;
    let parts = decompose_rqpoly_base_B(&poly, b, k);
    let recomposed = recompose_rqpoly_base_B(&parts, b);
    assert_eq!(poly.0, recomposed.0, "zero poly roundtrip must be identity");
    for part in &parts {
        assert_eq!(part.0, vec![0u64; PHI_COMMIT], "zero poly parts must be zero");
    }
}
