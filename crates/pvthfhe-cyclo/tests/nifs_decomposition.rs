//! RED tests for NIFS witness decomposition.
//!
//! Tests decompose_witness and recompose_witness for splitting a
//! Vec<RqPoly> into K parts where each part has ‖·‖_∞ < b_small.

use pvthfhe_cyclo::nifs::decomposition::{decompose_witness, recompose_witness};
use pvthfhe_cyclo::ring::{norm_inf, RqPoly, PHI_COMMIT, Q_COMMIT};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

/// Sample a random RqPoly with coefficients in [0, Q_COMMIT).
fn random_poly(rng: &mut ChaCha20Rng) -> RqPoly {
    let coeffs: Vec<u64> = (0..PHI_COMMIT).map(|_| rng.next_u64() % Q_COMMIT).collect();
    RqPoly(coeffs)
}

/// Sample a random witness of size `n` with coefficients in [0, Q_COMMIT).
fn random_witness(n: usize, rng: &mut ChaCha20Rng) -> Vec<RqPoly> {
    (0..n).map(|_| random_poly(rng)).collect()
}

/// RED: decompose_witness → recompose_witness roundtrip preserves the original.
#[test]
fn decompose_witness_roundtrip() {
    let mut rng = ChaCha20Rng::from_seed([31u8; 32]);
    let n = 5;
    let w = random_witness(n, &mut rng);
    let b_small: u64 = 1024;
    // With b=2 and b_small=1024 ≈ 2^10, we need ceil(log2(Q_COMMIT/2) / 10) ≈ 5 parts
    // For Q_COMMIT≈2^49, centred max ≈ 2^48, b_small=2^10 → 48/10 ≈ 5 digits in base 1024
    let k: usize = 5;
    let parts = decompose_witness(&w, b_small, k);
    let recomposed = recompose_witness(&parts, b_small);
    assert_eq!(w.len(), recomposed.len(), "witness length must be preserved");
    for (i, (orig, rec)) in w.iter().zip(recomposed.iter()).enumerate() {
        assert_eq!(
            orig.0, rec.0,
            "witness element {i} roundtrip mismatch"
        );
    }
}

/// RED: each decomposed witness part must have ∞-norm < b_small.
#[test]
fn decompose_witness_norm_bound() {
    let mut rng = ChaCha20Rng::from_seed([32u8; 32]);
    let n = 5;
    let w = random_witness(n, &mut rng);
    let b_small: u64 = 1024;
    let k: usize = 5;
    let parts = decompose_witness(&w, b_small, k);
    assert_eq!(parts.len(), k, "must produce exactly k parts");
    for (part_idx, part_witness) in parts.iter().enumerate() {
        for (elem_idx, poly) in part_witness.iter().enumerate() {
            let ni = norm_inf(poly);
            assert!(
                ni < b_small,
                "part {part_idx}, element {elem_idx}: ∞-norm {ni} >= b_small {b_small}"
            );
        }
    }
}

/// RED: decomposing an all-zeros witness should give all-zero parts.
#[test]
fn decompose_witness_zero() {
    let n = 3;
    let w = vec![RqPoly::zero(); n];
    let b_small: u64 = 1024;
    let k: usize = 5;
    let parts = decompose_witness(&w, b_small, k);
    let recomposed = recompose_witness(&parts, b_small);
    for (orig, rec) in w.iter().zip(recomposed.iter()) {
        assert_eq!(orig.0, rec.0, "zero witness roundtrip mismatch");
    }
    for part in &parts {
        for poly in part {
            assert_eq!(poly.0, vec![0u64; PHI_COMMIT], "zero witness part must be zero");
        }
    }
}

/// RED: when k is insufficient (b_small^k < centred max), the decomposition
/// still produces a valid decomposition but the recomposed may differ — the
/// function should produce at most k parts.
#[test]
fn decompose_witness_produces_correct_number_of_parts() {
    let mut rng = ChaCha20Rng::from_seed([33u8; 32]);
    let n = 3;
    let w = random_witness(n, &mut rng);
    let b_small: u64 = 1024;
    let k: usize = 5;
    let parts = decompose_witness(&w, b_small, k);
    assert_eq!(parts.len(), k, "must produce exactly k parts");
    for part in &parts {
        assert_eq!(part.len(), n, "each part must have same witness length");
    }
}
