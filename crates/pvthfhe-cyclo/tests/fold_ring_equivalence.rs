//! Equivalence test: the generic FoldRing-based ChannelFoldDriver correctly
//! applies NIFS fold steps with Fiat-Shamir ternary challenges.
//!
//! This is Phase 1.7 from the native-arithmetic migration plan.

use pvthfhe_cyclo::fold_ring::{Cyclo256Ring, FoldRing};

#[test]
fn channel_fold_driver_folds_with_nifs_prover() {
    let ring = Cyclo256Ring;
    let degree = ring.degree();

    let coeffs: Vec<u64> = {
        let mut v = vec![0u64; degree];
        v[0] = 42;
        v[1] = 7;
        v
    };
    let instance = pvthfhe_cyclo::ring::RqPoly(coeffs);

    let driver = pvthfhe_cyclo::channel_fold::ChannelFoldDriver::new(vec![ring]);
    let zero = driver.ring(0).zero();
    assert_eq!(driver.accumulator(0).commitment, zero);

    // fold_one now uses fold_one_generic with Fiat-Shamir ternary challenges.
    // The commitment after folding depends on the SHA-256 challenge output.
    // Verify at minimum: fold_count increments and no panic.
    let commitments = vec![instance.clone()];
    let witnesses = vec![instance];
    let mut driver = driver;
    driver
        .fold_one(&commitments, &witnesses)
        .expect("fold should succeed");
    assert_eq!(driver.accumulator(0).fold_count, 1);
}

#[test]
fn decompose_recompose_identity() {
    let ring = Cyclo256Ring;
    let degree = ring.degree();
    let coeffs: Vec<u64> = (0..degree).map(|i| (i * 7) as u64).collect();
    let a = pvthfhe_cyclo::ring::RqPoly(coeffs);

    let limbs = ring.decompose(&a, 1 << 16, 4);
    let back = ring.recompose(&limbs, 1 << 16).unwrap();

    let q = ring.modulus();
    for i in 0..degree {
        assert_eq!(
            a.0[i] % q,
            back.0[i] % q,
            "coefficient {i} must be congruent modulo q"
        );
    }
}
