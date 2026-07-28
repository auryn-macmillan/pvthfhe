//! Equivalence test: the generic FoldRing-based ChannelFoldDriver produces
//! accumulator states consistent with the existing single-ring fold engine.
//!
//! This is Phase 1.7 from the native-arithmetic migration plan.

use pvthfhe_cyclo::fold_ring::{Cyclo256Ring, FoldRing};

#[test]
fn channel_fold_driver_accumulator_matches_manual_fold() {
    let ring = Cyclo256Ring;
    let degree = ring.degree();

    // Build a simple instance polynomial (non-zero first coefficient)
    let coeffs: Vec<u64> = {
        let mut v = vec![0u64; degree];
        v[0] = 42;
        v[1] = 7;
        v
    };
    let instance = pvthfhe_cyclo::ring::RqPoly(coeffs);

    // Manual fold: acc = 0 + instance = instance
    let zero = ring.zero();
    let folded_manual = ring.add_poly(&zero, &instance).unwrap();

    // ChannelFoldDriver fold (single ring, single channel):
    let driver = pvthfhe_cyclo::channel_fold::ChannelFoldDriver::new(vec![ring]);
    // Access the accumulator before folding: should be zero
    let acc_before = &driver.accumulator(0).commitment;
    assert_eq!(
        *acc_before, zero,
        "initial accumulator must be zero"
    );

    // Fold via the driver (wrapper around add_poly)
    let instances = vec![instance];
    let mut driver = driver;
    driver.fold_one(&instances).expect("fold should succeed");

    let acc_after = &driver.accumulator(0).commitment;
    assert_eq!(
        *acc_after, folded_manual,
        "ChannelFoldDriver accumulator must equal manual fold result"
    );
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

    // After recomposition, coefficients may have grown due to limb shifts
    // — verify they're congruent modulo q
    let q = ring.modulus();
    for i in 0..degree {
        assert_eq!(a.0[i] % q, back.0[i] % q, "coefficient {i} must be congruent modulo q");
    }
}
