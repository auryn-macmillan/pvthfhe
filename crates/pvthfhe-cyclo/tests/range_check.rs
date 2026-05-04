//! Integration tests for the range-check sub-protocol.

use pvthfhe_cyclo::{
    range_check::check_range,
    ring::{RqPoly, PHI_COMMIT},
};

/// RLWE error bound from spec §4.
const B_E: u64 = 16;

/// Helper: polynomial with all raw coefficients set to `val`.
fn poly_uniform(val: u64) -> RqPoly {
    RqPoly(vec![val; PHI_COMMIT])
}

/// Helper: polynomial with all zero coefficients.
fn poly_zero() -> RqPoly {
    RqPoly(vec![0u64; PHI_COMMIT])
}

#[test]
fn check_range_accepts_zero() {
    assert!(check_range(&poly_zero(), B_E).is_ok());
}

#[test]
fn check_range_accepts_at_bound() {
    // All coefficients at centred value B_E → should be accepted.
    let poly = poly_uniform(B_E);
    assert!(check_range(&poly, B_E).is_ok());
}

/// RED test: a poly with centred coeff = B_E + 1 must be rejected.
/// With the stub (always returns Ok), this test FAILS, making it RED.
#[test]
fn range_check_rejects_out_of_bound() {
    let mut coeffs = vec![0u64; PHI_COMMIT];
    coeffs[0] = B_E + 1; // centred value = 17 > 16
    let poly = RqPoly(coeffs);
    assert!(
        check_range(&poly, B_E).is_err(),
        "expected Err for coefficient exceeding bound"
    );
}

#[test]
fn range_check_fuzz_valid_200() {
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::seed_from_u64(0xdeadbeef);
    for _ in 0..200 {
        use rand_chacha::rand_core::RngCore;
        let coeffs: Vec<u64> = (0..PHI_COMMIT)
            .map(|_| rng.next_u64() % (B_E + 1))
            .collect();
        let poly = RqPoly(coeffs);
        assert!(
            check_range(&poly, B_E).is_ok(),
            "valid poly rejected unexpectedly"
        );
    }
}

#[test]
fn range_check_fuzz_invalid_200() {
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::seed_from_u64(0xcafebabe);
    for _ in 0..200 {
        use rand_chacha::rand_core::RngCore;
        let mut coeffs: Vec<u64> = (0..PHI_COMMIT)
            .map(|_| rng.next_u64() % (B_E + 1))
            .collect();
        // Place one out-of-bound coeff at a random position.
        let pos = (rng.next_u64() as usize) % PHI_COMMIT;
        coeffs[pos] = B_E + 1;
        let poly = RqPoly(coeffs);
        assert!(
            check_range(&poly, B_E).is_err(),
            "invalid poly accepted unexpectedly"
        );
    }
}
