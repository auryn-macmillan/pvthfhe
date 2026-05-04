//! Binding property test for the Ajtai commitment scheme.
//!
//! Verifies that opening a commitment to a different witness returns `Err`,
//! and opening to the correct witness returns `Ok`.
use pvthfhe_nizk::ajtai::{AjtaiMatrix, AjtaiParams, Rq};
use pvthfhe_nizk::NizkError;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// Number of columns `m` used in this binding test.
const M: usize = 16;

fn bounded_witness(rng: &mut dyn rand_core::RngCore, params: &AjtaiParams) -> Vec<Rq> {
    (0..M)
        .map(|_| Rq::sample_bounded(rng, params.witness_bound).expect("sample_bounded succeeds"))
        .collect()
}

#[test]
fn ajtai_binding_negative_witness_differs() {
    let params = AjtaiParams::default();
    let seed = [0xAB_u8; 32];
    let matrix = AjtaiMatrix::from_seed(seed, &params, M).expect("matrix construction succeeds");

    let mut rng = ChaCha20Rng::from_seed([0x01_u8; 32]);
    let s1 = bounded_witness(&mut rng, &params);
    let commitment =
        pvthfhe_nizk::ajtai::AjtaiCommitment::commit(&matrix, &s1).expect("commit succeeds");

    let mut rng2 = ChaCha20Rng::from_seed([0x02_u8; 32]);
    let s2 = bounded_witness(&mut rng2, &params);

    let result = commitment.verify_open(&matrix, &s2);
    assert!(
        matches!(result, Err(NizkError::VerificationFailed(_))),
        "expected VerificationFailed, got {result:?}",
    );
}

#[test]
fn ajtai_binding_positive_witness_matches() {
    let params = AjtaiParams::default();
    let seed = [0xAB_u8; 32];
    let matrix = AjtaiMatrix::from_seed(seed, &params, M).expect("matrix construction succeeds");

    let mut rng = ChaCha20Rng::from_seed([0x01_u8; 32]);
    let s1 = bounded_witness(&mut rng, &params);
    let commitment =
        pvthfhe_nizk::ajtai::AjtaiCommitment::commit(&matrix, &s1).expect("commit succeeds");

    commitment
        .verify_open(&matrix, &s1)
        .expect("correct witness should verify");
}
