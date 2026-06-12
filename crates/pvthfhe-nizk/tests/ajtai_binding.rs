//! Binding property test for the Ajtai commitment scheme.
//!
//! Verifies that opening a commitment to a different witness returns `Err`,
//! and opening to the correct witness returns `Ok`.
use pvthfhe_nizk::ajtai::{AjtaiMatrix, AjtaiParams, Rq};
use pvthfhe_nizk::NizkError;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const M: usize = 16;

fn bounded_witness(
    rng: &mut dyn rand_core::RngCore,
    params: &AjtaiParams,
) -> Result<Vec<Rq>, NizkError> {
    (0..M)
        .map(|_| Rq::sample_bounded(rng, params.witness_bound))
        .collect()
}

#[test]
fn ajtai_binding_negative_witness_differs() -> Result<(), NizkError> {
    let params = AjtaiParams::default();
    let seed = [0xAB_u8; 32];
    let matrix = AjtaiMatrix::from_seed(seed, &params, M)?;

    let mut rng = ChaCha20Rng::from_seed([0x01_u8; 32]);
    let s1 = bounded_witness(&mut rng, &params)?;
    let commitment = pvthfhe_nizk::ajtai::AjtaiCommitment::commit(&matrix, &s1)?;

    let mut rng2 = ChaCha20Rng::from_seed([0x02_u8; 32]);
    let s2 = bounded_witness(&mut rng2, &params)?;

    let result = commitment.verify_open(&matrix, &s2);
    assert!(
        matches!(result, Err(NizkError::VerificationFailed { .. })),
        "expected VerificationFailed, got {result:?}",
    );
    Ok(())
}

#[test]
fn ajtai_binding_positive_witness_matches() -> Result<(), NizkError> {
    let params = AjtaiParams::default();
    let seed = [0xAB_u8; 32];
    let matrix = AjtaiMatrix::from_seed(seed, &params, M)?;

    let mut rng = ChaCha20Rng::from_seed([0x01_u8; 32]);
    let s1 = bounded_witness(&mut rng, &params)?;
    let commitment = pvthfhe_nizk::ajtai::AjtaiCommitment::commit(&matrix, &s1)?;

    commitment.verify_open(&matrix, &s1)?;
    Ok(())
}
