//! P2-M4: RED tests for Ajtai lattice commitment (Com_A).
#![allow(missing_docs, clippy::unwrap_used)]

use ark_bn254::Fr;
use ark_ff::Zero;
use pvthfhe_aggregator::folding::ajtai::AjtaiMatrix;

#[test]
fn ajtai_commit_is_deterministic() {
    let epoch = [1u8; 32];
    let a1 = AjtaiMatrix::<Fr>::from_epoch(&epoch, 1, 3);
    let a2 = AjtaiMatrix::<Fr>::from_epoch(&epoch, 1, 3);
    assert_eq!(a1.entries, a2.entries);
}

#[test]
fn ajtai_commit_differs_for_different_epoch() {
    let a1 = AjtaiMatrix::<Fr>::from_epoch(&[1u8; 32], 1, 3);
    let a2 = AjtaiMatrix::<Fr>::from_epoch(&[2u8; 32], 1, 3);
    assert_ne!(a1.entries, a2.entries);
}

#[test]
fn ajtai_commit_is_binding_toy() {
    let mat = AjtaiMatrix::<Fr>::from_epoch(&[3u8; 32], 1, 3);
    let w1 = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let w2 = vec![Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)];
    // Different witnesses should produce different commitments
    // (not guaranteed but overwhelmingly likely for random matrix)
    assert_ne!(mat.commit(&w1), mat.commit(&w2));
}

#[test]
fn ajtai_commitment_folding_is_homomorphic() {
    let mat = AjtaiMatrix::<Fr>::from_epoch(&[4u8; 32], 1, 3);
    let w1 = vec![Fr::from(1u64), Fr::zero(), Fr::zero()];
    let w2 = vec![Fr::zero(), Fr::from(1u64), Fr::zero()];
    let c1 = mat.commit(&w1);
    let c2 = mat.commit(&w2);
    let w_sum = vec![Fr::from(1u64), Fr::from(1u64), Fr::zero()];
    let c_sum = mat.commit(&w_sum);
    // c1 + c2 should equal c_sum (linearity)
    let expected = vec![c1[0] + c2[0]];
    assert_eq!(c_sum, expected);
}
