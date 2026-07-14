//! RED tests for NIFS folding (nifs/folding.rs).
//!
//! Tests the FoldedAccumulator struct, fold_instances, and verify_fold
//! using real Ajtai commitments over R_{q_commit}.

use pvthfhe_cyclo::ajtai::{
    commit as ajtai_commit, AjtaiCommitment, AjtaiParams,
};
use pvthfhe_cyclo::nifs::folding::{
    fold_instances, verify_fold, FoldedAccumulator,
};
use pvthfhe_cyclo::ring::{RqPoly, PHI_COMMIT, Q_COMMIT};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

/// Build deterministic Ajtai params for testing.
fn test_ajtai_params(n: usize) -> AjtaiParams {
    AjtaiParams {
        m: 13,
        n,
        q_commit: Q_COMMIT,
        seed: [0xAAu8; 32],
    }
}

/// Sample a small random RqPoly with coefficients in {-1, 0, 1}.
fn small_poly(rng: &mut ChaCha20Rng) -> RqPoly {
    let coeffs: Vec<u64> = (0..PHI_COMMIT)
        .map(|_| {
            let v = (rng.next_u64() % 3) as i64;
            match v {
                0 => 0,
                1 => 1,
                _ => Q_COMMIT - 1, // -1 ≡ Q_COMMIT - 1
            }
        })
        .collect();
    RqPoly(coeffs)
}

/// Sample a small witness vector of length n.
fn small_witness(n: usize, rng: &mut ChaCha20Rng) -> Vec<RqPoly> {
    (0..n).map(|_| small_poly(rng)).collect()
}

/// RED: folding two instances must pass verify_fold.
#[test]
fn fold_two_instances_roundtrip() {
    let mut rng = ChaCha20Rng::from_seed([41u8; 32]);
    let n = 5;
    let params = test_ajtai_params(n);

    // Create two small witness vectors
    let w1 = small_witness(n, &mut rng);
    let w2 = small_witness(n, &mut rng);

    // Commit to them
    let c1 = ajtai_commit(&params, &w1, &mut rng).expect("commit w1");
    let c2 = ajtai_commit(&params, &w2, &mut rng).expect("commit w2");

    // Build initial accumulator from c1
    let acc = FoldedAccumulator {
        commitment: c1.clone(),
        folded_witness: w1.clone(),
        norm_bound: 1024,
        fold_depth: 0,
        ajtai_params: params.clone(),
    };

    // Fold: acc + r * c2
    let r: u64 = 7; // use a small test coefficient
    let instances: Vec<AjtaiCommitment> = vec![c2.clone()];
    let witnesses: Vec<Vec<RqPoly>> = vec![w2.clone()];

    let new_acc = fold_instances(&acc, &instances, &witnesses, r)
        .expect("fold_instances must succeed");

    // Verify without witnesses
    let verify_instances: Vec<AjtaiCommitment> = vec![c2];
    assert!(
        verify_fold(&new_acc, &verify_instances, r),
        "verify_fold must accept honest fold"
    );
    assert_eq!(new_acc.fold_depth, 1);
}

/// RED: verify_fold must reject a tampered witness.
#[test]
fn fold_tampered_witness_rejected() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let n = 5;
    let params = test_ajtai_params(n);

    let w1 = small_witness(n, &mut rng);
    let w2 = small_witness(n, &mut rng);

    let c1 = ajtai_commit(&params, &w1, &mut rng).expect("commit w1");
    let c2 = ajtai_commit(&params, &w2, &mut rng).expect("commit w2");

    let acc = FoldedAccumulator {
        commitment: c1.clone(),
        folded_witness: w1.clone(),
        norm_bound: 1024,
        fold_depth: 0,
        ajtai_params: params.clone(),
    };

    let r: u64 = 7;
    let instances: Vec<AjtaiCommitment> = vec![c2.clone()];
    let witnesses: Vec<Vec<RqPoly>> = vec![w2.clone()];

    let mut new_acc = fold_instances(&acc, &instances, &witnesses, r)
        .expect("fold_instances must succeed");

    // Tamper the folded witness
    new_acc.folded_witness[0] = small_poly(&mut rng);

    // Verify with the original (untampered) commitment — should reject
    let verify_instances: Vec<AjtaiCommitment> = vec![c2];
    assert!(
        !verify_fold(&new_acc, &verify_instances, r),
        "verify_fold must reject tampered witness"
    );
}

/// RED: folding with an empty instances list is identity (acc unchanged).
#[test]
fn fold_no_instances_is_identity() {
    let mut rng = ChaCha20Rng::from_seed([43u8; 32]);
    let n = 5;
    let params = test_ajtai_params(n);
    let w = small_witness(n, &mut rng);
    let c = ajtai_commit(&params, &w, &mut rng).expect("commit");

    let acc = FoldedAccumulator {
        commitment: c.clone(),
        folded_witness: w.clone(),
        norm_bound: 1024,
        fold_depth: 0,
        ajtai_params: params.clone(),
    };

    let new_acc = fold_instances(&acc, &[], &[], 7)
        .expect("fold_instances with empty instances must succeed");

    assert_eq!(new_acc.commitment.commitment, acc.commitment.commitment,
        "commitment must be unchanged with empty instances");
    assert_eq!(new_acc.folded_witness, acc.folded_witness,
        "witness must be unchanged with empty instances");
    assert_eq!(new_acc.fold_depth, 0, "fold_depth must be unchanged");
}

/// RED: fold_instances must fail if instances and witnesses lengths differ.
#[test]
fn fold_mismatched_lengths_rejected() {
    let mut rng = ChaCha20Rng::from_seed([44u8; 32]);
    let n = 5;
    let params = test_ajtai_params(n);
    let w = small_witness(n, &mut rng);
    let c = ajtai_commit(&params, &w, &mut rng).expect("commit");

    let acc = FoldedAccumulator {
        commitment: c.clone(),
        folded_witness: w.clone(),
        norm_bound: 1024,
        fold_depth: 0,
        ajtai_params: params.clone(),
    };

    let c2 = ajtai_commit(&params, &w, &mut rng).expect("commit");
    let result = fold_instances(
        &acc,
        &[c2.clone()],  // 1 instance
        &[],             // 0 witnesses
        7,
    );
    assert!(
        result.is_err(),
        "fold_instances must reject mismatched lengths"
    );
}
