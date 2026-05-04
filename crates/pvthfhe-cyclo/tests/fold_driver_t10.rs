//! Integration tests for the T=10 sequential fold driver (F7).

use pvthfhe_cyclo::{driver::fold_all, fold::verify_fold, CcsPShareInstance};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

fn make_instance(id: u16, seed: u8) -> CcsPShareInstance {
    let ajtai = vec![seed; 32];
    let public_io = vec![seed.wrapping_add(1); 32];
    let witness = vec![seed.wrapping_add(2); 32];
    let binding: [u8; 32] = Sha256::new()
        .chain_update(&ajtai)
        .chain_update(&public_io)
        .chain_update(&witness)
        .finalize()
        .into();
    CcsPShareInstance {
        participant_id: id,
        ajtai_commitment_bytes: ajtai,
        public_io_bytes: public_io,
        ccs_witness_bytes: witness,
        sha256_binding_bytes: binding.to_vec(),
    }
}

fn make_10_instances() -> Vec<CcsPShareInstance> {
    (0u16..10)
        .map(|i| make_instance(i + 1, (i * 7 + 3) as u8))
        .collect()
}

fn make_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([99u8; 32])
}

/// RED: stub returns Err — this test will FAIL until driver is implemented.
#[test]
fn t10_fold_driver_norm_bounded() {
    let instances = make_10_instances();
    let mut rng = make_rng();
    let acc = fold_all(&instances, "test-session-f7", &mut rng)
        .expect("fold_all should succeed for 10 instances");
    assert!(
        acc.norm_bound_current <= 1344,
        "final norm_bound_current must be ≤ 1344, got {}",
        acc.norm_bound_current
    );
}

#[test]
fn t10_fold_driver_depth_correct() {
    let instances = make_10_instances();
    let mut rng = make_rng();
    let acc = fold_all(&instances, "test-session-f7", &mut rng)
        .expect("fold_all should succeed for 10 instances");
    assert_eq!(
        acc.fold_depth, 10,
        "expected fold_depth == 10 after T=10 fold"
    );
}

#[test]
fn t10_fold_driver_verify_passes() {
    let instances = make_10_instances();
    let mut rng = make_rng();
    let acc = fold_all(&instances, "test-session-f7", &mut rng).expect("fold_all should succeed");
    verify_fold(&acc, &instances).expect("verify_fold must accept the honest accumulator");
}

#[test]
fn fold_all_rejects_zero_instances() {
    let mut rng = make_rng();
    let result = fold_all(&[], "test-session-f7", &mut rng);
    assert!(
        result.is_err(),
        "fold_all must reject empty instances slice"
    );
}

#[test]
fn fold_all_rejects_11_instances() {
    let instances: Vec<CcsPShareInstance> =
        (0u16..11).map(|i| make_instance(i + 1, i as u8)).collect();
    let mut rng = make_rng();
    let result = fold_all(&instances, "test-session-f7", &mut rng);
    assert!(
        matches!(
            result,
            Err(pvthfhe_cyclo::CycloError::FoldDepthExhausted(_))
        ),
        "fold_all must return FoldDepthExhausted for 11 instances"
    );
}
