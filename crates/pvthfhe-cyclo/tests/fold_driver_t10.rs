//! Integration tests for the T=10 sequential fold driver (F7).

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use pvthfhe_cyclo::{driver::fold_all, fold::verify_fold, CcsPShareInstance};
use pvthfhe_types::CcsWitnessSecret;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

fn matrix_1x1(e: Fr) -> Vec<u8> {
    let mut m = vec![0u8, 0, 0, 1, 0, 0, 0, 1]; // rows=1, cols=1
    m.extend_from_slice(&e.into_bigint().to_bytes_le());
    m
}

fn witness_1var(fr: Fr) -> Vec<u8> {
    let mut bytes = vec![0u8, 0, 0, 1]; // num_vars=1
    bytes.extend_from_slice(&fr.into_bigint().to_bytes_le());
    bytes
}

fn make_ajtai_bytes(seed: u8) -> Vec<u8> {
    use pvthfhe_cyclo::fold::AJTAI_COMMITMENT_BYTES;
    (0..AJTAI_COMMITMENT_BYTES)
        .map(|i| (i as u8).wrapping_add(seed))
        .collect()
}

fn make_instance(id: u16, seed: u8) -> CcsPShareInstance {
    let ajtai = make_ajtai_bytes(seed);
    let public_io = vec![seed.wrapping_add(1); 32];
    let witness = witness_1var(Fr::ZERO);
    let binding: [u8; 32] = Sha256::new()
        .chain_update(&ajtai)
        .chain_update(&public_io)
        .chain_update(&witness)
        .finalize()
        .into();
    CcsPShareInstance {
        participant_id: id,
        ajtai_commitment_bytes: ajtai.into(),
        public_io_bytes: public_io.into(),
        ccs_witness_bytes: CcsWitnessSecret::new(witness),
        sha256_binding_bytes: binding.to_vec().into(),
        ccs_matrix_bytes: matrix_1x1(Fr::from(1u64)).into(),
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
