//! LatticeFold+ core roundtrip test — fold/verify with a trivial circuit.
//!
//! This test exercises the full prover → verifier pipeline:
//! 1. Creates n CCS instances from a trivial identity circuit.
//! 2. Folds them through `LatticeFoldProver::fold_n_instances()`.
//! 3. Verifies the accumulator through `LatticeFoldVerifier::verify()`.
//! 4. Checks that tampering with instances, epoch, or accumulator is rejected.
//!
//! Uses a trivial identity circuit: w_i = x_i (the witness equals the public input).
//! This satisfies the CCS relation Ax ∘ Bx = Cx when A=I, B=I, C=I.

use ark_bn254::Fr;
use sha3::{Digest, Keccak256};

use pvthfhe_compressor::latticefold::{ExternalInputs3, LatticeFoldProver, LatticeFoldVerifier};

fn test_epoch() -> [u8; 32] {
    Keccak256::digest(b"latticefold-roundtrip-test-epoch/v1").into()
}

fn test_srs() -> [u8; 32] {
    Keccak256::digest(b"latticefold-roundtrip-test-srs/v1").into()
}

/// Create n instances for a trivial identity circuit.
///
/// For an identity circuit, the witness equals the public input.
/// Each instance is (w_i, x_i, step_count_i) where w_i = x_i.
fn make_trivial_instances(n: usize) -> Vec<ExternalInputs3> {
    (0..n)
        .map(|i| {
            let val = Fr::from((i + 1) as u64);
            ExternalInputs3(val, val, Fr::from(1u64))
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Happy-path roundtrips
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn fold_verify_single_instance() {
    let prover = LatticeFoldProver::new(test_epoch(), test_srs());
    let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
    let instances = make_trivial_instances(1);
    let acc = prover.fold_n_instances(&instances);
    assert_eq!(acc.instance_count, 1);
    assert!(verifier.verify(&acc, &instances));
}

#[test]
fn fold_verify_two_instances() {
    let prover = LatticeFoldProver::new(test_epoch(), test_srs());
    let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
    let instances = make_trivial_instances(2);
    let acc = prover.fold_n_instances(&instances);
    assert_eq!(acc.instance_count, 2);
    assert!(verifier.verify(&acc, &instances));
}

#[test]
fn fold_verify_five_instances() {
    let prover = LatticeFoldProver::new(test_epoch(), test_srs());
    let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
    let instances = make_trivial_instances(5);
    let acc = prover.fold_n_instances(&instances);
    assert_eq!(acc.instance_count, 5);
    assert!(verifier.verify(&acc, &instances));
}

#[test]
fn fold_verify_ten_instances() {
    let prover = LatticeFoldProver::new(test_epoch(), test_srs());
    let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
    let instances = make_trivial_instances(10);
    let acc = prover.fold_n_instances(&instances);
    assert_eq!(acc.instance_count, 10);
    assert!(verifier.verify(&acc, &instances));
}

#[test]
fn fold_verify_sixty_four_instances() {
    let prover = LatticeFoldProver::new(test_epoch(), test_srs());
    let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
    let instances = make_trivial_instances(64);
    let acc = prover.fold_n_instances(&instances);
    assert_eq!(acc.instance_count, 64);
    assert!(verifier.verify(&acc, &instances));
}

#[test]
fn fold_verify_identity_circuit_extreme() {
    let prover = LatticeFoldProver::new(test_epoch(), test_srs());
    let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
    // Single instance with extreme values
    let instances = vec![ExternalInputs3(
        Fr::from(u64::MAX),
        Fr::from(u64::MAX),
        Fr::from(1u64),
    )];
    let acc = prover.fold_n_instances(&instances);
    assert!(verifier.verify(&acc, &instances));
}

#[test]
fn fold_verify_zero_instance() {
    let prover = LatticeFoldProver::new(test_epoch(), test_srs());
    let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
    let instances = vec![ExternalInputs3(
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    )];
    let acc = prover.fold_n_instances(&instances);
    assert!(verifier.verify(&acc, &instances));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Adversarial rejection tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn reject_wrong_epoch() {
    let prover = LatticeFoldProver::new(test_epoch(), test_srs());
    let wrong_epoch: [u8; 32] = Keccak256::digest(b"adversarial-epoch").into();
    let verifier = LatticeFoldVerifier::new(wrong_epoch, test_srs());
    let instances = make_trivial_instances(3);
    let acc = prover.fold_n_instances(&instances);
    assert!(
        !verifier.verify(&acc, &instances),
        "must reject when verifier uses wrong epoch"
    );
}

#[test]
fn reject_wrong_srs() {
    let prover = LatticeFoldProver::new(test_epoch(), test_srs());
    let wrong_srs: [u8; 32] = Keccak256::digest(b"adversarial-srs").into();
    let verifier = LatticeFoldVerifier::new(test_epoch(), wrong_srs);
    let instances = make_trivial_instances(3);
    let acc = prover.fold_n_instances(&instances);
    assert!(
        !verifier.verify(&acc, &instances),
        "must reject when verifier and prover use different SRS hashes"
    );
}

#[test]
fn reject_mismatched_instance_count() {
    let prover = LatticeFoldProver::new(test_epoch(), test_srs());
    let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
    let instances = make_trivial_instances(3);
    let acc = prover.fold_n_instances(&instances);
    let wrong_count = make_trivial_instances(2);
    assert!(
        !verifier.verify(&acc, &wrong_count),
        "must reject when instance count mismatches"
    );
}

#[test]
fn reject_tampered_instance() {
    let prover = LatticeFoldProver::new(test_epoch(), test_srs());
    let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
    let instances = make_trivial_instances(3);
    let acc = prover.fold_n_instances(&instances);
    let mut tampered = instances.clone();
    tampered[0] = ExternalInputs3(Fr::from(9999u64), Fr::from(9999u64), Fr::from(1u64));
    assert!(
        !verifier.verify(&acc, &tampered),
        "must reject tampered instance data"
    );
}

#[test]
fn reject_reordered_instances() {
    let prover = LatticeFoldProver::new(test_epoch(), test_srs());
    let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
    let instances = make_trivial_instances(3);
    let acc = prover.fold_n_instances(&instances);
    let mut reordered = instances.clone();
    reordered.swap(0, 2);
    assert!(
        !verifier.verify(&acc, &reordered),
        "must reject reordered instances — β^i weighting is positional"
    );
}

#[test]
fn accumulator_struct_integrity() {
    let prover = LatticeFoldProver::new(test_epoch(), test_srs());
    let instances = make_trivial_instances(2);
    let acc = prover.fold_n_instances(&instances);
    assert_eq!(acc.num_instances(), 2);
    assert_eq!(acc.instance_count, 2);
    assert_eq!(acc.epoch_hash, test_epoch());
    assert_eq!(acc.srs_hash, test_srs());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Large-scale stress test
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn fold_verify_large_scale() {
    let prover = LatticeFoldProver::new(test_epoch(), test_srs());
    let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
    // 256 instances — high enough to test O(n) β-power derivation
    let instances = make_trivial_instances(256);
    let acc = prover.fold_n_instances(&instances);
    assert_eq!(acc.instance_count, 256);
    assert!(verifier.verify(&acc, &instances));
}

#[test]
fn fold_verify_very_large_scale() {
    let prover = LatticeFoldProver::new(test_epoch(), test_srs());
    let verifier = LatticeFoldVerifier::new(test_epoch(), test_srs());
    // 1024 instances — tests Fiat-Shamir transcript scalability
    let instances = make_trivial_instances(1024);
    let acc = prover.fold_n_instances(&instances);
    assert_eq!(acc.instance_count, 1024);
    assert!(verifier.verify(&acc, &instances));
}
