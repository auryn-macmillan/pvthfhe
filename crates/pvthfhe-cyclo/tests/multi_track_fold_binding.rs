//! H.2 multi-track folding public-instance binding tests.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use pvthfhe_cyclo::{
    fold::{fold_one_step_multitrack, init_accumulator_multitrack, verify_fold_multitrack},
    CcsPShareInstance, FoldTrackCommitment, FoldTrackKind, MultiTrackFoldMetadata,
    MultiTrackPShareInstance,
};
use pvthfhe_types::CcsWitnessSecret;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn matrix_1x1(e: Fr) -> Vec<u8> {
    let mut m = vec![0u8, 0, 0, 1, 0, 0, 0, 1];
    m.extend_from_slice(&e.into_bigint().to_bytes_le());
    m
}

fn witness_1var(fr: Fr) -> Vec<u8> {
    let mut bytes = vec![0u8, 0, 0, 1];
    bytes.extend_from_slice(&fr.into_bigint().to_bytes_le());
    bytes
}

fn make_ajtai_bytes(id: u8) -> Vec<u8> {
    use pvthfhe_cyclo::fold::AJTAI_COMMITMENT_BYTES;
    (0..AJTAI_COMMITMENT_BYTES)
        .map(|i| (i as u8).wrapping_add(id))
        .collect()
}

fn track(kind: FoldTrackKind, slot_index: Option<u16>, fill: u8, bound: u64) -> FoldTrackCommitment {
    FoldTrackCommitment {
        kind,
        slot_index,
        commitment: vec![fill; 32],
        norm_bound: bound,
    }
}

fn metadata(participant_id: u16, instance_count: u32) -> MultiTrackFoldMetadata {
    MultiTrackFoldMetadata {
        session_id: "h2-session".to_string(),
        participant_id,
        party_binding: vec![0xA0, participant_id as u8],
        instance_count,
        tracks: vec![
            track(FoldTrackKind::Sk, None, 0x11, 16),
            track(FoldTrackKind::ESm, Some(7), 0x22, 32),
            track(FoldTrackKind::EncryptionWitness, Some(0), 0x33, 64),
        ],
    }
}

fn make_instance(id: u16) -> MultiTrackPShareInstance {
    make_instance_with_count(id, 1)
}

fn make_instance_with_count(id: u16, instance_count: u32) -> MultiTrackPShareInstance {
    let mut binding = [0u8; 32];
    binding[0] = id as u8;
    CcsPShareInstance {
        participant_id: id,
        ajtai_commitment_bytes: make_ajtai_bytes(id as u8).into(),
        public_io_bytes: vec![id as u8 ^ 0xAA; 32].into(),
        ccs_witness_bytes: CcsWitnessSecret::new(witness_1var(Fr::ZERO)),
        sha256_binding_bytes: binding.to_vec().into(),
        ccs_matrix_bytes: matrix_1x1(Fr::from(1u64)).into(),
    }
    .with_multi_track_metadata(metadata(id, instance_count))
}

#[test]
fn verify_fold_rejects_tampered_esm_track_while_sk_track_remains_valid() {
    let inst_a = make_instance_with_count(1, 2);
    let inst_b = make_instance_with_count(2, 2);
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    let acc0 = init_accumulator_multitrack(&inst_a, "h2-session").expect("init");
    let acc1 = fold_one_step_multitrack(acc0, &inst_a, &mut rng).expect("fold A");
    let acc2 = fold_one_step_multitrack(acc1, &inst_b, &mut rng).expect("fold B");

    verify_fold_multitrack(&acc2, &[make_instance_with_count(1, 2), make_instance_with_count(2, 2)]).expect("honest fold accepts");

    let mut tampered = make_instance_with_count(2, 2);
    let metadata = tampered
        .multi_track_metadata
        .as_mut()
        .expect("metadata must exist");
    metadata.tracks[1].commitment[0] ^= 0xFF;

    let result = verify_fold_multitrack(&acc2, &[make_instance_with_count(1, 2), tampered]);
    assert!(
        result.is_err(),
        "tampering only the e_sm commitment must be rejected even though sk remains unchanged"
    );
}

#[test]
fn verify_fold_rejects_cross_swapped_sk_and_esm_track_commitments() {
    let inst = make_instance(3);
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let acc0 = init_accumulator_multitrack(&inst, "h2-session").expect("init");
    let acc1 = fold_one_step_multitrack(acc0, &inst, &mut rng).expect("fold");

    let mut swapped = make_instance(3);
    let metadata = swapped
        .multi_track_metadata
        .as_mut()
        .expect("metadata must exist");
    metadata.tracks.swap(0, 1);

    let result = verify_fold_multitrack(&acc1, &[swapped]);
    assert!(
        result.is_err(),
        "domain-separated sk/e_sm tracks must not be silently cross-swappable"
    );
}
