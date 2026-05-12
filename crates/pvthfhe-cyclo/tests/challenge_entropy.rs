//! R2.2 GREEN: Challenge entropy statistical test.
//!
//! Exercises the fold challenge sampler 10⁴ times and asserts that the
//! challenge space has at least 13 bits of entropy (>= 8192 unique values).
//! The GREEN implementation derives challenges via `u16::from_le_bytes(h[0..2])`
//! over the constant subring Z_q \subset R_q, providing |C| = 2^16.

use pvthfhe_cyclo::{
    fiat_shamir,
    fold::{fold_one_step, init_accumulator},
    CcsPShareInstance,
};
use pvthfhe_types::CcsWitnessSecret;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::collections::HashSet;

fn make_ajtai_bytes(seed: u8) -> Vec<u8> {
    use pvthfhe_cyclo::fold::AJTAI_COMMITMENT_BYTES;
    (0..AJTAI_COMMITMENT_BYTES)
        .map(|i| (i as u8).wrapping_add(seed))
        .collect()
}

fn make_instance(id: u16, seed: u8) -> CcsPShareInstance {
    CcsPShareInstance {
        participant_id: id,
        ajtai_commitment_bytes: make_ajtai_bytes(seed).into(),
        public_io_bytes: vec![seed.wrapping_add(1); 32].into(),
        ccs_witness_bytes: CcsWitnessSecret::new(vec![0u8, 0, 0, 0]),
        sha256_binding_bytes: vec![0u8; 32].into(),
        ccs_matrix_bytes: vec![].into(),
    }
}

fn make_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([42u8; 32])
}

fn compute_challenge(
    session_id: &str,
    fold_depth: u32,
    acc_commitment: &[u8],
    inst_ajtai_bytes: &[u8],
    inst_public_io_bytes: &[u8],
) -> u16 {
    let h = fiat_shamir::challenge_v1(
        session_id,
        fold_depth,
        acc_commitment,
        inst_ajtai_bytes,
        inst_public_io_bytes,
    );
    u16::from_le_bytes([h[0], h[1]])
}

#[test]
fn challenge_entropy_minimum_13_bits() {
    const NUM_SAMPLES: usize = 10_000;

    let mut rng = make_rng();
    let mut seen_challenges: HashSet<u16> = HashSet::new();

    for i in 0..NUM_SAMPLES {
        let session_id = format!("challenge-entropy-{:05}", i);
        let instance = make_instance(1, i as u8);

        let acc = init_accumulator(&instance, &session_id)
            .expect("init_accumulator should succeed");

        let challenge = compute_challenge(
            &acc.session_id,
            acc.fold_depth,
            &acc.acc_commitment_bytes,
            instance.ajtai_commitment_bytes.as_ref(),
            instance.public_io_bytes.as_ref(),
        );

        let old_depth = acc.fold_depth;
        let old_public_io = acc.acc_public_io_bytes.clone();
        let session_id_clone = acc.session_id.clone();

        let new_acc = fold_one_step(acc, &instance, &mut rng)
            .expect("fold_one_step should succeed");

        let expected_io = fiat_shamir::public_io_v1(
            &session_id_clone,
            old_depth + 1,
            &old_public_io,
            instance.public_io_bytes.as_ref(),
            u64::from(challenge),
        );
        assert_eq!(
            expected_io.as_slice(),
            new_acc.acc_public_io_bytes,
            "public_io mismatch: fold used a different challenge than expected"
        );

        seen_challenges.insert(challenge);
    }

    let unique_count = seen_challenges.len();
    eprintln!(
        "challenge_entropy: {unique_count} unique challenges out of {NUM_SAMPLES} samples"
    );

    assert!(
        unique_count >= 8192,
        "challenge space entropy too low: found {unique_count} unique challenges, need >= 8192 (2^13)\n\
         Expected >= 8192 unique values for 128-bit soundness with T=10 (see fold-soundness-budget.md)"
    );
}
