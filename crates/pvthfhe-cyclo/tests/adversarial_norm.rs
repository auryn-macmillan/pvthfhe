//! Adversarial tests for norm-explosion rejection in the fold path.

use pvthfhe_cyclo::{
    fold::{fold_one_step, init_accumulator},
    CcsPShareInstance, PVTHFHE_CYCLO_PARAMS,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn per_step_budget() -> u64 {
    PVTHFHE_CYCLO_PARAMS.norm_bound_b / u64::from(PVTHFHE_CYCLO_PARAMS.sequential_t)
}

fn make_honest_instance(id: u16) -> CcsPShareInstance {
    let mut binding = [0u8; 32];
    binding[0] = id as u8;
    CcsPShareInstance {
        participant_id: id,
        ajtai_commitment_bytes: vec![id as u8; 32],
        public_io_bytes: vec![id as u8 ^ 0x5A; 32],
        ccs_witness_bytes: vec![1u8; 32],
        sha256_binding_bytes: binding.to_vec(),
    }
}

fn make_adversarial_instance(id: u16, round: u16, rng: &mut ChaCha20Rng) -> CcsPShareInstance {
    let mut ajtai_commitment_bytes = vec![0u8; 32];
    let mut public_io_bytes = vec![0u8; 32];
    let mut sha256_binding_bytes = vec![0u8; 32];
    rng.fill_bytes(&mut ajtai_commitment_bytes);
    rng.fill_bytes(&mut public_io_bytes);
    rng.fill_bytes(&mut sha256_binding_bytes);
    CcsPShareInstance {
        participant_id: id.wrapping_add(round),
        ajtai_commitment_bytes,
        public_io_bytes,
        ccs_witness_bytes: vec![0xFF; 32],
        sha256_binding_bytes,
    }
}

#[test]
fn adversarial_norm_rejects_single_exploding_witness() {
    let mut rng = ChaCha20Rng::from_seed([0x11; 32]);
    let honest = make_honest_instance(1);
    let acc = init_accumulator(&honest, "f11-adversarial-norm")
        .expect("init_accumulator should succeed for honest instance");
    let exploding = make_adversarial_instance(2, 0, &mut rng);

    assert!(255 > per_step_budget(), "test fixture must exceed B/T");

    let result = fold_one_step(acc, &exploding, &mut rng);
    assert!(
        result.is_err(),
        "fold_one_step must reject witness norm explosion beyond B/T"
    );
}

#[test]
fn adversarial_norm_fuzz_rejects_500_exploding_witnesses() {
    let mut rng = ChaCha20Rng::from_seed([0xA5; 32]);

    for round in 0u16..500 {
        let honest = make_honest_instance(round.wrapping_add(1));
        let acc = init_accumulator(&honest, "f11-adversarial-norm")
            .expect("init_accumulator should succeed for honest instance");
        let exploding = make_adversarial_instance(round.wrapping_add(2), round, &mut rng);

        let result = fold_one_step(acc, &exploding, &mut rng);
        assert!(
            result.is_err(),
            "round {round}: fold_one_step must reject witness norm explosion beyond B/T"
        );
    }
}
