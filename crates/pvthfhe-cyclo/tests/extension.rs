//! Tests for the extension sub-protocol (Cyclo §5, T2).

use pvthfhe_cyclo::ccs_encode::CcsInstance;
use pvthfhe_cyclo::extension::{check_norm_budget, extend};

fn make_instance(id: u16, witness: Vec<u8>) -> CcsInstance {
    CcsInstance {
        participant_id: id,
        ajtai_hash: [id as u8; 32],
        public_io_hash: [(id + 1) as u8; 32],
        sha256_binding: [0u8; 32],
        witness_bytes: witness,
    }
}

#[test]
fn extension_one_fold_step_correct() {
    // RED stub: this test will panic with unimplemented!() until the GREEN impl lands.
    let a = make_instance(1, vec![0u8; 4]);
    let b = make_instance(2, vec![0u8; 4]);
    let _ext = extend(&a, &b, 1).expect("extend should succeed");
}

#[test]
fn extend_r0_is_identity_like() {
    let a = make_instance(1, vec![0xAB, 0xCD]);
    let b = make_instance(2, vec![0x12, 0x34]);
    let ext = extend(&a, &b, 0).expect("extend r=0 should succeed");
    // XOR of same-length witnesses: 0xAB^0x12, 0xCD^0x34
    assert_eq!(ext.combined_witness_bytes, vec![0xAB ^ 0x12, 0xCD ^ 0x34]);
    assert_eq!(ext.challenge_r, 0);
}

#[test]
fn extend_r1_correct() {
    let a = make_instance(1, vec![0xFF, 0x00]);
    let b = make_instance(2, vec![0x0F, 0xF0]);
    let ext = extend(&a, &b, 1).expect("extend r=1");
    assert_eq!(ext.combined_witness_bytes, vec![0xFF ^ 0x0F, 0x00 ^ 0xF0]);
    assert_eq!(ext.challenge_r, 1);
}

#[test]
fn extend_r_neg1_correct() {
    let a = make_instance(1, vec![0xAA, 0x55]);
    let b = make_instance(2, vec![0x55, 0xAA]);
    let ext = extend(&a, &b, -1).expect("extend r=-1");
    assert_eq!(ext.combined_witness_bytes, vec![0xAA ^ 0x55, 0x55 ^ 0xAA]);
    assert_eq!(ext.challenge_r, -1);
}

#[test]
fn extend_rejects_invalid_r() {
    let a = make_instance(1, vec![1, 2]);
    let b = make_instance(2, vec![3, 4]);
    assert!(extend(&a, &b, 2).is_err());
    assert!(extend(&a, &b, -2).is_err());
}

#[test]
fn norm_budget_check() {
    use pvthfhe_cyclo::extension::ExtendedInstance;
    let ext = ExtendedInstance {
        participant_id: 1,
        combined_ajtai_hash: [0u8; 32],
        combined_public_io_hash: [0u8; 32],
        combined_witness_bytes: vec![],
        challenge_r: 0,
        norm_estimate: 100,
    };
    assert!(check_norm_budget(&ext, 100).is_ok());
    assert!(check_norm_budget(&ext, 99).is_err());
}

#[test]
fn extend_100_random_instances() {
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let challenges = [-1i8, 0, 1];
    for i in 0u16..100 {
        let len = (rng.next_u32() % 64 + 1) as usize;
        let mut wa = vec![0u8; len];
        let mut wb = vec![0u8; len];
        rng.fill_bytes(&mut wa);
        rng.fill_bytes(&mut wb);
        let a = make_instance(i, wa);
        let b = make_instance(i + 100, wb);
        let r = challenges[(i % 3) as usize];
        let ext = extend(&a, &b, r).expect("extend should succeed");
        check_norm_budget(&ext, 255 * 256).expect("norm within generous budget");
    }
}
