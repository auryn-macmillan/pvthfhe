//! Tests for the extension sub-protocol (Cyclo §5, T2).
//!
//! C.4: updated to use Fr-LE formatted witnesses (parse_witness compatible).

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use pvthfhe_cyclo::ccs_encode::CcsInstance;
use pvthfhe_cyclo::extension::{check_norm_budget, extend};

fn serialize_witness(data: &[Fr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len() * 32);
    let num = u32::try_from(data.len()).expect("witness too long");
    out.extend_from_slice(&num.to_be_bytes());
    for elem in data {
        out.extend_from_slice(&elem.into_bigint().to_bytes_le());
    }
    out
}

fn make_instance(id: u16, witness: Vec<u8>) -> CcsInstance {
    CcsInstance {
        participant_id: id,
        ajtai_hash: [id as u8; 32],
        public_io_hash: [(id + 1) as u8; 32],
        sha256_binding: [0u8; 32],
        witness_bytes: witness,
        ccs_matrix: Vec::new(),
    }
}

fn fr_u64(fr: &Fr) -> u64 {
    let limbs = fr.into_bigint().as_ref().to_vec();
    assert!(limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0);
    limbs[0]
}

#[test]
fn extension_one_fold_step_correct() {
    let a = make_instance(1, serialize_witness(&[]));
    let b = make_instance(2, serialize_witness(&[]));
    let _ext = extend(&a, &b, 1).expect("extend should succeed");
}

#[test]
fn extend_r0_is_identity_like() {
    let a_frs = [Fr::from(0xABu64), Fr::from(0xCDu64)];
    let b_frs = [Fr::from(0x12u64), Fr::from(0x34u64)];
    let wa = serialize_witness(&a_frs);
    let wb = serialize_witness(&b_frs);
    let a = make_instance(1, wa.clone());
    let b = make_instance(2, wb.clone());
    let ext = extend(&a, &b, 0).expect("extend r=0 should succeed");

    assert_eq!(
        ext.combined_witness_bytes,
        wa.iter()
            .zip(wb.iter())
            .map(|(x, y)| x ^ y)
            .collect::<Vec<_>>()
    );
    assert_eq!(ext.challenge_r, 0);

    // r=0: combined = a + 0*b = a; norm = max(|a_i|)
    let expected_norm = a_frs
        .iter()
        .map(|fr| {
            let c = fr_u64(fr) % 562_949_953_438_721;
            let neg = 562_949_953_438_721 - c;
            if neg < c {
                neg
            } else {
                c
            }
        })
        .max()
        .unwrap();
    assert_eq!(ext.norm_estimate, expected_norm);
}

#[test]
fn extend_r1_correct() {
    let a_frs = [Fr::from(5u64), Fr::from(10u64)];
    let b_frs = [Fr::from(3u64), Fr::from(7u64)];
    let wa = serialize_witness(&a_frs);
    let wb = serialize_witness(&b_frs);
    let a = make_instance(1, wa.clone());
    let b = make_instance(2, wb.clone());
    let ext = extend(&a, &b, 1).expect("extend r=1");

    assert_eq!(
        ext.combined_witness_bytes,
        wa.iter()
            .zip(wb.iter())
            .map(|(x, y)| x ^ y)
            .collect::<Vec<_>>()
    );
    assert_eq!(ext.challenge_r, 1);

    // r=1: combined = a + b; norm = max(|a_i + b_i|)
    use pvthfhe_cyclo::ring::Q_COMMIT;
    let expected_norm = a_frs
        .iter()
        .zip(b_frs.iter())
        .map(|(x, y)| {
            let sum = fr_u64(x) + fr_u64(y);
            let c = sum % Q_COMMIT;
            let neg = Q_COMMIT - c;
            if neg < c {
                neg
            } else {
                c
            }
        })
        .max()
        .unwrap();
    assert_eq!(ext.norm_estimate, expected_norm);
}

#[test]
fn extend_r_neg1_correct() {
    let a_frs = [Fr::from(100u64), Fr::from(50u64)];
    let b_frs = [Fr::from(30u64), Fr::from(20u64)];
    let wa = serialize_witness(&a_frs);
    let wb = serialize_witness(&b_frs);
    let a = make_instance(1, wa.clone());
    let b = make_instance(2, wb.clone());
    let ext = extend(&a, &b, -1).expect("extend r=-1");

    assert_eq!(
        ext.combined_witness_bytes,
        wa.iter()
            .zip(wb.iter())
            .map(|(x, y)| x ^ y)
            .collect::<Vec<_>>()
    );
    assert_eq!(ext.challenge_r, -1);

    // r=-1: combined = a - b; norm = max(|a_i - b_i|)
    use pvthfhe_cyclo::ring::Q_COMMIT;
    let expected_norm = a_frs
        .iter()
        .zip(b_frs.iter())
        .map(|(x, y)| {
            let diff = fr_u64(x).wrapping_sub(fr_u64(y));
            let c = diff % Q_COMMIT;
            let neg = Q_COMMIT - c;
            if neg < c {
                neg
            } else {
                c
            }
        })
        .max()
        .unwrap();
    assert_eq!(ext.norm_estimate, expected_norm);
}

#[test]
fn extend_rejects_invalid_r() {
    let wa = serialize_witness(&[Fr::from(1u64)]);
    let wb = serialize_witness(&[Fr::from(2u64)]);
    let a = make_instance(1, wa);
    let b = make_instance(2, wb);
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
    use pvthfhe_cyclo::ring::Q_COMMIT;
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let challenges = [-1i8, 0, 1];
    for i in 0u16..100 {
        let num_vars = (rng.next_u32() % 4 + 1) as usize;
        let mut frs_a = Vec::with_capacity(num_vars);
        let mut frs_b = Vec::with_capacity(num_vars);
        for _ in 0..num_vars {
            frs_a.push(Fr::from(rng.next_u64() % 1024));
            frs_b.push(Fr::from(rng.next_u64() % 1024));
        }
        let wa = serialize_witness(&frs_a);
        let wb = serialize_witness(&frs_b);
        let a = make_instance(i, wa);
        let b = make_instance(i + 100, wb);
        let r = challenges[(i % 3) as usize];
        let ext = extend(&a, &b, r).expect("extend should succeed");
        assert!(ext.norm_estimate < Q_COMMIT / 2);
        check_norm_budget(&ext, Q_COMMIT).expect("norm within Q_COMMIT budget");
    }
}
