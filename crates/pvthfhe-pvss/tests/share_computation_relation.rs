//! Focused E.1 tests for batched two-track Shamir/RS share computation.

use ark_bn254::Fr;
use ark_ff::AdditiveGroup;
use pvthfhe_pvss::share_computation::{
    compute_esm_secret_commitment, compute_sk_secret_commitment, verify_batched_share_computation,
    BatchedShareComputationStatement, ESmShareComputationSlot, FieldShare, ShareComputationTrack,
};

fn eval(coeffs: &[Fr], x: usize) -> Fr {
    let x = Fr::from(x as u64);
    coeffs
        .iter()
        .rev()
        .fold(Fr::ZERO, |acc, coeff| acc * x + coeff)
}

fn shares(coeffs: &[Fr], n: usize) -> Vec<FieldShare> {
    (1..=n)
        .map(|x| FieldShare {
            recipient_index: x as u16,
            value: eval(coeffs, x),
        })
        .collect()
}

fn valid_statement() -> BatchedShareComputationStatement {
    let session_id = b"e1-session".to_vec();
    let dkg_root = b"e1-dkg-root".to_vec();
    let dealer_id = 7;
    let sk_coeffs = vec![Fr::from(11u64), Fr::from(2u64), Fr::from(3u64)];
    let esm0_coeffs = vec![Fr::from(17u64), Fr::from(4u64), Fr::from(5u64)];
    let esm1_coeffs = vec![Fr::from(19u64), Fr::from(6u64), Fr::from(7u64)];

    BatchedShareComputationStatement {
        session_id: session_id.clone(),
        dkg_root: dkg_root.clone(),
        dealer_id,
        max_degree: 2,
        coefficient_bound: 32,
        sk: ShareComputationTrack {
            shares: shares(&sk_coeffs, 6),
            secret_commitment: compute_sk_secret_commitment(
                &session_id,
                &dkg_root,
                dealer_id,
                sk_coeffs[0],
            ),
        },
        esm_slots: vec![
            ESmShareComputationSlot {
                slot_index: 0,
                shares: shares(&esm0_coeffs, 6),
                smudge_commitment: compute_esm_secret_commitment(
                    &session_id,
                    &dkg_root,
                    dealer_id,
                    0,
                    esm0_coeffs[0],
                ),
            },
            ESmShareComputationSlot {
                slot_index: 1,
                shares: shares(&esm1_coeffs, 6),
                smudge_commitment: compute_esm_secret_commitment(
                    &session_id,
                    &dkg_root,
                    dealer_id,
                    1,
                    esm1_coeffs[0],
                ),
            },
        ],
    }
}

#[test]
fn accepts_batched_sk_and_esm_low_degree_relation() {
    let checked = verify_batched_share_computation(&valid_statement()).expect("valid relation");

    assert_eq!(checked.public_instance_commitment.len(), 32);
    assert_eq!(checked.sk_coefficients.len(), 3);
    assert_eq!(checked.esm_coefficients.len(), 2);
}

#[test]
fn rejects_tampered_esm_share_while_sk_remains_valid() {
    let mut statement = valid_statement();
    statement.esm_slots[0].shares[4].value += Fr::from(1u64);

    let err = verify_batched_share_computation(&statement).expect_err("tampered e_sm rejected");

    assert!(err.to_string().contains("e_sm slot 0"));
}

#[test]
fn rejects_non_low_degree_sk_share_vector() {
    let mut statement = valid_statement();
    statement.sk.shares[5].value += Fr::from(9u64);

    let err = verify_batched_share_computation(&statement).expect_err("non-low-degree sk rejected");

    assert!(err.to_string().contains("sk"));
}

#[test]
fn rejects_secret_commitment_replay_across_sessions() {
    let mut statement = valid_statement();
    statement.session_id = b"different-session".to_vec();

    let err = verify_batched_share_computation(&statement).expect_err("session replay rejected");

    assert!(err.to_string().contains("secret commitment"));
}

#[test]
fn foldable_public_instance_commitment_is_deterministic_and_session_bound() {
    let statement = valid_statement();
    let first = verify_batched_share_computation(&statement)
        .expect("valid relation")
        .public_instance_commitment;
    let second = verify_batched_share_computation(&statement)
        .expect("valid relation")
        .public_instance_commitment;
    assert_eq!(first, second);

    let mut changed = statement;
    changed.dkg_root = b"other-root".to_vec();
    let err = verify_batched_share_computation(&changed).expect_err("root replay rejected");
    assert!(err.to_string().contains("secret commitment"));
}

#[test]
fn rejects_coefficients_outside_public_bound() {
    let mut statement = valid_statement();
    statement.coefficient_bound = 6;

    let err = verify_batched_share_computation(&statement).expect_err("coefficient bound enforced");

    assert!(err.to_string().contains("coefficient bound"));
}
