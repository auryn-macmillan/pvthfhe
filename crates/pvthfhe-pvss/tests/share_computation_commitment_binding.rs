use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, Zero};
use pvthfhe_pvss::share_computation::{
    compute_esm_secret_commitment, compute_sk_secret_commitment, verify_batched_share_computation,
    BatchedShareComputationStatement, ESmShareComputationSlot, FieldShare, ShareComputationError,
    ShareComputationTrack,
};
use pvthfhe_types::ProtocolBytes;

fn shamir_split_small(secret: &Fr, n: usize, t: usize) -> Vec<(usize, Fr)> {
    let mut coeffs = vec![*secret];
    for i in 1..t {
        coeffs.push(Fr::from((i + 1) as u64));
    }
    let mut shares = Vec::with_capacity(n);
    for i in 1..=n {
        let x = Fr::from(i as u64);
        let y = coeffs.iter().rev().fold(Fr::ZERO, |acc, c| acc * x + c);
        shares.push((i, y));
    }
    shares
}

fn make_statement(
    shares: &[(usize, Fr)],
    claimed_p0: Fr,
    dealer_id: u16,
    threshold: usize,
) -> BatchedShareComputationStatement {
    let share_vals: Vec<FieldShare> = shares
        .iter()
        .map(|&(idx, val)| FieldShare {
            recipient_index: idx as u16,
            value: val,
        })
        .collect();
    let n = shares.len();
    let esm_vals: Vec<FieldShare> = (1..=n)
        .map(|i| FieldShare {
            recipient_index: i as u16,
            value: Fr::zero(),
        })
        .collect();
    let esm_commit =
        compute_esm_secret_commitment(b"test-session", &[0u8; 32], dealer_id, 1, Fr::zero());
    BatchedShareComputationStatement {
        session_id: ProtocolBytes::from(b"test-session".to_vec()),
        dkg_root: ProtocolBytes::from(vec![0u8; 32]),
        dealer_id,
        max_degree: threshold.saturating_sub(1),
        coefficient_bound: u64::MAX,
        sk: ShareComputationTrack {
            shares: share_vals,
            secret_commitment: compute_sk_secret_commitment(
                b"test-session",
                &[0u8; 32],
                dealer_id,
                claimed_p0,
            ),
        },
        esm_slots: vec![ESmShareComputationSlot {
            slot_index: 1,
            shares: esm_vals,
            smudge_commitment: esm_commit,
        }],
    }
}

#[test]
fn rejects_wrong_secret_commitment() {
    let n: usize = 16;
    let t: usize = 7;
    let secret = Fr::from(42u64);
    let shares = shamir_split_small(&secret, n, t);
    let wrong_p0 = secret + Fr::from(1u64);
    let stmt = make_statement(&shares, wrong_p0, 1, t);
    let result = verify_batched_share_computation(&stmt);
    assert!(
        matches!(
            result,
            Err(ShareComputationError::CommitmentMismatch { .. })
        ),
        "should reject wrong P(0) commitment; got {:?}",
        result,
    );
}

#[test]
fn accepts_correct_secret_commitment() {
    let n: usize = 16;
    let t: usize = 7;
    let secret = Fr::from(42u64);
    let shares = shamir_split_small(&secret, n, t);
    let stmt = make_statement(&shares, secret, 1, t);
    let result = verify_batched_share_computation(&stmt);
    assert!(
        result.is_ok(),
        "should accept correct P(0) commitment; got {:?}",
        result,
    );
}

#[test]
fn rejects_non_low_degree_shares() {
    let n: usize = 16;
    let t: usize = 7;
    let secret = Fr::from(42u64);
    let mut shares = shamir_split_small(&secret, n, t);
    shares[3].1 += Fr::from(1u64);
    let stmt = make_statement(&shares, secret, 1, t);
    let result = verify_batched_share_computation(&stmt);
    assert!(
        matches!(result, Err(ShareComputationError::NonLowDegree { .. })),
        "should reject non-low-degree shares; got {:?}",
        result,
    );
}
