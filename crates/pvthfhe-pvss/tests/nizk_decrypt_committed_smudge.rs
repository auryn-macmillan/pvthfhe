use pvthfhe_pvss::dkg_aggregation::{
    compute_esm_aggregate_commitment, compute_sk_aggregate_commitment,
};
use pvthfhe_pvss::nizk_decrypt::{
    derive_party_binding, DecryptNizkMode, DecryptNizkProver, DecryptNizkStatement,
    DecryptNizkVerifier, DecryptNizkWitness,
};
use pvthfhe_pvss::PvssError;
use pvthfhe_types::Secret;

const SLOT_ID: u16 = 3;
const DECRYPT_ROUND: u64 = 9;

fn esm_noise_bytes_for_test() -> Vec<u8> {
    vec![0xEE; 64]
}

fn committed_esm_agg_share() -> u64 {
    derive_party_binding(&esm_noise_bytes_for_test())
}

fn committed_statement() -> DecryptNizkStatement {
    let session_id = vec![0x51; 32];
    let dkg_root = vec![0xD4; 32];
    let accepted_dealers = vec![1, 2, 4];
    let sk_agg_share = 0x11_u64;
    let esm_agg_share = committed_esm_agg_share();

    DecryptNizkStatement {
        session_id: session_id.clone(),
        party_index: 1,
        ciphertext_u: vec![0x10, 0x20, 0x30, 0x40],
        ciphertext_v: vec![0xAA; 32],
        decrypted_share_bytes: vec![0x01, 0x02, 0x03, 0x04],
        party_pk: vec![0x55; 48],
        epoch: 7,
        dkg_root: dkg_root.clone(),
        expected_sk_agg_share: sk_agg_share,
        dealer_index: pvthfhe_pvss::derive_dealer_index(&session_id),
        mode: DecryptNizkMode::CommittedSmudge {
            slot_id: SLOT_ID,
            decrypt_round: DECRYPT_ROUND,
            ciphertext_hash: pvthfhe_pvss::nizk_decrypt::compute_decrypt_ciphertext_hash(
                &[0x10, 0x20, 0x30, 0x40],
                &[0xAA; 32],
            ),
            accepted_participant_ids: accepted_dealers.clone(),
            sk_agg_commit: compute_sk_aggregate_commitment(
                &session_id,
                &dkg_root,
                1,
                &accepted_dealers,
                ark_bn254::Fr::from(sk_agg_share),
            ),
            esm_agg_commit: compute_esm_aggregate_commitment(
                &session_id,
                &dkg_root,
                1,
                &accepted_dealers,
                SLOT_ID,
                ark_bn254::Fr::from(esm_agg_share),
            ),
        },
    }
}

fn committed_witness() -> DecryptNizkWitness {
    DecryptNizkWitness {
        secret_key_bytes: Secret::new(vec![0x11; 64]),
        decryption_noise: Secret::new(vec![0x22; 64]),
        sk_agg_share: Some(0x11_u64),
        esm_agg_share: Some(committed_esm_agg_share()),
        esm_noise_poly_bytes: Some(esm_noise_bytes_for_test()),
    }
}

#[test]
fn committed_smudge_requires_explicit_esm_witness() {
    let statement = committed_statement();
    let mut witness = committed_witness();
    witness.esm_agg_share = None;
    witness.esm_noise_poly_bytes = None;

    let result = DecryptNizkProver::prove(&statement, &witness);

    assert_eq!(result, Err(PvssError::InvalidShare));
}

#[test]
fn committed_smudge_rejects_local_smudge_proof() {
    let committed = committed_statement();
    let mut legacy = committed.clone();
    legacy.mode = DecryptNizkMode::LegacyLocalSmudge;

    let legacy_witness = DecryptNizkWitness {
        secret_key_bytes: Secret::new(vec![0x11; 64]),
        decryption_noise: Secret::new(vec![0x99; 64]),
        sk_agg_share: None,
        esm_agg_share: None,
        esm_noise_poly_bytes: None,
    };
    let proof = DecryptNizkProver::prove(&legacy, &legacy_witness)
        .expect("legacy local-smudge proof remains explicit non-equivalent mode");

    let result = DecryptNizkVerifier::verify(&committed, &proof);

    assert_eq!(result, Err(PvssError::InvalidShare));
}

#[test]
fn committed_smudge_binds_slot_round_and_aggregate_commitments() {
    let statement = committed_statement();
    let witness = committed_witness();
    let proof = DecryptNizkProver::prove(&statement, &witness).expect("committed proof");

    DecryptNizkVerifier::verify(&statement, &proof).expect("honest committed proof verifies");

    let mut wrong_round = statement.clone();
    wrong_round.mode = DecryptNizkMode::CommittedSmudge {
        slot_id: SLOT_ID,
        decrypt_round: DECRYPT_ROUND + 1,
        ciphertext_hash: pvthfhe_pvss::nizk_decrypt::compute_decrypt_ciphertext_hash(
            &statement.ciphertext_u,
            &statement.ciphertext_v,
        ),
        accepted_participant_ids: match &statement.mode {
            DecryptNizkMode::CommittedSmudge {
                accepted_participant_ids,
                ..
            } => accepted_participant_ids.clone(),
            DecryptNizkMode::LegacyLocalSmudge => unreachable!(),
        },
        sk_agg_commit: match &statement.mode {
            DecryptNizkMode::CommittedSmudge { sk_agg_commit, .. } => *sk_agg_commit,
            DecryptNizkMode::LegacyLocalSmudge => unreachable!(),
        },
        esm_agg_commit: match &statement.mode {
            DecryptNizkMode::CommittedSmudge { esm_agg_commit, .. } => *esm_agg_commit,
            DecryptNizkMode::LegacyLocalSmudge => unreachable!(),
        },
    };

    let result = DecryptNizkVerifier::verify(&wrong_round, &proof);

    assert_eq!(result, Err(PvssError::InvalidShare));
}

/// RED test (Batch B.2): prover must reject a witness whose esm_agg_share
/// does not match derive_party_binding(esm_noise_poly_bytes).
///
/// Before the cross-check is enforced, this test should FAIL because the
/// prover accepts the mismatched witness. After enforcement, the mismatch
/// is detected and the prover returns InvalidShare.
#[test]
fn red_committed_smudge_esm_share_binding() {
    let statement = committed_statement();
    let mut witness = committed_witness();
    witness.esm_agg_share = Some(0xDEAD_BEEF);

    let result = DecryptNizkProver::prove(&statement, &witness);

    assert!(
        result.is_err(),
        "prover must reject witness with esm_agg_share not matching esm_noise_poly_bytes"
    );
    assert_eq!(
        result,
        Err(PvssError::InvalidShare),
        "mismatched esm_agg_share must produce InvalidShare"
    );
}
