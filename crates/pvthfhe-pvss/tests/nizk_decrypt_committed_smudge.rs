use pvthfhe_fhe::{mock::MockBackend, FheBackend};
use pvthfhe_pvss::dkg_aggregation::{
    compute_esm_aggregate_commitment, compute_sk_aggregate_commitment,
};
use pvthfhe_pvss::encrypt::{CommittedSmudgeUse, LatticePvssBfvAdapter};
use pvthfhe_pvss::nizk_decrypt::{
    derive_party_binding, CommittedSmudgeSlot, DecryptNizkMode, DecryptNizkProof,
    DecryptNizkProver, DecryptNizkStatement, DecryptNizkVerifier, DecryptNizkWitness,
};
use pvthfhe_pvss::slot_registry::SmudgeSlotRegistry;
use pvthfhe_pvss::{PvssContext, PvssError};
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
        committed_smudge_slot: None,
    }
}

fn acknowledge_mock_backend() {
    unsafe {
        std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
    }
}

#[test]
fn production_adapter_committed_smudge_uses_caller_slot_and_round() {
    acknowledge_mock_backend();

    let adapter = LatticePvssBfvAdapter::new_with_backend(
        MockBackend::load_params("[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n")
            .expect("load mock backend"),
    );
    let ctx = PvssContext {
        n: 4,
        t: 2,
        session_id: vec![0x51; 32],
        epoch: 7,
        dkg_root: vec![0xD4; 32],
        dealer_index: pvthfhe_pvss::derive_dealer_index(&[0x51; 32]),
    };
    let slot_id = 7;
    let decrypt_round = 42;
    let committed_esm = esm_noise_bytes_for_test();
    let proof_share = adapter
        .prove_decrypted_share(
            &[0x10, 0x20, 0x30, 0x40],
            &[0x55; 48],
            1,
            vec![0x01, 0x02, 0x03, 0x04],
            &committed_witness(),
            &ctx,
            Some(committed_esm),
            Some(CommittedSmudgeUse {
                slot_id,
                decrypt_round,
            }),
            Some(0x11_u64),
        )
        .expect("production adapter committed proof");
    let proof = DecryptNizkProof::from_bytes(proof_share.proof.0).expect("decode proof envelope");
    let opened = proof.decode().expect("open decrypt proof");

    match opened.statement.mode {
        DecryptNizkMode::CommittedSmudge {
            slot_id: opened_slot_id,
            decrypt_round: opened_decrypt_round,
            ..
        } => {
            assert_eq!(opened_slot_id, slot_id);
            assert_eq!(opened_decrypt_round, decrypt_round);
        }
        DecryptNizkMode::LegacyLocalSmudge => panic!("expected committed-smudge mode"),
    }
}

#[test]
fn production_adapter_rejects_zero_committed_smudge_slot() {
    acknowledge_mock_backend();

    let adapter = LatticePvssBfvAdapter::new_with_backend(
        MockBackend::load_params("[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n")
            .expect("load mock backend"),
    );
    let ctx = PvssContext {
        n: 4,
        t: 2,
        session_id: vec![0x51; 32],
        epoch: 7,
        dkg_root: vec![0xD4; 32],
        dealer_index: pvthfhe_pvss::derive_dealer_index(&[0x51; 32]),
    };

    let result = adapter.prove_decrypted_share(
        &[0x10, 0x20, 0x30, 0x40],
        &[0x55; 48],
        1,
        vec![0x01, 0x02, 0x03, 0x04],
        &committed_witness(),
        &ctx,
        Some(esm_noise_bytes_for_test()),
        Some(CommittedSmudgeUse {
            slot_id: 0,
            decrypt_round: 42,
        }),
        Some(0x11_u64),
    );

    assert_eq!(result, Err(PvssError::InvalidShare));
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
        sk_agg_share: Some(legacy.expected_sk_agg_share),
        esm_agg_share: None,
        esm_noise_poly_bytes: None,
        committed_smudge_slot: None,
    };
    let proof = DecryptNizkProver::prove(&legacy, &legacy_witness)
        .expect("legacy local-smudge proof remains explicit non-equivalent mode");

    let result = DecryptNizkVerifier::verify(&committed, &proof);

    assert_eq!(result, Err(PvssError::InvalidShare));
}

#[test]
fn committed_smudge_legacy_missing_sk_agg_share_fails_closed() {
    let mut statement = committed_statement();
    statement.mode = DecryptNizkMode::LegacyLocalSmudge;
    statement.expected_sk_agg_share = derive_party_binding(&statement.party_pk);

    let witness = DecryptNizkWitness {
        secret_key_bytes: Secret::new(vec![0x11; 64]),
        decryption_noise: Secret::new(vec![0x99; 64]),
        sk_agg_share: None,
        esm_agg_share: None,
        esm_noise_poly_bytes: None,
        committed_smudge_slot: None,
    };

    let result = DecryptNizkProver::prove(&statement, &witness)
        .and_then(|proof| DecryptNizkVerifier::verify(&statement, &proof));

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

// ── C6: committed-smudge slot binding and uniqueness ──────────────────

#[test]
fn committed_smudge_binds_to_ciphertext() {
    let statement = committed_statement();
    let witness = committed_witness();
    let proof = DecryptNizkProver::prove(&statement, &witness).expect("committed proof");

    DecryptNizkVerifier::verify(&statement, &proof).expect("honest proof verifies");

    let mut wrong_ct = statement.clone();
    wrong_ct.ciphertext_u = vec![0xFF, 0xEE, 0xDD, 0xCC];
    wrong_ct.ciphertext_v = vec![0xBB; 32];
    if let DecryptNizkMode::CommittedSmudge {
        slot_id,
        decrypt_round,
        accepted_participant_ids,
        sk_agg_commit,
        esm_agg_commit,
        ..
    } = &statement.mode
    {
        wrong_ct.mode = DecryptNizkMode::CommittedSmudge {
            slot_id: *slot_id,
            decrypt_round: *decrypt_round,
            ciphertext_hash: pvthfhe_pvss::nizk_decrypt::compute_decrypt_ciphertext_hash(
                &wrong_ct.ciphertext_u,
                &wrong_ct.ciphertext_v,
            ),
            accepted_participant_ids: accepted_participant_ids.clone(),
            sk_agg_commit: *sk_agg_commit,
            esm_agg_commit: *esm_agg_commit,
        };
    }

    let result = DecryptNizkVerifier::verify(&wrong_ct, &proof);
    assert_eq!(
        result,
        Err(PvssError::InvalidShare),
        "changing ciphertext must change committed-smudge slot binding causing rejection"
    );
}

#[test]
fn committed_smudge_slot_uniqueness() {
    let mut registry = SmudgeSlotRegistry::new();
    let statement = committed_statement();
    let mut witness = committed_witness();

    let slot = CommittedSmudgeSlot::from_statement(&statement)
        .expect("statement has CommittedSmudge mode");
    witness.committed_smudge_slot = Some(slot);

    let _proof1 = DecryptNizkProver::prove_with_registry(&statement, &witness, &mut registry)
        .expect("first slot use succeeds");

    let result = DecryptNizkProver::prove_with_registry(&statement, &witness, &mut registry);
    assert!(
        result.is_err(),
        "reusing the same smudge slot must be rejected"
    );
}

#[test]
fn committed_smudge_slot_epoch_binding() {
    let statement = committed_statement();
    let mut witness = committed_witness();

    let slot = CommittedSmudgeSlot {
        epoch: statement.epoch + 1,
        slot_index: SLOT_ID,
        ciphertext_hash: match &statement.mode {
            DecryptNizkMode::CommittedSmudge {
                ciphertext_hash, ..
            } => *ciphertext_hash,
            DecryptNizkMode::LegacyLocalSmudge => unreachable!(),
        },
        decryption_round: DECRYPT_ROUND,
    };
    witness.committed_smudge_slot = Some(slot);

    let result = DecryptNizkProver::prove(&statement, &witness);
    assert_eq!(
        result,
        Err(PvssError::InvalidShare),
        "epoch mismatch in committed-smudge slot must be rejected"
    );
}
