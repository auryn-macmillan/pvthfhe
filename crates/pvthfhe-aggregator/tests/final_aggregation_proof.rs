use pvthfhe_aggregator::decrypt::{
    prove_final_aggregation, verify_final_aggregation, C6DecryptProofRef, CrtReconstructionClaim,
    FinalAggregationStatement, LagrangeCoefficientClaim, PlaintextEncodingClaim,
    ProvenDecryptShare,
};

fn plaintext_hash(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"pvthfhe-final-plaintext-hash-v1");
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn valid_statement() -> FinalAggregationStatement {
    let plaintext = b"OK".to_vec();
    FinalAggregationStatement {
        session_id: b"g1-session".to_vec(),
        dkg_root: [7u8; 32],
        ciphertext_hash: [9u8; 32],
        plaintext_hash: plaintext_hash(&plaintext),
        threshold: 2,
        accepted_participant_ids: vec![1, 2, 3],
        selected_shares: vec![
            ProvenDecryptShare {
                participant_id: 1,
                share_value_mod_plaintext: 5,
                proof_digest: [1u8; 32],
                proof_ref: C6DecryptProofRef {
                    dkg_root: [7u8; 32],
                    ciphertext_hash: [9u8; 32],
                    participant_id: 1,
                    decrypt_share_commitment: [11u8; 32],
                    proof_digest: [1u8; 32],
                },
            },
            ProvenDecryptShare {
                participant_id: 2,
                share_value_mod_plaintext: 9,
                proof_digest: [2u8; 32],
                proof_ref: C6DecryptProofRef {
                    dkg_root: [7u8; 32],
                    ciphertext_hash: [9u8; 32],
                    participant_id: 2,
                    decrypt_share_commitment: [12u8; 32],
                    proof_digest: [2u8; 32],
                },
            },
        ],
        lagrange_coefficients: vec![
            LagrangeCoefficientClaim {
                participant_id: 1,
                coefficient_mod_plaintext: 2,
            },
            LagrangeCoefficientClaim {
                participant_id: 2,
                coefficient_mod_plaintext: 65_535,
            },
        ],
        combined_share_mod_plaintext: 1,
        crt: CrtReconstructionClaim {
            moduli: vec![257, 263],
            residues: vec![1, 1],
            reconstructed_mod_plaintext: 1,
        },
        plaintext_encoding: PlaintextEncodingClaim {
            plaintext_modulus: 65_536,
            decoded_plaintext: plaintext,
            slots: vec![2, 0x4b4f],
        },
    }
}

#[test]
fn final_aggregation_proof_rejects_wrong_plaintext_with_valid_looking_shares() {
    let stmt = valid_statement();
    let proof = prove_final_aggregation(&stmt).expect("valid final aggregation proof");

    let mut wrong = stmt.clone();
    wrong.plaintext_encoding.decoded_plaintext = b"NO".to_vec();

    assert!(
        verify_final_aggregation(&wrong, &proof).is_err(),
        "public verifier must reject wrong plaintext without redoing BFV aggregation"
    );
}

#[test]
fn final_aggregation_proof_rejects_duplicate_participant_ids() {
    let mut stmt = valid_statement();
    stmt.selected_shares[1].participant_id = stmt.selected_shares[0].participant_id;

    assert!(prove_final_aggregation(&stmt).is_err());
}

#[test]
fn final_aggregation_proof_rejects_participant_outside_accepted_set() {
    let mut stmt = valid_statement();
    stmt.selected_shares[1].participant_id = 4;
    stmt.lagrange_coefficients[1].participant_id = 4;

    assert!(prove_final_aggregation(&stmt).is_err());
}

#[test]
fn final_aggregation_proof_rejects_wrong_lagrange_coefficient() {
    let mut stmt = valid_statement();
    stmt.lagrange_coefficients[0].coefficient_mod_plaintext = 3;

    assert!(prove_final_aggregation(&stmt).is_err());
}

#[test]
fn final_aggregation_proof_rejects_bad_crt_reconstruction() {
    let mut stmt = valid_statement();
    stmt.crt.residues[0] = 2;

    assert!(prove_final_aggregation(&stmt).is_err());
}

#[test]
fn final_aggregation_proof_rejects_bad_plaintext_decoding() {
    let mut stmt = valid_statement();
    stmt.plaintext_encoding.slots[1] = 0x4241;

    assert!(prove_final_aggregation(&stmt).is_err());
}

#[test]
fn final_aggregation_proof_rejects_mixed_session_c6_proof_ref() {
    let mut stmt = valid_statement();
    stmt.selected_shares[1].proof_ref.dkg_root = [8u8; 32];

    assert!(
        prove_final_aggregation(&stmt).is_err(),
        "C7 must not aggregate a C6 proof ref bound to a different DKG/session root"
    );
}

#[test]
fn final_aggregation_proof_rejects_mixed_ciphertext_c6_proof_ref() {
    let mut stmt = valid_statement();
    stmt.selected_shares[1].proof_ref.ciphertext_hash = [10u8; 32];

    assert!(
        prove_final_aggregation(&stmt).is_err(),
        "C7 must not aggregate a C6 proof ref bound to a different ciphertext"
    );
}

#[test]
fn final_aggregation_proof_rejects_plaintext_hash_mismatch() {
    let mut stmt = valid_statement();
    stmt.plaintext_hash = plaintext_hash(b"NO");

    assert!(
        prove_final_aggregation(&stmt).is_err(),
        "C7 statement must bind the public plaintext message through plaintext_hash"
    );
}

#[test]
fn final_aggregation_proof_digest_changes_when_c6_ref_changes() {
    let stmt = valid_statement();
    let proof = prove_final_aggregation(&stmt).expect("valid final aggregation proof");

    let mut changed = stmt.clone();
    changed.selected_shares[0]
        .proof_ref
        .decrypt_share_commitment = [13u8; 32];

    assert!(
        verify_final_aggregation(&changed, &proof).is_err(),
        "changing a bound C6 decryption-share commitment must invalidate the C7 proof"
    );
}
