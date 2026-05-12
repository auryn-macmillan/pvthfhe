#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use pvthfhe_pvss::nizk_decrypt::{
    DecryptNizkMode, DecryptNizkProof, DecryptNizkProver, DecryptNizkStatement,
    DecryptNizkVerifier, DecryptNizkWitness,
};
use pvthfhe_pvss::PvssError;

fn sample_statement() -> DecryptNizkStatement {
    DecryptNizkStatement {
        session_id: vec![9; 32],
        party_index: 1,
        ciphertext_u: vec![0x10, 0x20, 0x30, 0x40],
        ciphertext_v: vec![0xAA; 32],
        decrypted_share_bytes: vec![0x01, 0x02, 0x03, 0x04],
        party_pk: vec![0x55; 48],
        epoch: 0,
        dkg_root: vec![0xAB; 32],
        mode: DecryptNizkMode::LegacyLocalSmudge,
    }
}

fn sample_witness() -> DecryptNizkWitness {
    DecryptNizkWitness {
        secret_key_bytes: vec![0x11; 64],
        decryption_noise: vec![0x22; 64],
        sk_agg_share: None,
        esm_agg_share: None,
        esm_noise_poly_bytes: None,
    }
}

#[test]
fn changing_dkg_root_rejects_verify() {
    let stmt_a = sample_statement();
    let witness = sample_witness();
    let proof = DecryptNizkProver::prove(&stmt_a, &witness).expect("prove with dkg_root");

    // Verify with same statement works.
    DecryptNizkVerifier::verify(&stmt_a, &proof).expect("verify with correct dkg_root");

    // Change only dkg_root and verify must fail.
    let mut stmt_b = stmt_a.clone();
    stmt_b.dkg_root = vec![0xCD; 64];

    let result = DecryptNizkVerifier::verify(&stmt_b, &proof);
    assert_eq!(result, Err(PvssError::InvalidShare));
}

#[test]
fn encode_decode_roundtrip_preserves_dkg_root() {
    let stmt = sample_statement();
    let witness = sample_witness();
    let proof = DecryptNizkProver::prove(&stmt, &witness).expect("prove");

    let decoded = DecryptNizkProof::from_bytes(proof.proof_bytes.clone()).expect("decode proof");
    let opened = decoded.decode().expect("reopen proof");

    assert_eq!(
        opened.statement.dkg_root, stmt.dkg_root,
        "dkg_root must survive wire-format roundtrip"
    );

    // Encode → decode roundtrip produces identical data.
    let reopened_stmt = opened.statement;
    assert_eq!(reopened_stmt.dkg_root, stmt.dkg_root);
    assert_eq!(reopened_stmt, stmt, "full statement must roundtrip");
}

#[test]
fn statement_mismatch_due_to_dkg_root_fails() {
    let stmt_a = sample_statement();
    let witness = sample_witness();
    let proof = DecryptNizkProver::prove(&stmt_a, &witness).expect("prove");

    let mut stmt_b = sample_statement();
    stmt_b.dkg_root = vec![0xEF; 64];

    // Statement mismatch is checked by the verifier after decoding.
    let result = DecryptNizkVerifier::verify(&stmt_b, &proof);
    assert_eq!(result, Err(PvssError::InvalidShare));
}

#[test]
fn empty_dkg_root_rejected() {
    let mut stmt = sample_statement();
    stmt.dkg_root = vec![];

    let witness = sample_witness();
    let result = DecryptNizkProver::prove(&stmt, &witness);
    assert_eq!(result, Err(PvssError::InvalidShare));
}

#[test]
fn oversized_dkg_root_rejected() {
    let mut stmt = sample_statement();
    stmt.dkg_root = vec![0xFF; 1 << 21]; // exceeds MAX_FIELD_LEN (1 << 20)

    let witness = sample_witness();
    let result = DecryptNizkProver::prove(&stmt, &witness);
    assert_eq!(result, Err(PvssError::InvalidShare));
}
