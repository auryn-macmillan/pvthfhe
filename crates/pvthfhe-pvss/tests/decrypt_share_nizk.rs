//! Integration tests for PVSS decrypt-share NIZKs.

use pvthfhe_pvss::nizk_decrypt::{
    DecryptNizkMode, DecryptNizkProof, DecryptNizkProver, DecryptNizkStatement,
    DecryptNizkVerifier, DecryptNizkWitness, DECRYPT_NIZK_DOMAIN_SEPARATOR,
};
use pvthfhe_pvss::PvssError;
use pvthfhe_types::Secret;

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
        expected_sk_agg_share: pvthfhe_pvss::nizk_decrypt::derive_party_binding(&[0x55; 48]),
        dealer_index: pvthfhe_pvss::derive_dealer_index(&[9; 32]),
        mode: DecryptNizkMode::LegacyLocalSmudge,
    }
}

fn sample_witness() -> DecryptNizkWitness {
    DecryptNizkWitness {
        secret_key_bytes: Secret::new(vec![0x11; 64]),
        decryption_noise: Secret::new(vec![0x22; 64]),
        sk_agg_share: Some(pvthfhe_pvss::nizk_decrypt::derive_party_binding(
            &[0x55; 48],
        )),
        esm_agg_share: None,
        esm_noise_poly_bytes: None,
        committed_smudge_slot: None,
    }
}

#[test]
fn honest_decryption_accepted() {
    let statement = sample_statement();
    let witness = sample_witness();

    let proof = DecryptNizkProver::prove(&statement, &witness).expect("prove honest decrypt share");
    assert_eq!(proof.domain_separator, DECRYPT_NIZK_DOMAIN_SEPARATOR);

    let decoded = DecryptNizkProof::from_bytes(proof.proof_bytes.clone()).expect("decode proof");
    DecryptNizkVerifier::verify(&statement, &decoded).expect("accept honest decrypt-share proof");
}

#[test]
fn epoch_roundtrips_through_wire_format() {
    let mut statement = sample_statement();
    statement.epoch = 42;

    let witness = sample_witness();
    let proof = DecryptNizkProver::prove(&statement, &witness).expect("prove with non-zero epoch");

    let decoded =
        DecryptNizkProof::from_bytes(proof.proof_bytes).expect("decode epoch-bearing proof");

    let reopened = decoded.decode().expect("reopen epoch-bearing proof");

    assert_eq!(
        reopened.statement.epoch, 42,
        "epoch must survive wire-format round-trip, got {}",
        reopened.statement.epoch
    );
}

#[test]
fn forged_decryption_rejected() {
    let statement = sample_statement();
    let witness = sample_witness();
    let proof = DecryptNizkProver::prove(&statement, &witness).expect("prove honest decrypt share");

    let mut forged = statement.clone();
    forged.decrypted_share_bytes[0] ^= 0xFF;

    let result = DecryptNizkVerifier::verify(&forged, &proof);
    assert_eq!(result, Err(PvssError::InvalidShare));
}
