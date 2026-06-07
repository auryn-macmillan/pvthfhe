//! R3.2 RED: Adversary without `sk_i` cannot produce a valid partial-decrypt
//! NIZK proof.  Currently `derive_secret_share` makes the binding vacuous:
//! any witness produces a verifiable proof because the commitment depends
//! only on public statement fields.

use pvthfhe_pvss::nizk_decrypt::{
    DecryptNizkMode, DecryptNizkProver, DecryptNizkStatement, DecryptNizkVerifier,
    DecryptNizkWitness,
};
use pvthfhe_types::Secret;

fn sample_statement() -> DecryptNizkStatement {
    DecryptNizkStatement {
        session_id: vec![0xAA; 32],
        party_index: 7,
        ciphertext_u: vec![0x01, 0x02, 0x03, 0x04],
        ciphertext_v: vec![0xBB; 32],
        decrypted_share_bytes: vec![0x10, 0x20, 0x30, 0x40],
        party_pk: vec![0xCC; 48],
        epoch: 0,
        dkg_root: vec![0xDD; 32],
        expected_sk_agg_share: 0x1234_5678_9ABC_DEF0,
        dealer_index: pvthfhe_pvss::derive_dealer_index(&[0xAA; 32]),
        mode: DecryptNizkMode::LegacyLocalSmudge,
    }
}

/// Prover with an obviously-wrong secret key (all zeroes) can currently
/// forge a valid proof because `derive_secret_share` does not depend on
/// `secret_key_bytes` — the `secret_share` scalar used in the hash binding
/// is derived from public statement fields.
///
/// After GREEN, a proof produced with a secret key that does not match
/// the party's real `sk_i` must be REJECTED by the verifier.
#[test]
fn adversary_without_ski_cannot_produce_valid_proof() {
    let stmt = sample_statement();

    // Witness with a trivially-wrong "secret key" — this should fail
    // verification because the NIZK must prove knowledge of
    // the REAL sk_agg_share matching expected_sk_agg_share in the statement.
    let wrong_witness = DecryptNizkWitness {
        secret_key_bytes: Secret::new(vec![0x00; 64]),
        decryption_noise: Secret::new(vec![0x00; 64]),
        sk_agg_share: None,
        esm_agg_share: None,
        esm_noise_poly_bytes: None,
        committed_smudge_slot: None,
    };

    // The adversary (who does not know the real sk_agg_share) must not even
    // obtain a legacy proof by falling back to a public-key-derived binding.
    let result = DecryptNizkProver::prove(&stmt, &wrong_witness);

    assert!(
        result.is_err(),
        "Proof with wrong sk_agg_share must be REJECTED (soundness violation)."
    );
}

/// Demonstrate that two different witnesses produce proofs that both verify
/// for the same statement.  This is a soundness failure: the verifier cannot
/// tell which party (with which sk_i) produced the proof, making the NIZK
/// useless for attributing decryption shares.
#[test]
fn two_different_witnesses_both_verify() {
    let stmt = sample_statement();
    let correct_sk = stmt.expected_sk_agg_share;

    let witness_a = DecryptNizkWitness {
        secret_key_bytes: Secret::new(vec![0x11; 64]),
        decryption_noise: Secret::new(vec![0x22; 64]),
        sk_agg_share: Some(correct_sk),
        esm_agg_share: None,
        esm_noise_poly_bytes: None,
        committed_smudge_slot: None,
    };
    let witness_b = DecryptNizkWitness {
        secret_key_bytes: Secret::new(vec![0xAA; 64]),
        decryption_noise: Secret::new(vec![0xBB; 64]),
        sk_agg_share: Some(correct_sk ^ 0xFFFF_FFFF),
        esm_agg_share: None,
        esm_noise_poly_bytes: None,
        committed_smudge_slot: None,
    };

    let proof_a = DecryptNizkProver::prove(&stmt, &witness_a).expect("prove with witness a");
    let proof_b = DecryptNizkProver::prove(&stmt, &witness_b).expect("prove with witness b");

    let result_a = DecryptNizkVerifier::verify(&stmt, &proof_a);
    let result_b = DecryptNizkVerifier::verify(&stmt, &proof_b);

    assert!(
        result_a.is_err() || result_b.is_err(),
        "At least one proof with a different witness must be REJECTED. \
         Both currently accepted (soundness violation)."
    );
}
