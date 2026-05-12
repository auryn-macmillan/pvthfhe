//! Public anchor storage and acceptance tests for the off-chain verifier.

use pvthfhe_offchain_verifier::{
    accept_verified_plaintext, DkgPublicAnchors, InMemoryDkgAnchorStore, PublicAnchorError,
    VerifiedDecryption,
};

fn digest(value: u8) -> [u8; 32] {
    [value; 32]
}

fn dkg_anchors() -> DkgPublicAnchors {
    DkgPublicAnchors {
        dkg_root: digest(1),
        aggregated_pk_commit: digest(2),
        participant_set_hash: digest(3),
        sk_agg_commits_root: digest(4),
        esm_agg_commits_root: digest(5),
        smudge_slot_policy_hash: digest(6),
    }
}

fn verified_decryption() -> VerifiedDecryption {
    VerifiedDecryption {
        dkg_root: digest(1),
        ciphertext_hash: digest(7),
        expected_sk_commits_root: digest(4),
        expected_esm_commits_root: digest(5),
        slot_id: 11,
        decrypt_round: 12,
        plaintext_hash: digest(8),
        plaintext: b"accepted plaintext".to_vec(),
        proof_verified: true,
    }
}

#[test]
fn stored_dkg_anchors_roundtrip_and_matching_decryption_accepts_plaintext() {
    let mut store = InMemoryDkgAnchorStore::default();
    let anchors = dkg_anchors();
    store.store_dkg_anchors(anchors.clone()).unwrap();

    assert_eq!(store.load_dkg_anchors(&anchors.dkg_root), Some(&anchors));

    let decrypt = verified_decryption();
    let accepted = accept_verified_plaintext(&store, &decrypt).unwrap();
    assert_eq!(accepted, b"accepted plaintext");
}

#[test]
fn mismatched_esm_anchor_rejects_before_plaintext_acceptance() {
    let mut store = InMemoryDkgAnchorStore::default();
    store.store_dkg_anchors(dkg_anchors()).unwrap();

    let mut decrypt = verified_decryption();
    decrypt.expected_esm_commits_root = digest(89);

    let err = accept_verified_plaintext(&store, &decrypt).unwrap_err();
    assert_eq!(err, PublicAnchorError::AnchorMismatch);
}

#[test]
fn mismatched_dkg_root_or_sk_anchor_rejects_before_plaintext_acceptance() {
    let mut store = InMemoryDkgAnchorStore::default();
    store.store_dkg_anchors(dkg_anchors()).unwrap();

    let mut wrong_dkg = verified_decryption();
    wrong_dkg.dkg_root = digest(99);
    assert_eq!(
        accept_verified_plaintext(&store, &wrong_dkg).unwrap_err(),
        PublicAnchorError::UnknownDkgRoot
    );

    let mut wrong_sk = verified_decryption();
    wrong_sk.expected_sk_commits_root = digest(88);
    assert_eq!(
        accept_verified_plaintext(&store, &wrong_sk).unwrap_err(),
        PublicAnchorError::AnchorMismatch
    );
}

#[test]
fn unverified_proof_never_accepts_plaintext_even_when_anchors_match() {
    let mut store = InMemoryDkgAnchorStore::default();
    store.store_dkg_anchors(dkg_anchors()).unwrap();

    let mut decrypt = verified_decryption();
    decrypt.proof_verified = false;

    assert_eq!(
        accept_verified_plaintext(&store, &decrypt).unwrap_err(),
        PublicAnchorError::ProofNotVerified
    );
}
