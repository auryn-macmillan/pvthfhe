use pvthfhe_aggregator::decrypt::{
    verify_dkg_decryption_anchor_equality, DecryptionFoldPublicAnchors, DkgFoldPublicAnchors,
};

fn digest(tag: u8) -> [u8; 32] {
    [tag; 32]
}

fn dkg_anchors() -> DkgFoldPublicAnchors {
    DkgFoldPublicAnchors {
        dkg_root: digest(1),
        aggregated_pk_commit: digest(2),
        participant_set_hash: digest(3),
        sk_agg_commits_root: digest(4),
        esm_agg_commits_root: digest(5),
        smudge_slot_policy_hash: digest(6),
    }
}

fn decrypt_anchors() -> DecryptionFoldPublicAnchors {
    DecryptionFoldPublicAnchors {
        dkg_root: digest(1),
        ciphertext_hash: digest(7),
        expected_sk_commits_root: digest(4),
        expected_esm_commits_root: digest(5),
        slot_id: 11,
        decrypt_round: 12,
        plaintext_hash: digest(8),
    }
}

#[test]
fn public_anchor_equality_accepts_matching_dkg_decryption_roots() {
    verify_dkg_decryption_anchor_equality(&dkg_anchors(), &decrypt_anchors())
        .expect("matching DKG/decryption anchors must verify");
}

#[test]
fn public_anchor_equality_rejects_dkg_root_mismatch() {
    let dkg = dkg_anchors();
    let mut decrypt = decrypt_anchors();
    decrypt.dkg_root = digest(99);

    assert!(
        verify_dkg_decryption_anchor_equality(&dkg, &decrypt).is_err(),
        "public verifier must reject a decryption folded proof tied to a different DKG root"
    );
}

#[test]
fn public_anchor_equality_rejects_sk_or_esm_root_mismatch() {
    let dkg = dkg_anchors();

    let mut sk_mismatch = decrypt_anchors();
    sk_mismatch.expected_sk_commits_root = digest(88);
    assert!(
        verify_dkg_decryption_anchor_equality(&dkg, &sk_mismatch).is_err(),
        "public verifier must reject an expected sk aggregate root mismatch"
    );

    let mut esm_mismatch = decrypt_anchors();
    esm_mismatch.expected_esm_commits_root = digest(89);
    assert!(
        verify_dkg_decryption_anchor_equality(&dkg, &esm_mismatch).is_err(),
        "public verifier must reject an expected e_sm aggregate root mismatch"
    );
}
