use pvthfhe_compressor::{
    verify_compressed_public_anchors, CompressedDecryptionPublicAnchors, CompressedDkgPublicAnchors,
};

fn digest(tag: u8) -> [u8; 32] {
    [tag; 32]
}

fn dkg_anchors() -> CompressedDkgPublicAnchors {
    CompressedDkgPublicAnchors {
        dkg_root: digest(1),
        aggregated_pk_commit: digest(2),
        participant_set_hash: digest(3),
        sk_agg_commits_root: digest(4),
        esm_agg_commits_root: digest(5),
        smudge_slot_policy_hash: digest(6),
    }
}

fn decrypt_anchors() -> CompressedDecryptionPublicAnchors {
    CompressedDecryptionPublicAnchors {
        dkg_root: digest(1),
        ciphertext_hash: digest(7),
        expected_sk_commits_root: digest(4),
        expected_esm_commits_root: digest(5),
        slot_id: 21,
        decrypt_round: 22,
        plaintext_hash: digest(8),
    }
}

#[test]
fn compressed_public_anchors_surface_all_h1_fields() {
    let dkg = dkg_anchors();
    let decrypt = decrypt_anchors();

    assert_eq!(dkg.dkg_root, decrypt.dkg_root);
    assert_eq!(dkg.sk_agg_commits_root, decrypt.expected_sk_commits_root);
    assert_eq!(dkg.esm_agg_commits_root, decrypt.expected_esm_commits_root);
    assert_eq!(dkg.aggregated_pk_commit, digest(2));
    assert_eq!(dkg.participant_set_hash, digest(3));
    assert_eq!(dkg.smudge_slot_policy_hash, digest(6));
    assert_eq!(decrypt.ciphertext_hash, digest(7));
    assert_eq!(decrypt.slot_id, 21);
    assert_eq!(decrypt.decrypt_round, 22);
    assert_eq!(decrypt.plaintext_hash, digest(8));
}

#[test]
fn compressed_public_anchor_equality_rejects_mismatches() {
    let dkg = dkg_anchors();
    verify_compressed_public_anchors(&dkg, &decrypt_anchors())
        .expect("matching compressed public anchors must verify");

    let mut dkg_root_mismatch = decrypt_anchors();
    dkg_root_mismatch.dkg_root = digest(90);
    assert!(verify_compressed_public_anchors(&dkg, &dkg_root_mismatch).is_err());

    let mut sk_mismatch = decrypt_anchors();
    sk_mismatch.expected_sk_commits_root = digest(91);
    assert!(verify_compressed_public_anchors(&dkg, &sk_mismatch).is_err());

    let mut esm_mismatch = decrypt_anchors();
    esm_mismatch.expected_esm_commits_root = digest(92);
    assert!(verify_compressed_public_anchors(&dkg, &esm_mismatch).is_err());
}
