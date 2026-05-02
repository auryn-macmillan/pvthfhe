#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use pvthfhe_keygen_spec::{
    BFVPublicKey, BfvPublicKeyDerivation, BlameProof, BlameProofSpec, KeygenSession,
    KeygenSessionSpec, PublicVerificationArtifact, PublicVerificationArtifactSpec, Share,
    ShareSpec,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct KatVector {
    schema: String,
    session: KeygenSession,
    shares: Vec<Share>,
    artifact: PublicVerificationArtifact,
    blame_proof: BlameProof,
    derived_public_key: BFVPublicKey,
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(".sisyphus")
        .join("design")
        .join("p4")
        .join("kat")
}

fn roundtrip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let json = serde_json::to_string_pretty(value).expect("serialize roundtrip value");
    serde_json::from_str(&json).expect("deserialize roundtrip value")
}

#[test]
fn kat_vectors_roundtrip_and_derive_bfv_key() {
    let dir = vectors_dir();
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("cannot read vectors dir {:?}: {}", dir, error))
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .map(|ext| ext == "json")
                .unwrap_or(false)
        })
        .collect();
    entries.sort_by_key(|entry| entry.path());

    assert!(
        !entries.is_empty(),
        "no JSON KAT vectors found in {:?}",
        dir
    );

    for entry in entries {
        let path = entry.path();
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {:?}: {}", path, error));
        let vector: KatVector = serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("cannot parse {:?}: {}", path, error));

        assert_eq!(
            vector.schema, "pvthfhe-p4-kat-v1",
            "{:?}: unexpected schema",
            path
        );

        let session_from_trait = KeygenSession::from_wire_json(
            &vector.session.to_wire_json().expect("session to wire json"),
        )
        .expect("session from wire json");
        assert_eq!(
            session_from_trait, vector.session,
            "{:?}: session trait roundtrip",
            path
        );
        assert_eq!(
            roundtrip(&vector.session),
            vector.session,
            "{:?}: session serde roundtrip",
            path
        );

        for share in &vector.shares {
            let from_trait =
                Share::from_wire_json(&share.to_wire_json().expect("share to wire json"))
                    .expect("share from wire json");
            assert_eq!(from_trait, *share, "{:?}: share trait roundtrip", path);
            assert_eq!(
                roundtrip(share),
                *share,
                "{:?}: share serde roundtrip",
                path
            );
        }

        let artifact_from_trait = PublicVerificationArtifact::from_wire_json(
            &vector
                .artifact
                .to_wire_json()
                .expect("artifact to wire json"),
        )
        .expect("artifact from wire json");
        assert_eq!(
            artifact_from_trait, vector.artifact,
            "{:?}: artifact trait roundtrip",
            path
        );
        assert_eq!(
            roundtrip(&vector.artifact),
            vector.artifact,
            "{:?}: artifact serde roundtrip",
            path
        );

        let blame_from_trait = BlameProof::from_wire_json(
            &vector
                .blame_proof
                .to_wire_json()
                .expect("blame to wire json"),
        )
        .expect("blame from wire json");
        assert_eq!(
            blame_from_trait, vector.blame_proof,
            "{:?}: blame trait roundtrip",
            path
        );
        assert_eq!(
            roundtrip(&vector.blame_proof),
            vector.blame_proof,
            "{:?}: blame serde roundtrip",
            path
        );

        let derived = vector
            .artifact
            .derive_bfv_public_key(&vector.session, &vector.shares)
            .expect("derive BFV public key");
        assert_eq!(
            derived, vector.derived_public_key,
            "{:?}: derived BFV public key mismatch",
            path
        );
        assert_eq!(
            roundtrip(&derived),
            vector.derived_public_key,
            "{:?}: bfv key serde roundtrip",
            path
        );
    }
}
