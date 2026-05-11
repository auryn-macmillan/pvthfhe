//! Banner regression test for the Cyclo backend identifier.

use pvthfhe_cyclo::{adapter::LegacyHashChainAdapter, CycloAdapter};

#[test]
fn backend_id_banner_mentions_lemma9_heuristic() {
    assert!(
        LegacyHashChainAdapter.backend_id().contains("lemma9-heuristic"),
        "backend_id banner must expose the Lemma 9 heuristic assumption"
    );
}
