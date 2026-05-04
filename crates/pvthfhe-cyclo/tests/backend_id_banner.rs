use pvthfhe_cyclo::{adapter::StubCycloAdapter, CycloAdapter};

#[test]
fn backend_id_banner_mentions_lemma9_heuristic() {
    assert!(
        StubCycloAdapter.backend_id().contains("lemma9-heuristic"),
        "backend_id banner must expose the Lemma 9 heuristic assumption"
    );
}
