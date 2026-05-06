use pvthfhe_aggregator::Aggregator;

#[test]
fn default_folding_is_cyclo() {
    let aggregator = Aggregator::default();
    assert_eq!(
        aggregator.folding_backend_id,
        "cyclo-rlwe-t10-lemma9-heuristic"
    );
}
