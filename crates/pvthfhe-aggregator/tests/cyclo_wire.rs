use pvthfhe_aggregator::folding::CycloFoldingAdapter;

#[test]
fn cyclo_wire_backend_id_is_real() {
    let adapter = CycloFoldingAdapter::new();
    assert_eq!(
        adapter.backend_id(),
        "cyclo-rlwe-t10",
        "folding layer must report the real Cyclo backend id"
    );
}
