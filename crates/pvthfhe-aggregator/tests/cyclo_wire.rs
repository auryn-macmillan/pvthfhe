//! Basic wiring test for the Cyclo folding adapter.

use pvthfhe_aggregator::folding::HashChainCycloAdapter;

#[test]
fn cyclo_wire_backend_id_is_real() {
    let adapter = HashChainCycloAdapter::new();
    assert!(
        adapter.backend_id().contains("cyclo-rlwe"),
        "folding layer must report the real Cyclo backend id"
    );
}
