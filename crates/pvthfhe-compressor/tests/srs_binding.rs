//! R5.3: SRS is bound to on-chain epoch, not a seed: u64.

use ark_bn254::Fr;
use pvthfhe_compressor::nova::DkgAggregationStepCircuit;
use pvthfhe_compressor::nova::NovaCompressor;
use pvthfhe_compressor::nova::SBIND_DKG_AGGREGATION;

fn sid() -> [u8; 32] {
    [0u8; 32]
}

#[test]
fn srs_is_derived_from_epoch_hash_not_seed() {
    let epoch_a: [u8; 32] = [0xA0u8; 32];
    let epoch_b: [u8; 32] = [0xB0u8; 32];

    let comp_a = NovaCompressor::<DkgAggregationStepCircuit<Fr>>::new(
        epoch_a,
        4,
        sid(),
        SBIND_DKG_AGGREGATION,
    )
    .expect("construct compressor with epoch_a");
    let comp_b = NovaCompressor::<DkgAggregationStepCircuit<Fr>>::new(
        epoch_b,
        4,
        sid(),
        SBIND_DKG_AGGREGATION,
    )
    .expect("construct compressor with epoch_b");

    // Different epochs must produce different SRS hashes.
    assert_ne!(
        comp_a.srs_hash(),
        comp_b.srs_hash(),
        "Different epochs must produce different SRS"
    );

    // Same epoch must produce identical SRS hashes (deterministic SRS).
    let comp_a2 = NovaCompressor::<DkgAggregationStepCircuit<Fr>>::new(
        epoch_a,
        4,
        sid(),
        SBIND_DKG_AGGREGATION,
    )
    .expect("construct second compressor with epoch_a");
    assert_eq!(
        comp_a.srs_hash(),
        comp_a2.srs_hash(),
        "Same epoch must produce identical SRS"
    );
}
