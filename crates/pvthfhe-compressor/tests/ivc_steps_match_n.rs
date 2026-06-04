//! R5.2: IVC_STEPS is a runtime parameter, not a constant 4.

use ark_bn254::Fr;
use pvthfhe_compressor::nova::{
    encode_triple, DkgAggregationStepCircuit, ExternalInputs3, NovaCompressor,
    SBIND_DKG_AGGREGATION,
};
use sha2::{Digest, Sha256};

fn sid() -> [u8; 32] {
    [0u8; 32]
}

#[test]
fn ivc_steps_is_runtime_not_constant_four() {
    let epoch_hash = [0x42u8; 32];

    let compressor = NovaCompressor::<DkgAggregationStepCircuit<Fr>>::new(
        epoch_hash,
        8,
        sid(),
        SBIND_DKG_AGGREGATION,
    )
    .expect("construct compressor with ivc_steps=8");

    let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));
    let steps = vec![
        pvthfhe_compressor::nova::ExternalInputs3(
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64)
        );
        8
    ];
    let proof = compressor.prove_steps(&acc, &steps).expect("prove_steps");
    let vk = compressor.verifier_key();
    assert!(compressor
        .verify_steps(&vk, &proof, &acc, &steps)
        .expect("verify_steps"));

    assert_eq!(
        compressor.ivc_steps(),
        8,
        "ivc_steps must be stored and retrievable"
    );
}

#[test]
fn ivc_steps_matches_number_of_parties() {
    const SEED: u64 = 0x6976635f73746570;
    let seed_bytes = SEED.to_be_bytes();
    let epoch_hash: [u8; 32] = Sha256::digest(&seed_bytes).into();

    let n_parties = 16;
    let compressor = NovaCompressor::<DkgAggregationStepCircuit<Fr>>::new(
        epoch_hash,
        n_parties,
        sid(),
        SBIND_DKG_AGGREGATION,
    )
    .expect("construct compressor");

    assert_eq!(
        compressor.ivc_steps(),
        n_parties,
        "IVC_STEPS ({}) must match n ({})",
        compressor.ivc_steps(),
        n_parties,
    );
}
