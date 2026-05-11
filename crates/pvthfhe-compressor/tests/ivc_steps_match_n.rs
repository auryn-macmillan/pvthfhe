//! R5.2 RED: IVC_STEPS is a runtime parameter, not a constant 4.
//!
//! This test must FAIL (compile error) against current main because
//! `SonobeCompressor::new` does not accept an `ivc_steps` parameter.

use pvthfhe_compressor::sonobe::SonobeCompressor;
use pvthfhe_compressor::ProofCompressor;
use pvthfhe_compressor::sonobe::ToyStepCircuit;
use ark_bn254::Fr;

#[test]
fn ivc_steps_is_runtime_not_constant_four() {
    let epoch_hash = [0x42u8; 32];

    // RED: `new` does not accept `ivc_steps` on main.
    let compressor =
        SonobeCompressor::<ToyStepCircuit<Fr>>::new(epoch_hash, 8)
            .expect("construct compressor with ivc_steps=8");

    let acc = [0u8; 32];
    let pi = [0u8; 32];
    let proof = compressor.prove(&acc, &pi).expect("prove");
    let vk = compressor.verifier_key();
    assert!(compressor.verify(&vk, &proof, &pi).expect("verify"));

    // Verify that compressor stores the ivc_steps parameter.
    assert_eq!(compressor.ivc_steps(), 8, "ivc_steps must be stored and retrievable");
}

#[test]
fn ivc_steps_matches_number_of_parties() {
    let epoch_hash = [0u8; 32];

    // RED: `new` does not accept `ivc_steps` on main.
    let n_parties = 16;
    let compressor =
        SonobeCompressor::<ToyStepCircuit<Fr>>::new(epoch_hash, n_parties)
            .expect("construct compressor");

    assert_eq!(
        compressor.ivc_steps(), n_parties,
        "IVC_STEPS ({}) must match n ({})",
        compressor.ivc_steps(), n_parties,
    );
}
