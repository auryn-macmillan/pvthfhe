use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};
use pvthfhe_compressor::nova::{
    bfv_encryption_circuit::{BFV_L, BFV_Q, BFV_STEP_DATA_LEN, B_U},
    encode_hex, encode_quad, set_bfv_encryption_data, CycloFoldStepCircuit, NovaCompressor,
    SBIND_CYCLO_FOLD,
};
use pvthfhe_compressor::ProofCompressor;

fn build_honest_bfv_data() -> Vec<Vec<Fr>> {
    let mut step = vec![Fr::zero(); BFV_STEP_DATA_LEN];
    for l in 0..BFV_L {
        step[l] = Fr::from(100u64 + l as u64);
    }
    for l in 0..BFV_L {
        step[3 + l] = Fr::from(200u64 + l as u64);
    }
    for l in 0..BFV_L {
        step[6 + l] = Fr::from(10u64);
    }
    for l in 0..BFV_L {
        step[9 + l] = Fr::from(20u64);
    }
    for l in 0..BFV_L {
        step[12 + l] = Fr::from(2u64);
    }
    step[15] = Fr::from(1u64);
    step[16] = Fr::from(2u64);
    step[17] = Fr::from(3u64);
    step[18] = Fr::from(4u64);

    for l in 0..BFV_L {
        let q = Fr::from(BFV_Q[l]);
        let ct0 = Fr::from(10u64) * step[15] + step[16] + step[12 + l] * step[18] + q * Fr::zero();
        let ct1 = Fr::from(20u64) * step[15] + step[17] + q * Fr::zero();
        step[l] = ct0;
        step[3 + l] = ct1;
    }

    for l in 0..BFV_L {
        step[19 + l] = Fr::zero();
        step[22 + l] = Fr::zero();
    }

    let gamma = Fr::from(12345u64);
    let mut g_pow = Fr::one();
    for l in 0..BFV_L {
        step[25 + l] = g_pow;
        g_pow *= gamma;
    }

    vec![step]
}

#[test]
fn honest_bfv_encryption_prove_accepts() {
    let data = build_honest_bfv_data();
    set_bfv_encryption_data(data);

    let compressor =
        NovaCompressor::<CycloFoldStepCircuit<Fr>>::new([0u8; 32], 1, [0u8; 32], SBIND_CYCLO_FOLD)
            .expect("compressor");

    let acc = encode_hex((
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
    ));
    let pi = encode_quad((Fr::zero(), Fr::zero(), Fr::one(), Fr::zero()));

    let result = compressor.prove(&acc, &pi);
    assert!(result.is_ok(), "honest bfv proof must succeed: {result:?}");
}

#[test]
fn tampered_pk0_rejected() {
    let mut data = build_honest_bfv_data();
    data[0][6] = Fr::from(999u64);

    set_bfv_encryption_data(data);

    let compressor =
        NovaCompressor::<CycloFoldStepCircuit<Fr>>::new([0u8; 32], 1, [0u8; 32], SBIND_CYCLO_FOLD)
            .expect("compressor");
    let acc = encode_hex((
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
    ));
    let pi = encode_quad((Fr::zero(), Fr::zero(), Fr::one(), Fr::zero()));

    let proof = compressor.prove(&acc, &pi);
    if proof.is_ok() {
        let vk = compressor.verifier_key();
        let verify_result = compressor.verify(&vk, proof.as_ref().unwrap(), &acc, &pi);
        assert!(
            verify_result.is_err() || verify_result == Ok(false),
            "tampered pk0 must fail verification: {verify_result:?}"
        );
    }
}

#[test]
fn tampered_u_norm_bound_rejected() {
    let mut data = build_honest_bfv_data();
    data[0][15] = Fr::from(B_U + 1);

    set_bfv_encryption_data(data);

    let compressor =
        NovaCompressor::<CycloFoldStepCircuit<Fr>>::new([0u8; 32], 1, [0u8; 32], SBIND_CYCLO_FOLD)
            .expect("compressor");
    let acc = encode_hex((
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
    ));
    let pi = encode_quad((Fr::zero(), Fr::zero(), Fr::one(), Fr::zero()));

    let proof = compressor.prove(&acc, &pi);
    if proof.is_ok() {
        let vk = compressor.verifier_key();
        let verify_result = compressor.verify(&vk, proof.as_ref().unwrap(), &acc, &pi);
        assert!(
            verify_result.is_err() || verify_result == Ok(false),
            "norm bound violation must fail verification: {verify_result:?}"
        );
    }
}

#[test]
fn tampered_ct0_rejected() {
    let mut data = build_honest_bfv_data();
    data[0][0] = Fr::from(777u64);

    set_bfv_encryption_data(data);

    let compressor =
        NovaCompressor::<CycloFoldStepCircuit<Fr>>::new([0u8; 32], 1, [0u8; 32], SBIND_CYCLO_FOLD)
            .expect("compressor");
    let acc = encode_hex((
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
    ));
    let pi = encode_quad((Fr::zero(), Fr::zero(), Fr::one(), Fr::zero()));

    let proof = compressor.prove(&acc, &pi);
    if proof.is_ok() {
        let vk = compressor.verifier_key();
        let verify_result = compressor.verify(&vk, proof.as_ref().unwrap(), &acc, &pi);
        assert!(
            verify_result.is_err() || verify_result == Ok(false),
            "tampered ct0 must fail verification: {verify_result:?}"
        );
    }
}

#[test]
fn empty_data_no_constraint_violation() {
    set_bfv_encryption_data(vec![]);

    let compressor =
        NovaCompressor::<CycloFoldStepCircuit<Fr>>::new([0u8; 32], 1, [0u8; 32], SBIND_CYCLO_FOLD)
            .expect("compressor");
    let acc = encode_hex((
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
    ));
    let pi = encode_quad((Fr::zero(), Fr::zero(), Fr::one(), Fr::zero()));

    let result = compressor.prove(&acc, &pi);
    assert!(
        result.is_ok(),
        "empty bfv data (Track A) must succeed: {result:?}"
    );
}
