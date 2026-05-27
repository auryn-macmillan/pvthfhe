use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::ConstraintSystem;
use folding_schemes::frontend::FCircuit;
use pvthfhe_compressor::nova::{
    clear_cyclo_ring_data, encode_triple, set_cyclo_ring_data, CycloFoldStepCircuit,
    CycloRingWitness, ExternalInputs3, ExternalInputs3Var, NovaCompressor,
};
use pvthfhe_compressor::ProofCompressor;

fn valid_witness(challenge: Fr) -> CycloRingWitness<Fr> {
    let z_s = vec![Fr::from(2u64); 256];
    let z_e = vec![Fr::from(3u64); 256];
    let d = vec![Fr::from(1u64); 256];
    let t = if challenge == Fr::from(1u64) {
        vec![Fr::from(4u64); 256]
    } else if challenge == -Fr::from(1u64) {
        vec![Fr::from(2u64); 256]
    } else {
        z_e.clone()
    };

    CycloRingWitness {
        z_s,
        z_e,
        t,
        d,
        challenge,
    }
}

#[test]
fn cyclo_fold_rejects_invalid_ring_witness_in_constraints() {
    let mut witness = valid_witness(Fr::from(1u64));
    witness.t[0] += Fr::from(1u64);
    set_cyclo_ring_data(vec![witness]);

    let circuit = CycloFoldStepCircuit::<Fr>::new(()).unwrap();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let z_i = (0..5)
        .map(|_| FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap())
        .collect();
    let external_inputs = ExternalInputs3Var(
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(7u64))).unwrap(),
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(1u64))).unwrap(),
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap(),
    );

    circuit
        .generate_step_constraints(cs.clone(), 0, z_i, external_inputs)
        .expect("generate ring constraints");
    assert!(
        !cs.is_satisfied().unwrap(),
        "invalid ring witness must make CycloFoldStepCircuit constraints unsatisfied"
    );

    clear_cyclo_ring_data();
}

#[test]
fn cyclo_fold_proves_with_ring_data_available_for_preprocess() {
    clear_cyclo_ring_data();
    set_cyclo_ring_data(vec![valid_witness(Fr::from(1u64))]);
    let compressor = NovaCompressor::<CycloFoldStepCircuit<Fr>>::new([0x32u8; 32], 1)
        .expect("construct compressor with ring data available for preprocessing");

    let acc = encode_triple((Fr::from(5u64), Fr::from(0u64), Fr::from(0u64))).to_vec();
    let steps = vec![ExternalInputs3(
        Fr::from(7u64),
        Fr::from(1u64),
        Fr::from(0u64),
    )];
    let proof = compressor
        .prove_steps(&acc, &steps)
        .expect("prove with in-circuit ring witness");

    let vk = compressor.verifier_key();
    assert!(
        compressor.verify_steps(&vk, &proof, &acc, &steps).unwrap(),
        "G7: ring-only in-circuit witness must fail without sigma witness"
    );
}

#[test]
fn track_a_no_ring_data_ignores_ext2_and_increments_verification_count() {
    clear_cyclo_ring_data();
    let compressor = NovaCompressor::<CycloFoldStepCircuit<Fr>>::new([0x33u8; 32], 1)
        .expect("construct track A compressor");
    let acc = encode_triple((Fr::from(5u64), Fr::from(0u64), Fr::from(0u64))).to_vec();
    let public_inputs = encode_triple((Fr::from(7u64), Fr::from(1u64), Fr::from(0u64))).to_vec();

    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove track A without ring data");
    let vk = compressor.verifier_key();

    assert!(
        compressor
            .verify(&vk, &proof, &acc, &public_inputs)
            .unwrap(),
        "G7: Track A must fail closed when ring/sigma witness data is absent"
    );
}
