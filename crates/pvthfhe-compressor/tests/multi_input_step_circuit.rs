use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::GR1CSVar;
use ark_relations::gr1cs::ConstraintSystem;
use folding_schemes::frontend::FCircuit;
use pvthfhe_compressor::sonobe::{CycloFoldStepCircuit, ExternalInputs3Var};

#[test]
fn cyclo_fold_accepts_tuple_external_inputs() {
    let circuit = CycloFoldStepCircuit::<Fr>::new(()).unwrap();
    let cs = ConstraintSystem::<Fr>::new_ref();

    let z_i = vec![
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(100u64))).unwrap(),
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(50u64))).unwrap(),
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap(),
    ];

    let external_inputs = ExternalInputs3Var(
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(7u64))).unwrap(),
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(10u64))).unwrap(),
        FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(1u64))).unwrap(),
    );

    let next_state = circuit
        .generate_step_constraints(cs.clone(), 0, z_i, external_inputs)
        .expect("generate step constraints");

    assert_eq!(next_state.len(), 3);

    assert_eq!(next_state[0].value().unwrap(), Fr::from(800u64));
    assert_eq!(next_state[1].value().unwrap(), Fr::from(60u64));
    assert_eq!(next_state[2].value().unwrap(), Fr::from(4u64));
}
