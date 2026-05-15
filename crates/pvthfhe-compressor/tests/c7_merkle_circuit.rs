use ark_bn254::Fr;
use ark_ff::Field;
use folding_schemes::frontend::FCircuit;
use pvthfhe_compressor::sonobe::{
    encode_triple, hash8_native, C7DecryptAggregationCircuit, C7MerkleExternalInputs,
    C7MerkleStepCircuit, MerkleWitnessData, SonobeCompressor,
};
use pvthfhe_compressor::StepCircuit;

fn epoch() -> [u8; 32] {
    [0x03u8; 32]
}

fn make_merkle_step(
    share_eval: Fr,
    lagrange_coeff: Fr,
    merkle_root: Fr,
    leaf_value: Fr,
    leaf_index: Fr,
    siblings: &[Fr],
) -> C7MerkleExternalInputs<Fr> {
    C7MerkleExternalInputs {
        share_eval,
        lagrange_coeff,
        merkle_root,
        merkle_data: MerkleWitnessData {
            leaf_value,
            leaf_index,
            siblings: siblings.to_vec(),
        },
    }
}

/// Compute a valid Merkle root via Poseidon for depth-5 arity-8.
/// Walks 5 levels: for each level, hash current with 7 siblings.
fn poseidon_merkle_root(leaf: Fr, all_siblings: &[Fr; 35]) -> Fr {
    let mut current = leaf;
    for level in 0..5 {
        let start = level * 7;
        let level_siblings = &all_siblings[start..start + 7];
        let mut inputs = vec![current];
        inputs.extend_from_slice(level_siblings);
        current = hash8_native(&inputs);
    }
    current
}

/// Create a valid Merkle step for testing. Uses real Poseidon hashes with depth-5.
fn valid_merkle_step(share_eval: u64) -> C7MerkleExternalInputs<Fr> {
    let leaf = Fr::from(1u64);
    let siblings = [Fr::from(1u64); 35];
    let root = poseidon_merkle_root(leaf, &siblings);
    make_merkle_step(
        Fr::from(share_eval),
        Fr::from(1u64),
        root,
        leaf,
        Fr::from(0u64),
        &siblings,
    )
}

/// Test 1: C7 Merkle step circuit compiles with Sonobe.
#[test]
fn merkle_circuit_compiles() {
    let compressor = SonobeCompressor::<C7MerkleStepCircuit<Fr>>::new(epoch(), 4)
        .expect("construct C7 merkle sonobe compressor");
    let vk = compressor.verifier_key();
    assert_eq!(vk.backend_id, "sonobe-nova-bn254-grumpkin");
}

/// Test 2: state_len is 3.
#[test]
fn merkle_circuit_state_len_three() {
    let circuit = C7MerkleStepCircuit::<Fr>::new(()).expect("construct C7 merkle circuit");
    assert_eq!(circuit.state_len(), 3);
}

/// Test 3: circuit_hash is deterministic.
#[test]
fn merkle_circuit_hash_deterministic() {
    let circuit_a = C7MerkleStepCircuit::<Fr>::new(()).expect("construct C7 merkle a");
    let circuit_b = C7MerkleStepCircuit::<Fr>::new(()).expect("construct C7 merkle b");
    assert_eq!(circuit_a.circuit_hash(), circuit_b.circuit_hash());
}

/// Test 4: full roundtrip prove/verify with 4 steps (depth-5, 35 siblings).
#[test]
fn merkle_circuit_roundtrip() {
    let num_steps = 4;
    let compressor =
        SonobeCompressor::<C7MerkleStepCircuit<Fr>>::new(epoch(), num_steps)
            .expect("construct C7 merkle sonobe compressor");

    let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));

    let steps: Vec<C7MerkleExternalInputs<Fr>> = (0..num_steps)
        .map(|i| valid_merkle_step((42 + i as u64) * 100))
        .collect();

    let proof = compressor
        .prove_steps_merkle(&acc, &steps)
        .expect("prove_steps_merkle");

    let vk = compressor.verifier_key();

    let valid = compressor
        .verify_steps_merkle(&vk, &proof, &steps)
        .expect("verify_steps_merkle");
    assert!(valid, "Nova Merkle proof must verify with real Poseidon");
}

/// Test 5: tampered leaf_value MUST be rejected by proof verification.
///
/// With real Poseidon, a wrong leaf_value produces a different hash than
/// the provided merkle_root. The proof must either fail to produce or fail
/// to verify.
#[test]
fn merkle_circuit_wrong_leaf_rejected() {
    let num_steps = 4;
    let compressor =
        SonobeCompressor::<C7MerkleStepCircuit<Fr>>::new(epoch(), num_steps)
            .expect("construct C7 merkle sonobe compressor");

    let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));

    let step0 = valid_merkle_step(4200);
    let leaf_wrong = Fr::from(9999u64);
    let siblings = [Fr::from(1u64); 35];
    let root_correct = poseidon_merkle_root(Fr::from(1u64), &siblings);
    let step1 = make_merkle_step(
        Fr::from(4200u64),
        Fr::from(1u64),
        root_correct, // correct root for leaf=1, but leaf is 9999
        leaf_wrong,
        Fr::from(0u64),
        &siblings,
    );
    let step2 = valid_merkle_step(4400);
    let step3 = valid_merkle_step(4500);

    let steps = vec![step0, step1, step2, step3];

    let result = compressor.prove_steps_merkle(&acc, &steps);

    match result {
        // If prove succeeds (Nova may fold unsatisfied constraints),
        // verification must reject the proof.
        Ok(proof) => {
            let vk = compressor.verifier_key();
            let valid = compressor
                .verify_steps_merkle(&vk, &proof, &steps)
                .expect("verify_steps_merkle");
            assert!(
                !valid,
                "Nova verification MUST reject tampered leaf with real Poseidon"
            );
        }
        // If prove fails, that's also acceptable.
        Err(_) => {
            // prove_step rejected the unsatisfiable constraints — correct behavior.
        }
    }
}

/// Test 6: circuit_hash differs from C7DecryptAggregationCircuit.
#[test]
fn merkle_circuit_differs_from_c7_basic() {
    let merkle = C7MerkleStepCircuit::<Fr>::new(()).expect("construct C7 merkle");
    let basic =
        C7DecryptAggregationCircuit::<Fr>::new(()).expect("construct C7 basic");
    assert_ne!(
        merkle.circuit_hash(),
        basic.circuit_hash(),
        "C7 Merkle circuit hash must differ from basic C7 circuit hash"
    );
}

/// Test 7: descriptor width is 40 for depth-5, arity-8.
#[test]
fn merkle_circuit_descriptor_width_depth5() {
    let circuit = C7MerkleStepCircuit::<Fr>::new(()).expect("construct C7 merkle");
    assert_eq!(circuit.descriptor().width, 40);
}

/// Test 8: circuit with custom depth/arity computes correct width.
#[test]
fn merkle_circuit_custom_depth_descriptor() {
    let circuit = C7MerkleStepCircuit::<Fr>::new_with_depth(5, 8)
        .expect("construct depth-5 merkle");
    assert_eq!(circuit.descriptor().width, 40);
    assert_eq!(circuit.merkle_depth, 5);
    assert_eq!(circuit.merkle_arity, 8);
}

/// Test 9: non-zero merkle_leaf_index MUST be rejected.
///
/// The in-circuit Merkle verification currently only supports position 0
/// (current node always placed first in the sibling list). A non-zero
/// leaf_index violates the constraint `leaf_index == 0` enforced in
/// both `verify_merkle_path` and `generate_step_constraints`.
/// Full position-aware ordering is deferred (see c7_merkle_circuit.rs docs).
#[test]
fn merkle_leaf_index_constraint_enforced() {
    let num_steps = 4;
    let compressor = SonobeCompressor::<C7MerkleStepCircuit<Fr>>::new(epoch(), num_steps)
        .expect("construct C7 merkle sonobe compressor");

    let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));

    // Build a step with non-zero leaf_index.
    let leaf = Fr::from(1u64);
    let siblings = [Fr::from(1u64); 35];
    let root = poseidon_merkle_root(leaf, &siblings);
    let bad_step = make_merkle_step(
        Fr::from(4200u64),
        Fr::from(1u64),
        root,
        leaf,
        Fr::from(5u64), // non-zero leaf_index — must be rejected
        &siblings,
    );

    let mut steps = vec![bad_step];
    for i in 1..num_steps {
        steps.push(valid_merkle_step((42 + i as u64) * 100));
    }

    let result = compressor.prove_steps_merkle(&acc, &steps);

    match result {
        // If prove succeeds (Nova may fold unsatisfied constraints),
        // verification must reject the proof.
        Ok(proof) => {
            let vk = compressor.verifier_key();
            let valid = compressor
                .verify_steps_merkle(&vk, &proof, &steps)
                .expect("verify_steps_merkle");
            assert!(
                !valid,
                "Nova verification MUST reject non-zero leaf_index"
            );
        }
        // If prove fails, that's also acceptable — constraint rejected by prover.
        Err(_) => {
            // prove_step rejected the unsatisfiable constraint — correct behavior.
        }
    }
}
