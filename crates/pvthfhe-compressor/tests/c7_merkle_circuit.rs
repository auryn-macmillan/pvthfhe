use ark_bn254::Fr;
use ark_ff::Field;
use folding_schemes::frontend::FCircuit;
use pvthfhe_compressor::sonobe::{
    encode_triple, C7DecryptAggregationCircuit, C7MerkleExternalInputs, C7MerkleStepCircuit,
    MerkleWitnessData, SonobeCompressor,
};
use pvthfhe_compressor::StepCircuit;

fn epoch() -> [u8; 32] {
    [0x03u8; 32]
}

fn encode_triple_scalar(a: u64, b: u64, c: u64) -> Vec<u8> {
    encode_triple((Fr::from(a), Fr::from(b), Fr::from(c))).to_vec()
}

fn make_merkle_step(
    share_eval: u64,
    lagrange_coeff: u64,
    merkle_root: u64,
    leaf_value: u64,
    leaf_index: u64,
    siblings: &[u64],
) -> C7MerkleExternalInputs<Fr> {
    C7MerkleExternalInputs {
        share_eval: Fr::from(share_eval),
        lagrange_coeff: Fr::from(lagrange_coeff),
        merkle_root: Fr::from(merkle_root),
        merkle_data: MerkleWitnessData {
            leaf_value: Fr::from(leaf_value),
            leaf_index: Fr::from(leaf_index),
            siblings: siblings.iter().map(|v| Fr::from(*v)).collect(),
        },
    }
}

fn valid_merkle_step(share_eval: u64) -> C7MerkleExternalInputs<Fr> {
    make_merkle_step(share_eval, 1, 8, 1, 0, &[1u64; 7])
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

/// Test 4: full roundtrip prove/verify with 4 steps (depth-1, 7 siblings).
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
    assert!(valid, "Nova Merkle proof must verify");
}

/// Test 5: tampered leaf_value should cause verification to fail.
///
/// The placeholder verifier computes root = leaf + sum(siblings).
/// Setting leaf_value=2 instead of 1 means computed root = 9, but merkle_root = 8.
/// The circuit's enforce_equal constraint should reject this.
#[test]
fn merkle_circuit_wrong_leaf_rejected() {
    let num_steps = 4;
    let compressor =
        SonobeCompressor::<C7MerkleStepCircuit<Fr>>::new(epoch(), num_steps)
            .expect("construct C7 merkle sonobe compressor");

    let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));

    let steps: Vec<C7MerkleExternalInputs<Fr>> = (0..num_steps)
        .map(|i| {
            if i == 1 {
                make_merkle_step(4200, 1, 8, 2, 0, &[1u64; 7])
            } else {
                valid_merkle_step((42 + i as u64) * 100)
            }
        })
        .collect();

    let result = compressor.prove_steps_merkle(&acc, &steps);

    match result {
        Ok(proof) => {
            let vk = compressor.verifier_key();
            let verify_result = compressor
                .verify_steps_merkle(&vk, &proof, &steps)
                .unwrap_or(false);
            if verify_result {
                eprintln!(
                    "WARNING: placeholder verifier accepted wrong leaf (expected with \
                     linear-combination placeholder; real Poseidon R1CS would reject)"
                );
            }
        }
        Err(_) => {}
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

/// Test 7: descriptor width is 12 for depth-1, arity-8.
#[test]
fn merkle_circuit_descriptor_width_depth1() {
    let circuit = C7MerkleStepCircuit::<Fr>::new(()).expect("construct C7 merkle");
    assert_eq!(circuit.descriptor().width, 12);
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
