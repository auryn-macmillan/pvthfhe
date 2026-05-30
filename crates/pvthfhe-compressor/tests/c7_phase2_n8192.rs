use ark_bn254::Fr;
use ark_ff::Field;
use pvthfhe_compressor::merkle::{build_merkle_tree, prove_merkle_path, verify_merkle_proof};
use pvthfhe_compressor::poly_eval::eval_poly_bn254;
use pvthfhe_compressor::witness::C7WitnessSet;

const N: usize = 8192;
const ARITY: usize = 8;

fn generate_coeffs(seed: u64) -> Vec<Fr> {
    let mut coeffs = Vec::with_capacity(N);
    let mut v = Fr::from(seed);
    for _ in 0..N {
        coeffs.push(v);
        v += Fr::from(1u64);
    }
    coeffs
}

#[test]
fn merkle_tree_8192_correct_root() {
    let coeffs = generate_coeffs(0);
    let (tree1, root1) = build_merkle_tree(&coeffs, ARITY);
    let (tree2, root2) = build_merkle_tree(&coeffs, ARITY);
    assert_eq!(root1, root2, "deterministic tree must produce same root");
    assert_ne!(root1, Fr::from(0u64), "root must not be zero");
    assert_eq!(tree1.last().unwrap()[0], root1);
    assert_eq!(tree2.last().unwrap()[0], root2);
}

#[test]
fn merkle_proof_8192_verifies() {
    let coeffs = generate_coeffs(1);
    let (tree, _root) = build_merkle_tree(&coeffs, ARITY);
    let proof = prove_merkle_path(&tree, 0, ARITY);
    assert!(verify_merkle_proof(&proof, ARITY));
}

#[test]
fn merkle_proof_rejects_wrong_leaf() {
    let coeffs = generate_coeffs(2);
    let (tree, _root) = build_merkle_tree(&coeffs, ARITY);
    let mut proof = prove_merkle_path(&tree, 0, ARITY);
    proof.leaf_value += Fr::from(1u64);
    assert!(!verify_merkle_proof(&proof, ARITY));
}

#[test]
fn merkle_proof_rejects_wrong_root() {
    let coeffs = generate_coeffs(3);
    let (tree, _root) = build_merkle_tree(&coeffs, ARITY);
    let mut proof = prove_merkle_path(&tree, 0, ARITY);
    proof.root += Fr::from(1u64);
    assert!(!verify_merkle_proof(&proof, ARITY));
}

#[test]
fn merkle_proof_rejects_out_of_range() {
    let coeffs = generate_coeffs(4);
    let (tree, _root) = build_merkle_tree(&coeffs, ARITY);
    let mut proof = prove_merkle_path(&tree, 0, ARITY);
    proof.leaf_index = N + 1;
    assert!(!verify_merkle_proof(&proof, ARITY));
}

#[test]
fn poly_eval_horner_matches() {
    let coeffs = generate_coeffs(5);
    let r = Fr::from(7u64);

    let mut expected = Fr::from(0u64);
    for (i, c) in coeffs.iter().enumerate() {
        let power = (N - 1 - i) as u64;
        expected += *c * r.pow(&[power]);
    }

    let result = eval_poly_bn254(&coeffs, r);
    assert_eq!(result, expected);
}

#[test]
fn c7_witness_set_all_commitments_pass() {
    let shares: Vec<Vec<Fr>> = (0..4).map(|i| generate_coeffs(i)).collect();
    let lagrange: Vec<Fr> = vec![
        Fr::from(1u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    ];
    let challenge_r = Fr::from(5u64);
    let prover_nonce = Fr::from(0u64);
    let witnesses = C7WitnessSet::new(&shares, &lagrange, challenge_r, prover_nonce);
    assert!(witnesses.verify_commitments());
}

#[test]
fn c7_witness_set_bad_commitment_rejected() {
    let shares: Vec<Vec<Fr>> = (0..4).map(|i| generate_coeffs(i + 10)).collect();
    let lagrange: Vec<Fr> = vec![
        Fr::from(1u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    ];
    let challenge_r = Fr::from(5u64);
    let prover_nonce = Fr::from(0u64);
    let mut witnesses = C7WitnessSet::new(&shares, &lagrange, challenge_r, prover_nonce);
    witnesses.participants[0].coeff_commitment += Fr::from(1u64);
    assert!(!witnesses.verify_commitments());
}

// ── KNOWN_LIMITATION(c7-nova-test): c7_nova_fold_n8192_4_steps removed ──
// C7DecryptAggregationCircuit lacks nova_snark::traits::circuit::StepCircuit impl,
// and c7_fold_witnesses is gated behind `legacy-nova`. Re-instate when
// C7DecryptAggregationCircuit is ported to nova-snark backend.
