//! M1: Merkle tree domain separation tests.
//!
//! Verifies that leaf-level hashing and internal-node hashing use distinct
//! domain tags (Fr::zero() vs Fr::one()) to prevent second-preimage attacks.

use ark_bn254::Fr;
use ark_ff::{One, Zero};
use pvthfhe_compressor::merkle::{build_merkle_tree, prove_merkle_path, verify_merkle_proof};
use pvthfhe_compressor::nova::hash8_native;

#[test]
fn domain_bit_changes_hash() {
    // Same 8 inputs with different domain bits must produce different hashes.
    let children: Vec<Fr> = (0..8).map(|i| Fr::from(i as u64)).collect();

    let mut leaf_inputs = vec![Fr::zero()];
    leaf_inputs.extend_from_slice(&children);
    let leaf_hash = hash8_native(&leaf_inputs);

    let mut internal_inputs = vec![Fr::one()];
    internal_inputs.extend_from_slice(&children);
    let internal_hash = hash8_native(&internal_inputs);

    assert_ne!(
        leaf_hash, internal_hash,
        "M1 FAIL: domain bit=0 and domain bit=1 produced the same hash for identical children. Domain separation is not working."
    );
}

#[test]
fn leaf_internal_domain_separation_in_tree() {
    // Build a 2-level 8-ary tree (8 leaves -> 1 root).
    // Verify that:
    // 1. The root is computed with domain=0 (leaf-hash) since there are only 8 leaves.
    // 2. Proof verification uses the correct domain bit at each level.

    let leaves: Vec<Fr> = (0..8).map(|i| Fr::from(i as u64 + 100)).collect();
    let arity = 8usize;

    let (tree, root) = build_merkle_tree(&leaves, arity);

    // Build expected leaf hash: hash8_native([0, leaf0..leaf7])
    let mut expected_inputs = vec![Fr::zero()];
    expected_inputs.extend_from_slice(&leaves);
    let expected_root = hash8_native(&expected_inputs);

    assert_eq!(
        root, expected_root,
        "single-level root must be leaf-hash with domain=0"
    );

    // Verify the proof works with domain separation baked in
    let proof = prove_merkle_path(&tree, 0, arity);
    assert!(
        verify_merkle_proof(&proof, arity),
        "proof must verify with domain separation"
    );
}

#[test]
fn leaf_hash_never_equals_internal_hash() {
    // Second-preimage resistance: a leaf hash (domain=0) must never
    // equal an internal hash (domain=1), even with identical children.
    // An attacker cannot craft a leaf value that looks like an internal node.

    let children: Vec<Fr> = (0..8).map(|i| Fr::from(i as u64 + 42)).collect();

    // Hash as if these are leaves: domain=0
    let mut leaf_inputs = vec![Fr::zero()];
    leaf_inputs.extend_from_slice(&children);
    let leaf_hash = hash8_native(&leaf_inputs);

    // Hash as if these are internal children: domain=1
    let mut internal_inputs = vec![Fr::one()];
    internal_inputs.extend_from_slice(&children);
    let internal_hash = hash8_native(&internal_inputs);

    assert_ne!(
        leaf_hash, internal_hash,
        "M1 FAIL: second-preimage resistance broken — leaf hash collides with internal hash"
    );
}

#[test]
fn two_level_tree_domain_separation() {
    // Build a 2-level tree with 64 leaves (64 -> 8 -> 1).
    // Level 1 nodes use domain=0 (leaf hash).
    // Level 2 root uses domain=1 (internal hash).

    let leaves: Vec<Fr> = (0..64).map(|i| Fr::from(i as u64 + 1000)).collect();
    let arity = 8usize;

    let (tree, root) = build_merkle_tree(&leaves, arity);

    // Manually compute level 1 nodes (domain=0)
    let mut level1 = Vec::new();
    for chunk in leaves.chunks(arity) {
        let mut inputs = vec![Fr::zero()];
        inputs.extend_from_slice(chunk);
        level1.push(hash8_native(&inputs));
    }

    // Manually compute root from level 1 (domain=1)
    let mut root_inputs = vec![Fr::one()];
    root_inputs.extend_from_slice(&level1);
    let expected_root = hash8_native(&root_inputs);

    assert_eq!(
        root, expected_root,
        "2-level tree root must match domain-separated hashing"
    );

    // Verify proof for leaf 0
    let proof = prove_merkle_path(&tree, 0, arity);
    assert!(
        verify_merkle_proof(&proof, arity),
        "two-level proof must verify"
    );

    // Verify proof for leaf 8 (first leaf in second chunk)
    let proof2 = prove_merkle_path(&tree, 8, arity);
    assert!(
        verify_merkle_proof(&proof2, arity),
        "proof for leaf 8 must verify"
    );
}

#[test]
fn existing_merkle_tests_still_pass() {
    // Sanity: the basic hash determinism and tree construction
    // from the inline tests in merkle.rs still hold.
    let inputs: Vec<Fr> = (0..8).map(|i| Fr::from(i as u64)).collect();
    // Determinism check (with domain=1 since we're testing internal usage)
    let mut with_domain = vec![Fr::one()];
    with_domain.extend_from_slice(&inputs);
    assert_eq!(hash8_native(&with_domain), hash8_native(&with_domain));

    // Different inputs produce different hashes
    let mut a = with_domain.clone();
    a[8] = Fr::from(99u64);
    assert_ne!(hash8_native(&with_domain), hash8_native(&a));

    // Tree with 16 leaves produces non-zero root
    let leaves: Vec<Fr> = (0..16).map(|i| Fr::from(i as u64)).collect();
    let (_tree, root) = build_merkle_tree(&leaves, 8);
    assert_ne!(root, Fr::from(0u64));
}
