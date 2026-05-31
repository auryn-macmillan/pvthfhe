use ark_bn254::Fr;
use ark_ff::UniformRand;
use pvthfhe_compressor::merkle::{build_merkle_tree, prove_merkle_path, verify_merkle_proof};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[test]
fn fabricated_merkle_path_rejected() {
    let arity = 8;

    for trial in 0..100 {
        let mut rng = ChaCha20Rng::seed_from_u64(0x60010000 + trial as u64);

        let leaves: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
        let (tree, _root) = build_merkle_tree(&leaves, arity);

        let proof = prove_merkle_path(&tree, 0, arity);
        assert!(
            verify_merkle_proof(&proof, arity),
            "valid proof must verify"
        );

        let mut fake_proof = proof.clone();
        if let Some(first_sibling_group) = fake_proof.siblings.first_mut() {
            if !first_sibling_group.is_empty() {
                first_sibling_group[0] = Fr::rand(&mut rng);
            }
        }

        assert!(
            !verify_merkle_proof(&fake_proof, arity),
            "fabricated Merkle proof trial {trial}: must not verify"
        );
    }
}

#[test]
fn wrong_merkle_root_rejected() {
    let arity = 8;

    for trial in 0..100 {
        let mut rng = ChaCha20Rng::seed_from_u64(0x60020000 + trial as u64);

        let leaves: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
        let (tree, _root) = build_merkle_tree(&leaves, arity);

        let mut proof = prove_merkle_path(&tree, 0, arity);
        assert!(
            verify_merkle_proof(&proof, arity),
            "valid proof must verify"
        );

        proof.root = Fr::rand(&mut rng);
        assert!(
            !verify_merkle_proof(&proof, arity),
            "wrong Merkle root trial {trial}: must not verify"
        );
    }
}

#[test]
fn merkle_leaf_index_out_of_bounds_should_panic() {
    let arity = 8;
    let mut rng = ChaCha20Rng::seed_from_u64(0x60030000);
    let leaves: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
    let (tree, _) = build_merkle_tree(&leaves, arity);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prove_merkle_path(&tree, 99, arity);
    }));
    assert!(
        result.is_err(),
        "out-of-bounds Merkle leaf index must cause panic (or be rejected)"
    );
}
