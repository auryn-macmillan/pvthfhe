use ark_bn254::Fr;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use sha3::{Digest, Keccak256};

/// Poseidon-8 native hash replacement (Track A: Nova removed).
///
/// Uses Keccak256 with domain separation instead of the original
/// BN254 Poseidon permutation. Merkle tree commitments remain
/// deterministic and collision-resistant.
fn hash8_native(values: &[Fr]) -> Fr {
    let mut hasher = Keccak256::new();
    hasher.update(b"poseidon-8-keccak-replacement-v1");
    for value in values {
        let bytes = value.into_bigint().to_bytes_be();
        hasher.update(&bytes);
    }
    Fr::from_be_bytes_mod_order(&hasher.finalize())
}

/// A Merkle proof for a single leaf in an 8-ary tree.
#[derive(Clone, Debug)]
pub struct MerkleProof {
    /// Index of the leaf in the tree (0-based).
    pub leaf_index: usize,
    /// The value at the leaf.
    pub leaf_value: Fr,
    /// Sibling nodes at each level. `siblings[level][j]` gives the j-th sibling.
    pub siblings: Vec<Vec<Fr>>,
    /// The Merkle root.
    pub root: Fr,
}

fn hash8_with_domain(values: &[Fr], domain: Fr) -> Fr {
    let mut inputs = vec![domain];
    inputs.extend_from_slice(values);
    hash8_native(&inputs)
}

/// Build an 8-ary Merkle tree over the given leaves.
pub fn build_merkle_tree(leaves: &[Fr], arity: usize) -> (Vec<Vec<Fr>>, Fr) {
    assert!(arity > 0);
    assert!(!leaves.is_empty());

    let mut levels: Vec<Vec<Fr>> = vec![leaves.to_vec()];

    while levels.last().unwrap().len() > 1 {
        let current = levels.last().unwrap();
        let mut next = Vec::new();
        let domain = if levels.len() == 1 {
            Fr::zero()
        } else {
            Fr::one()
        };

        for chunk in current.chunks(arity) {
            let mut inputs = vec![Fr::from(0u64); arity];
            for (i, val) in chunk.iter().enumerate() {
                inputs[i] = *val;
            }
            next.push(hash8_with_domain(&inputs, domain));
        }
        levels.push(next);
    }

    let root = levels.last().unwrap()[0];
    (levels, root)
}

/// Generate a Merkle proof for a leaf at the given index.
pub fn prove_merkle_path(tree: &[Vec<Fr>], leaf_index: usize, arity: usize) -> MerkleProof {
    assert!(!tree.is_empty());
    assert!(leaf_index < tree[0].len());

    let leaf_value = tree[0][leaf_index];
    let root = tree.last().unwrap()[0];

    let mut siblings: Vec<Vec<Fr>> = Vec::new();
    let mut idx = leaf_index;

    for level in 0..tree.len() - 1 {
        let level_nodes = &tree[level];
        let sibling_start = (idx / arity) * arity;
        let sibling_end = (sibling_start + arity).min(level_nodes.len());

        let mut level_siblings = Vec::with_capacity(arity - 1);
        for i in sibling_start..sibling_end {
            if i != idx {
                level_siblings.push(level_nodes[i]);
            }
        }
        while level_siblings.len() < arity - 1 {
            level_siblings.push(Fr::from(0u64));
        }

        siblings.push(level_siblings);
        idx /= arity;
    }

    MerkleProof {
        leaf_index,
        leaf_value,
        siblings,
        root,
    }
}

/// Verify a Merkle proof for an 8-ary tree.
pub fn verify_merkle_proof(proof: &MerkleProof, arity: usize) -> bool {
    let mut current = proof.leaf_value;
    let mut idx = proof.leaf_index;

    for (level, level_siblings) in proof.siblings.iter().enumerate() {
        let position = idx % arity;
        let mut inputs = vec![Fr::from(0u64); arity];

        let mut sib_iter = level_siblings.iter();
        for j in 0..arity {
            if j == position {
                inputs[j] = current;
            } else {
                inputs[j] = *sib_iter.next().unwrap_or(&Fr::from(0u64));
            }
        }

        let domain = if level == 0 { Fr::zero() } else { Fr::one() };
        current = hash8_with_domain(&inputs, domain);
        idx /= arity;
    }

    current == proof.root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash8_deterministic() {
        let inputs: Vec<Fr> = (0..8).map(|i| Fr::from(i as u64)).collect();
        let domain = Fr::one();
        assert_eq!(
            hash8_with_domain(&inputs, domain),
            hash8_with_domain(&inputs, domain)
        );
    }

    #[test]
    fn hash8_different_inputs() {
        let a: Vec<Fr> = (0..8).map(|i| Fr::from(i as u64)).collect();
        let mut b = a.clone();
        b[7] = Fr::from(99u64);
        let domain = Fr::one();
        assert_ne!(hash8_with_domain(&a, domain), hash8_with_domain(&b, domain));
    }

    #[test]
    fn tree_small() {
        let leaves: Vec<Fr> = (0..16).map(|i| Fr::from(i as u64)).collect();
        let (_tree, root) = build_merkle_tree(&leaves, 8);
        assert_ne!(root, Fr::from(0u64));
    }
}
