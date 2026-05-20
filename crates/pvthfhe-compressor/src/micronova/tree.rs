//! P3-M2 CompressionTree: bottom-up folding verification tree.
//!
//! Builds a complete binary tree from leaf accumulator hashes, then folds
//! all nodes through a [`MicroNovaCompressor`] using heterogeneous IVC.
//! Internal nodes verify that their children correctly fold, while leaf
//! nodes contribute their hashes to the accumulator.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};

use crate::micronova::compressor::MicroNovaCompressor;
use crate::sonobe::ExternalInputs3;
use crate::witness::hash_all_coeffs;
use crate::{CompressedProof, CompressorError};

/// Compression tree: bottom-up folding verification.
///
/// For a tree with `2^depth` leaves, there are `2^(depth+1) - 1` total nodes
/// (internal + leaves). Nodes are ordered level-by-level from root to leaves,
/// matching the [`crate::sonobe::latticefold_circuit_family::LatticeFoldTreeCircuitFamily`]
/// indexing scheme.
pub struct CompressionTree {
    /// Number of internal levels above the leaves.
    pub depth: usize,
    /// The compressed root proof covering all tree nodes.
    pub root_proof: CompressedProof,
}

fn fr_to_bytes_be(value: Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let be = value.into_bigint().to_bytes_be();
    let start = 32usize.saturating_sub(be.len());
    bytes[start..].copy_from_slice(&be);
    bytes
}

impl CompressionTree {
    /// Build a compression tree from leaf accumulator hashes.
    ///
    /// Each leaf is a 32-byte hash. Pairs are hashed together with native Poseidon
    /// bottom-up to compute internal node hashes. The full tree (leaves +
    /// internal nodes in level order) is then folded through a single
    /// heterogeneous IVC chain via [`MicroNovaCompressor::prove_tree`].
    ///
    /// # Panics
    ///
    /// Panics if `leaf_hashes.len()` is not a power of two.
    pub fn build(leaf_hashes: &[[u8; 32]]) -> Result<Self, CompressorError> {
        assert!(
            leaf_hashes.len().is_power_of_two(),
            "leaf count must be power of 2"
        );
        let depth = leaf_hashes.len().ilog2() as usize;

        // Build tree bottom-up, storing every level as a Vec<[u8; 32]>.
        // levels[0] = leaves, levels[1] = first parents, ..., levels[depth] = root.
        let mut levels: Vec<Vec<[u8; 32]>> = Vec::with_capacity(depth + 1);
        levels.push(leaf_hashes.to_vec());

        while levels.last().unwrap().len() > 1 {
            let current = levels.last().unwrap();
            let mut next = Vec::with_capacity(current.len() / 2);
            for pair in current.chunks(2) {
                let left_fr = Fr::from_be_bytes_mod_order(&pair[0]);
                let right_fr = Fr::from_be_bytes_mod_order(&pair[1]);
                let parent_fr = hash_all_coeffs(&[left_fr, right_fr]);
                next.push(fr_to_bytes_be(parent_fr));
            }
            levels.push(next);
        }

        // levels now contains `depth + 1` entries:
        //    levels[0]         = leaves
        //    levels[1..depth]  = internal levels (ascending)
        //    levels[depth]     = root

        let total_nodes = (1usize << (depth + 1)) - 1;
        let mut steps: Vec<ExternalInputs3<Fr>> = Vec::with_capacity(total_nodes);

        // Walk levels from root (top) to leaves (bottom).
        for level_from_top in 0..=depth {
            // Index into `levels` (which is leaf-first).
            let level_idx = depth - level_from_top;
            let lvl = &levels[level_idx];

            if level_from_top == depth {
                // Leaf level — no children below.
                // Use circuit variant 0 (leaf ring-equation verifier).
                // ext.0 = ext.1 = 1, ext.2 = leaf_hash.
                for hash in lvl {
                    steps.push(ExternalInputs3(
                        Fr::from(1u64),
                        Fr::from(1u64),
                        Fr::from_be_bytes_mod_order(hash),
                    ));
                }
            } else {
                // Internal level — children are in levels[level_idx - 1].
                let children_idx = level_idx - 1;
                for (i, hash) in lvl.iter().enumerate() {
                    let left = Fr::from_be_bytes_mod_order(&levels[children_idx][2 * i]);
                    let right = Fr::from_be_bytes_mod_order(&levels[children_idx][2 * i + 1]);
                    let parent = Fr::from_be_bytes_mod_order(hash);
                    steps.push(ExternalInputs3(left, right, parent));
                }
            }
        }

        // Fold the entire tree through the heterogeneous compressor.
        let epoch = [6u8; 32];
        let compressor = MicroNovaCompressor::new(depth, epoch);
        let root_proof = compressor.prove_tree(&steps)?;

        Ok(Self { depth, root_proof })
    }
}
