use pvthfhe_compressor::micronova::tree::CompressionTree;

#[test]
fn compression_2_leaf() {
    let leaves = vec![[1u8; 32], [2u8; 32]];
    let tree = CompressionTree::build(&leaves).unwrap();
    assert_eq!(tree.depth, 1);
}

#[test]
fn compression_4_leaf() {
    let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    let tree = CompressionTree::build(&leaves).unwrap();
    assert_eq!(tree.depth, 2);
}

#[test]
fn compression_8_leaf() {
    let leaves = vec![
        [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32], [7u8; 32], [8u8; 32],
    ];
    let tree = CompressionTree::build(&leaves).unwrap();
    assert_eq!(tree.depth, 3);
}

#[test]
fn compression_proofs_are_constant_size() {
    let leaves_2 = vec![[1u8; 32], [2u8; 32]];
    let tree_2 = CompressionTree::build(&leaves_2).unwrap();
    let size_2 = tree_2.root_proof.0.len();

    let leaves_8 = vec![
        [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32], [7u8; 32], [8u8; 32],
    ];
    let tree_8 = CompressionTree::build(&leaves_8).unwrap();
    let size_8 = tree_8.root_proof.0.len();

    // Root proof size should be O(1) with respect to tree depth.
    // The difference between 2-leaf and 8-leaf compressed proofs should be
    // bounded by a small constant factor (Nova IVC proof overhead).
    // Depth-1 (1 node) vs depth-3 (15 nodes): proof size should not grow
    // linearly with the number of folded nodes.
    let max_ratio = 4.0;
    let ratio = size_8 as f64 / size_2 as f64;
    assert!(
        ratio < max_ratio,
        "proof size ratio {} exceeds max {max_ratio} (2-leaf={size_2}B, 8-leaf={size_8}B)",
        ratio
    );
}
