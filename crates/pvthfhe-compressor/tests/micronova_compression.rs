use ark_bn254::Fr;
use pvthfhe_compressor::micronova::tree::CompressionTree;

#[test] fn compression_2_leaf() {
    let leaves = vec![[1u8; 32], [2u8; 32]];
    let tree = CompressionTree::build(&leaves).unwrap();
    assert_eq!(tree.depth, 1);
}
#[test] fn compression_4_leaf() {
    let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    let tree = CompressionTree::build(&leaves).unwrap();
    assert_eq!(tree.depth, 2);
}
