//! Integration tests: folding_n64.
//!
//! The hash-chain-surrogate implementation tested here was removed in R4.3.
//! Equivalent fold-depth tests now live in folding.rs and folding_adversarial.rs.
#![allow(missing_docs, clippy::unwrap_used)]

#[cfg(feature = "hash-chain-surrogate")]
compile_error!("hash-chain-surrogate was removed in R4.3. See folding.rs for real folding tests.");

#[test]
fn folding_n64_removed_in_r4_3() {
    // This test was for the hash-chain surrogate, removed in R4.3.
    // The depth-bomb and scaling tests are now in folding_adversarial.rs
    // (test_depth_bomb_fold_to_depth_10_exact, etc.).
}
