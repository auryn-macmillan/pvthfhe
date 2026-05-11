//! R5.4 RED: verifier must reject proofs whose SRS hash does not match
//! the on-chain registry value for the epoch.

use pvthfhe_offchain_verifier::check_srs_hash;

#[test]
fn reject_mismatched_srs_hash() {
    let compressor_srs = [0xAAu8; 32];
    let onchain_srs = [0xBBu8; 32];

    let result = check_srs_hash(&compressor_srs, &onchain_srs);
    assert!(
        result.is_err(),
        "verifier must reject proofs when compressor SRS hash does not match on-chain registry"
    );
}

#[test]
fn accept_matching_srs_hash() {
    let hash = [0xAAu8; 32];

    let result = check_srs_hash(&hash, &hash);
    assert!(
        result.is_ok(),
        "verifier must accept proofs when compressor SRS hash matches on-chain registry"
    );
}
