//! Red test for the BN254 KZG SRS artifact.

use std::fs;

#[test]
fn srs_load() {
    let srs_path = format!("{}/../../bench/srs/bn254.srs", env!("CARGO_MANIFEST_DIR"));

    let metadata = fs::metadata(&srs_path).expect("missing bn254.srs artifact");

    assert!(metadata.len() > 0, "bn254.srs must be non-empty");
}
