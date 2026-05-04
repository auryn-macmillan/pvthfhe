//! RED test for the BN254/Grumpkin half-pairing cycle wiring.

use pvthfhe_micronova::cycle::{
    bn254_scalar_to_grumpkin_base, grumpkin_base_to_bn254_scalar, Bn254Scalar,
};

#[test]
fn bn254_scalar_round_trips_through_grumpkin_base() {
    let original = Bn254Scalar::from(42_u64);
    let embedded = bn254_scalar_to_grumpkin_base(original);
    let recovered = grumpkin_base_to_bn254_scalar(embedded);

    assert_eq!(recovered, original);
}
