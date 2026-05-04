//! BN254/Grumpkin half-pairing cycle helpers.

use ark_bn254::{Fq as Bn254Base, Fr as Bn254ScalarField};
use ark_ff::PrimeField;
use ark_grumpkin::{Fq as GrumpkinBase, Fr as GrumpkinScalarField};

/// BN254 base field type.
pub type Bn254BaseField = Bn254Base;

/// BN254 scalar field type.
pub type Bn254Scalar = Bn254ScalarField;

/// Grumpkin base field type.
pub type GrumpkinBaseField = GrumpkinBase;

/// Grumpkin scalar field type.
pub type GrumpkinScalar = GrumpkinScalarField;

/// Embed a BN254 scalar into the isomorphic Grumpkin base field.
#[must_use]
pub fn bn254_scalar_to_grumpkin_base(value: Bn254Scalar) -> GrumpkinBaseField {
    grumpkin_from_bn254_repr(value.into_bigint())
}

/// Extract a BN254 scalar from the isomorphic Grumpkin base field.
#[must_use]
pub fn grumpkin_base_to_bn254_scalar(value: GrumpkinBaseField) -> Bn254Scalar {
    bn254_from_grumpkin_repr(value.into_bigint())
}

fn grumpkin_from_bn254_repr(repr: <Bn254Scalar as PrimeField>::BigInt) -> GrumpkinBaseField {
    match GrumpkinBaseField::from_bigint(repr) {
        Some(value) => value,
        None => unreachable!("BN254 scalar representation must fit inside Grumpkin base field"),
    }
}

fn bn254_from_grumpkin_repr(repr: <GrumpkinBaseField as PrimeField>::BigInt) -> Bn254Scalar {
    match Bn254Scalar::from_bigint(repr) {
        Some(value) => value,
        None => unreachable!("Grumpkin base representation must fit inside BN254 scalar field"),
    }
}
