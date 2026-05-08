use ark_bn254::{Fr, Fq};
use ark_ff::PrimeField;
fn main() {
    println!("Fr - 1: {}", Fr::from(-1i64).into_bigint());
    println!("Fq - 1: {}", Fq::from(-1i64).into_bigint());
}
