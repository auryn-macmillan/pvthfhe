//! Smoke test for the scaffolded MicroNova prover API.

use pvthfhe_micronova::{MicroNovaError, MicroNovaProver, R1csInstance};

#[test]
fn prover_smoke_calls_prove() {
    let r1cs = R1csInstance::default();
    let witness = [];

    let result = MicroNovaProver::prove(&r1cs, &witness);

    assert_eq!(result, Err(MicroNovaError::Unimplemented));
}
