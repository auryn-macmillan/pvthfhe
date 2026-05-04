//! Smoke test for the scaffolded MicroNova prover API.

use pvthfhe_cyclo::CycloAccumulator;
use pvthfhe_micronova::{MicroNovaError, MicroNovaProver, R1csInstance};

fn smoke_accumulator() -> CycloAccumulator {
    CycloAccumulator {
        fold_depth: 1,
        acc_commitment_bytes: vec![1u8; 32],
        acc_public_io_bytes: vec![2u8; 32],
        norm_bound_current: 64,
        session_id: String::from("micronova-smoke-session"),
        params_digest: [3u8; 32],
    }
}

#[test]
fn prover_smoke_calls_prove() {
    let r1cs = R1csInstance::default();
    let accumulator = smoke_accumulator();

    let result = MicroNovaProver::prove(&r1cs, &accumulator);

    assert_eq!(result, Err(MicroNovaError::Unimplemented));
}

#[test]
fn prover_smoke_calls_verify() {
    let r1cs = R1csInstance::default();
    let accumulator = smoke_accumulator();
    let proof = Default::default();

    let result = MicroNovaProver::verify(&proof, &accumulator, &r1cs);

    assert_eq!(result, Err(MicroNovaError::Unimplemented));
}
