//! Smoke test for the scaffolded MicroNova prover API.

use pvthfhe_cyclo::CycloAccumulator;
use pvthfhe_micronova::{MicroNovaProver, R1csInstance};

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

    assert!(
        result.is_ok(),
        "prove should succeed for the prototype binding"
    );
}

#[test]
fn prover_smoke_calls_verify() {
    let r1cs = R1csInstance::default();
    let accumulator = smoke_accumulator();
    let proof = MicroNovaProver::prove(&r1cs, &accumulator)
        .expect("prove should succeed before verify is exercised");

    let result = MicroNovaProver::verify(&proof, &accumulator, &r1cs);

    assert!(
        result.is_ok(),
        "verify should accept the matching prototype proof"
    );
}
