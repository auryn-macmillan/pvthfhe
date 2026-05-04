use pvthfhe_micronova::{MicroNovaProver, R1csInstance};

#[test]
fn prover_smoke_calls_prove() {
    let r1cs = R1csInstance::default();
    let witness = Vec::new();

    let _ = MicroNovaProver::prove(&r1cs, &witness);
}
