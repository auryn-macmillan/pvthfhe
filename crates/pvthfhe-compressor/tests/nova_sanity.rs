#[cfg(feature = "nova-test")]
use ff::Field;
#[cfg(feature = "nova-test")]
use nova_snark::frontend::*;
#[cfg(feature = "nova-test")]
use nova_snark::nova::*;
#[cfg(feature = "nova-test")]
use nova_snark::provider::*;
#[cfg(feature = "nova-test")]
use nova_snark::traits::circuit::TrivialCircuit;
#[cfg(feature = "nova-test")]
use nova_snark::traits::snark::default_ck_hint;
#[cfg(feature = "nova-test")]
use nova_snark::traits::Engine;

#[cfg(feature = "nova-test")]
type E1 = Bn256EngineKZG;
#[cfg(feature = "nova-test")]
type E2 = GrumpkinEngine;

#[cfg(feature = "nova-test")]
#[test]
fn nova_sanity() {
    let circuit = TrivialCircuit::<<E1 as Engine>::Scalar>::default();

    // PublicParams takes 3 type params: E1, E2, C
    let pp = PublicParams::<E1, E2, _>::setup(&circuit, &*default_ck_hint(), &*default_ck_hint())
        .expect("PublicParams::setup should succeed");

    let num_steps = 1;

    // RecursiveSNARK takes 3 type params: E1, E2, C
    let mut recursive_snark =
        RecursiveSNARK::<E1, E2, _>::new(&pp, &circuit, &[<E1 as Engine>::Scalar::ZERO])
            .expect("RecursiveSNARK::new should succeed");

    recursive_snark
        .prove_step(&pp, &circuit)
        .expect("prove_step should succeed");

    let result = recursive_snark.verify(&pp, num_steps, &[<E1 as Engine>::Scalar::ZERO]);
    assert!(result.is_ok(), "RecursiveSNARK verify should succeed");
}
