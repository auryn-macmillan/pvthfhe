//! Integration tests: round_trip_props.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use proptest::prelude::*;
use pvthfhe_fhe::mock::MockBackend;
use pvthfhe_fhe::FheBackend;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

const TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

fn acknowledge_mock_backend() {
    std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn round_trip(plaintext in prop::collection::vec(any::<u8>(), 4..=64)) {
        acknowledge_mock_backend();
        let backend = MockBackend::load_params(TOML).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let share0 = backend.keygen_share(0, &mut rng).unwrap();
        let share1 = backend.keygen_share(1, &mut rng).unwrap();
        let share2 = backend.keygen_share(2, &mut rng).unwrap();
        let pk = backend.aggregate_keygen(&[share0, share1, share2]).unwrap();

        let ct = backend.encrypt(&pk, &plaintext, &mut rng).unwrap();

        let ds0 = backend.partial_decrypt(&ct, 0, &mut rng).unwrap();
        let ds1 = backend.partial_decrypt(&ct, 1, &mut rng).unwrap();
        let ds2 = backend.partial_decrypt(&ct, 2, &mut rng).unwrap();

        let recovered = backend.aggregate_decrypt(&ct, &[ds0, ds1, ds2], 2).unwrap();
        prop_assert_eq!(recovered, plaintext);
    }
}
