//! Property-based tamper tests for the pvthfhe-core FHE backend.
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
    fn tampered_share_rejected(
        plaintext in prop::collection::vec(any::<u8>(), 4..=64),
        tamper_byte in 1u8..=255u8,
        tamper_pos in any::<usize>()
    ) {
        acknowledge_mock_backend();
        let backend = MockBackend::load_params(TOML).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(99);

        let share0 = backend.keygen_share(0, &mut rng).unwrap();
        let share1 = backend.keygen_share(1, &mut rng).unwrap();
        let share2 = backend.keygen_share(2, &mut rng).unwrap();
        let pk = backend.aggregate_keygen(&[share0, share1, share2]).unwrap();

        let ct = backend.encrypt(&pk, &plaintext, &mut rng).unwrap();

        let mut ds0 = backend.partial_decrypt(&ct, 0, &mut rng).unwrap();
        let ds1 = backend.partial_decrypt(&ct, 1, &mut rng).unwrap();
        let ds2 = backend.partial_decrypt(&ct, 2, &mut rng).unwrap();

        if !ds0.bytes.is_empty() {
            let pos = tamper_pos % ds0.bytes.len();
            ds0.bytes[pos] ^= tamper_byte;
        }

        let result = backend.aggregate_decrypt(&ct, &[ds0, ds1, ds2], 2);
        match result {
            Err(_) => {}
            Ok(recovered) => {
                prop_assert_ne!(recovered, plaintext,
                    "tampered share produced correct plaintext (should be wrong)");
            }
        }
    }
}
