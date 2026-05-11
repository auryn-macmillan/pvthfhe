//! R1.3 RED: Encryption randomness guard.
//!
//! Calling `deal()` twice with identical inputs (same secret, same session_id,
//! same recipient public keys) must produce different ciphertext vectors. This
//! guards against accidental determinism in the encryption pipeline.

use pvthfhe_fhe::{mock::MockBackend, FheBackend};
use pvthfhe_pvss::{LatticePvssBfvAdapter, PvssAdapter, PvssContext};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

const TEST_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

fn acknowledge_mock_backend() {
    unsafe {
        std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
    }
}

fn recipient_keypair(seed: u64, session_byte: u8) -> (MockBackend, Vec<u8>) {
    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let session_id = [session_byte; 32];
    let share = backend
        .keygen_share_with_session(&session_id, 1, &mut ChaCha8Rng::seed_from_u64(seed))
        .expect("keygen share");
    let public_key = backend.aggregate_keygen(&[share]).expect("aggregate keygen");
    backend.setup_threshold(1, 1).expect("setup single-party threshold");
    (backend, public_key.bytes)
}

#[test]
fn enc_randomness_ciphertexts_differ_across_runs() {
    acknowledge_mock_backend();

    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let adapter = LatticePvssBfvAdapter::new_with_backend(backend);
    let ctx = PvssContext {
        n: 3,
        t: 2,
        session_id: vec![9; 32],
        epoch: 0,
    };

    let secret = b"test-secret";

    let recipients = (0..ctx.n)
        .map(|index| recipient_keypair(100 + index as u64, index as u8 + 1))
        .collect::<Vec<_>>();
    let recipient_pks = recipients
        .iter()
        .map(|(_, public_key)| public_key.clone())
        .collect::<Vec<_>>();

    // Deal the same secret twice with identical inputs.
    let encrypted1 = adapter
        .deal(secret, &recipient_pks, &ctx)
        .expect("first deal must succeed");
    let encrypted2 = adapter
        .deal(secret, &recipient_pks, &ctx)
        .expect("second deal must succeed");

    assert_eq!(
        encrypted1.ciphertexts.len(),
        encrypted2.ciphertexts.len(),
        "both deal calls must produce same number of ciphertexts"
    );

    // At least one ciphertext must differ between the two runs.
    let any_pair_differs = encrypted1
        .ciphertexts
        .iter()
        .zip(encrypted2.ciphertexts.iter())
        .any(|(ct1, ct2)| ct1 != ct2);

    assert!(
        any_pair_differs,
        "ciphertexts must differ between independent deal() calls \
         (expected non-determinism from encryption randomness)"
    );
}

#[test]
fn derive_share_randomness_is_absent_from_source() {
    // RED: Confirm the deterministic derive_share_randomness function has been
    // removed from encrypt.rs. Grep the source for the function name.
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("encrypt.rs"),
    )
    .expect("read encrypt.rs");
    assert!(
        !src.contains("derive_share_randomness"),
        "derive_share_randomness must be absent from encrypt.rs"
    );
}
