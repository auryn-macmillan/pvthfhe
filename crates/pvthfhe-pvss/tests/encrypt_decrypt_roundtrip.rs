//! Roundtrip test for BFV-backed PVSS encryption.

use pvthfhe_fhe::{mock::MockBackend, types::Ciphertext, FheBackend};
use pvthfhe_pvss::nizk_decrypt::DecryptNizkWitness;
use pvthfhe_pvss::{LatticePvssBfvAdapter, PvssAdapter, PvssContext};
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};

const TEST_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

fn acknowledge_mock_backend() {
    unsafe {
        std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
    }
}

fn recipient_keypair(seed: u64, session_byte: u8) -> (MockBackend, Vec<u8>) {
    let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let session_id = [session_byte; 32];
    let share = backend
        .keygen_share_with_session(&session_id, 1, &mut rng)
        .expect("keygen share");
    let public_key = backend.aggregate_keygen(&[share]).expect("aggregate keygen");
    backend.setup_threshold(1, 1).expect("setup single-party threshold");
    (backend, public_key.bytes)
}

#[test]
fn encrypt_decrypt_roundtrip_recovers_secret() {
    acknowledge_mock_backend();

    let encryption_backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
    let adapter = LatticePvssBfvAdapter::new_with_backend(encryption_backend);
    let ctx = PvssContext {
        n: 3,
        t: 2,
        session_id: vec![9; 32],
    };

    let mut rng = ChaCha8Rng::seed_from_u64(7);
    let mut secret = vec![0u8; 32];
    rng.fill_bytes(&mut secret);

    let recipients = (0..ctx.n)
        .map(|index| recipient_keypair(100 + index as u64, index as u8 + 1))
        .collect::<Vec<_>>();
    let recipient_pks = recipients
        .iter()
        .map(|(_, public_key)| public_key.clone())
        .collect::<Vec<_>>();

    assert_eq!(adapter.backend_id(), "lattice-pvss-bfv-d2");

    let encrypted = adapter
        .deal(&secret, &recipient_pks, &ctx)
        .expect("deal encrypted shares");
    adapter
        .verify_shares(&encrypted, &ctx)
        .expect("verify encrypted shares");

    let decrypted_shares = encrypted
        .ciphertexts
        .iter()
        .zip(recipients.iter())
        .enumerate()
        .map(|(index, (ciphertext_bytes, (backend, _)))| {
            let ciphertext = Ciphertext {
                bytes: ciphertext_bytes.clone(),
            };
            let decrypt_share = backend
                .partial_decrypt(&ciphertext, 1, &mut rng)
                .expect("partial decrypt");
            let share_bytes = backend
                .aggregate_decrypt(&ciphertext, &[decrypt_share], 1)
                .expect("aggregate decrypt");

            adapter
                .prove_decrypted_share(
                    ciphertext_bytes,
                    &recipient_pks[index],
                    index,
                    share_bytes,
                    &DecryptNizkWitness {
                        secret_key_bytes: vec![index as u8 + 1; 64],
                        decryption_noise: vec![index as u8 + 2; 64],
                    },
                    &ctx,
                )
                .expect("attach decrypt proof")
        })
        .collect::<Vec<_>>();

    let recovered = adapter
        .recover(&decrypted_shares[..ctx.t], &ctx)
        .expect("recover secret");

    assert_eq!(recovered, secret);
}
