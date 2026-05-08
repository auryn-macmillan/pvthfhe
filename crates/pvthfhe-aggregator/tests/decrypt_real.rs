//! Integration test: decrypt_real.

use pvthfhe_aggregator::{
    decrypt::{aggregate_decrypt, partial_decrypt},
    keygen::simulator::{KeygenResult, KeygenSimulator},
};
use pvthfhe_fhe::{fhers::FhersBackend, FheBackend};
use rand::thread_rng;
use sha2::{Digest, Sha256};

const TEST_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

fn must<T, E: core::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error:?}"),
    }
}

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

#[test]
fn decrypt_real_smoke_test() {
    let backend = must(
        FhersBackend::load_params(TEST_PARAMS_TOML),
        "load real backend",
    );
    let mut simulator = KeygenSimulator::new_with_backend(8, 5, backend.clone());
    let result = must(simulator.run(), "run keygen simulator");

    let transcript = match result {
        KeygenResult::Complete(transcript) => transcript,
        KeygenResult::Blamed(blamed) => panic!("expected complete transcript, blamed: {blamed:?}"),
    };

    must(backend.setup_threshold(8, 5), "setup threshold state");

    let mut rng = thread_rng();
    let plaintext = [0u8; 64];
    let ciphertext = must(
        backend.encrypt(
            &transcript.round3_aggregate.aggregate_pk,
            &plaintext,
            &mut rng,
        ),
        "encrypt plaintext",
    );
    let ciphertext_hash = hash_bytes(&ciphertext.bytes);
    let shares = [1u32, 2, 3, 4, 5]
        .into_iter()
        .map(|party_id| {
            partial_decrypt(
                &backend,
                &ciphertext,
                party_id,
                &transcript.dkg_root,
                &ciphertext_hash,
                1,
                &mut rng,
            )
        })
        .collect::<Result<Vec<_>, _>>();
    let shares = must(shares, "produce partial decrypt shares");

    let recovered = must(
        aggregate_decrypt(
            &backend,
            &ciphertext,
            &shares,
            5,
            &transcript.participant_set,
            &transcript.dkg_root,
            &ciphertext_hash,
            1,
        ),
        "aggregate decrypt",
    );

    assert_eq!(recovered, plaintext);
}
