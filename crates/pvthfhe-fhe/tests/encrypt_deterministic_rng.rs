//! Integration tests for deterministic-RNG encryption reproducibility.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use pvthfhe_fhe::{fhers::FhersBackend, FheBackend};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

fn setup_backend() -> (FhersBackend, pvthfhe_fhe::PublicKey) {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let session_id = [51u8; 32];
    let mut rng = ChaCha8Rng::seed_from_u64(999);
    let shares = (1u32..=5)
        .map(|party_id| backend.keygen_share_with_session(&session_id, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("keygen shares");

    backend
        .setup_threshold(5, 3, Sha256::digest(session_id).into())
        .expect("setup threshold");
    let pk = backend.aggregate_keygen(&shares).expect("aggregate keygen");
    (backend, pk)
}

#[test]
fn same_seed_produces_same_ciphertext() {
    let (backend, pk) = setup_backend();

    let mut rng_a = ChaCha8Rng::seed_from_u64(42);
    let mut rng_b = ChaCha8Rng::seed_from_u64(42);

    let ct_a = backend
        .encrypt(&pk, b"hello", &mut rng_a)
        .expect("encrypt a");
    let ct_b = backend
        .encrypt(&pk, b"hello", &mut rng_b)
        .expect("encrypt b");

    assert_eq!(
        ct_a.bytes, ct_b.bytes,
        "same-seed same-plaintext must produce identical ciphertexts"
    );
}
