//! Golden-vector tests for byte/slot encoding boundaries.

use pvthfhe_fhe::{
    fhers::{bytes_to_slots, slots_to_bytes, FhersBackend},
    FheBackend, FheError,
};
use rand::thread_rng;

const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";
const DEGREE: usize = 8192;

#[test]
fn encoding_golden_256_bytes() {
    let input = (0u8..=255).collect::<Vec<_>>();

    let slots = bytes_to_slots(&input, DEGREE);
    let recovered = slots_to_bytes(&slots, input.len());

    assert_eq!(recovered, input);
}

#[test]
fn encoding_golden_real_ascii_roundtrip() {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let mut rng = thread_rng();
    let session_id = [37u8; 32];
    let shares = (1u32..=3)
        .map(|party_id| backend.keygen_share_with_session(&session_id, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("keygen shares");
    let pk = backend.aggregate_keygen(&shares).expect("aggregate keygen");
    backend.setup_threshold(3, 2).expect("setup threshold");

    let plaintext = b"non-trivial ascii plaintext";
    let ciphertext = backend.encrypt(&pk, plaintext, &mut rng).expect("encrypt");
    let decrypt_shares = [1u32, 2]
        .into_iter()
        .map(|party_id| backend.partial_decrypt(&ciphertext, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("partial decrypt shares");

    let recovered = backend
        .aggregate_decrypt(&ciphertext, &decrypt_shares, 2, b"")
        .expect("aggregate decrypt");

    assert_eq!(recovered, plaintext);
}

#[test]
fn encoding_golden_full_plaintext() {
    let input = vec![0x00u8; (DEGREE - 1) * 2];

    let slots = bytes_to_slots(&input, DEGREE);
    let recovered = slots_to_bytes(&slots, input.len());

    assert_eq!(recovered, input);
}

#[test]
fn encoding_golden_plaintext_too_long() {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let mut rng = thread_rng();
    let session_id = [23u8; 32];
    let shares = (1u32..=3)
        .map(|party_id| backend.keygen_share_with_session(&session_id, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("keygen shares");
    let pk = backend.aggregate_keygen(&shares).expect("aggregate keygen");

    let input = vec![0u8; ((DEGREE - 1) * 2) + 1];

    let err = backend
        .encrypt(&pk, &input, &mut rng)
        .expect_err("oversized plaintext should fail");

    assert_eq!(
        err,
        FheError::PlaintextTooLong {
            max: (DEGREE - 1) * 2,
            got: input.len(),
        }
    );
}
