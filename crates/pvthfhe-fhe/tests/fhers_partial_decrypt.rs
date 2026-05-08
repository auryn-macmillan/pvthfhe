//! Integration tests for real partial decryption in `FhersBackend`.

use fhe::bfv::Ciphertext as BfvCiphertext;
use fhe::trbfv::ShareManager;
use fhe_math::rq::{Poly, Representation};
use fhe_traits::{DeserializeParametrized, Serialize};
use pvthfhe_fhe::{fhers::FhersBackend, wire, FheBackend};
use rand::thread_rng;
use std::sync::Arc;

const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

#[test]
fn fhers_partial_decrypt_returns_real_decryption_share_polynomials() {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let session_id = [41u8; 32];
    let mut rng = thread_rng();

    let shares = (1u32..=5)
        .map(|party_id| backend.keygen_share_with_session(&session_id, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("keygen shares");

    backend.setup_threshold(5, 3).expect("setup threshold");

    let pk = backend.aggregate_keygen(&shares).expect("aggregate keygen");
    let ciphertext = backend.encrypt(&pk, b"42", &mut rng).expect("encrypt");
    let ct = BfvCiphertext::from_bytes(&ciphertext.bytes, backend.bfv_params())
        .expect("deserialize ciphertext");

    for party_id in 2u32..=5 {
        let decrypt_share = backend
            .partial_decrypt(&ciphertext, party_id, &mut rng)
            .expect("partial decrypt should succeed");
        assert_eq!(decrypt_share.party_id, party_id);
        assert!(
            !decrypt_share.bytes.is_empty(),
            "decrypt share bytes should be non-empty"
        );

        let decoded = wire::decode_decrypt_share(&decrypt_share.bytes).expect("decode share");
        assert!(
            !decoded.d_share_poly.is_empty(),
            "inner decryption-share polynomial bytes should be non-empty"
        );
    }

    let decrypt_share_1 = backend
        .partial_decrypt(&ciphertext, 1, &mut rng)
        .expect("party 1 partial decrypt should succeed");
    let decoded_share_1 = wire::decode_decrypt_share(&decrypt_share_1.bytes).expect("decode share");
    assert!(!decoded_share_1.d_share_poly.is_empty());

    let party_state = backend.take_party_state(1).expect("party state");
    let share_manager = ShareManager::new(5, 2, backend.bfv_params().clone());
    let sk_poly_sum = share_manager
        .coeffs_to_poly_level0(&party_state.sk_poly_sum)
        .expect("sk poly sum");
    let sk_poly_sum: Poly = sk_poly_sum.as_ref().clone();
    let zero_esi = Poly::zero(
        backend
            .bfv_params()
            .ctx_at_level(0)
            .expect("level-0 context"),
        Representation::PowerBasis,
    );
    let expected_share_poly = share_manager
        .decryption_share(Arc::new(ct), sk_poly_sum, zero_esi)
        .expect("expected decryption share");

    assert_eq!(decoded_share_1.d_share_poly, expected_share_poly.to_bytes());
}
