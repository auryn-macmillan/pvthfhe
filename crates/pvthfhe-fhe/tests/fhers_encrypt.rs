#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for real encryption in `FhersBackend`.

use fhe::bfv::{Ciphertext as BfvCiphertext, PublicKey as BfvPublicKey};
use fhe_math::rq::Poly;
use fhe_traits::{DeserializeParametrized, DeserializeWithContext};
use pvthfhe_fhe::{fhers::FhersBackend, wire, FheBackend};
use rand::thread_rng;

const CANONICAL_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

#[test]
fn fhers_encrypt_uses_real_public_key_encryption() {
    let backend = FhersBackend::load_params(CANONICAL_PARAMS_TOML).expect("load params");
    let session_id = [11u8; 32];
    let mut rng = thread_rng();

    let shares = (1u32..=3)
        .map(|party_id| backend.keygen_share_with_session(&session_id, party_id, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("keygen shares");

    let pk = backend.aggregate_keygen(&shares).expect("aggregate keygen");
    let decoded_pk = wire::decode_public_key(&pk.bytes).expect("decode public key");
    let ctx = backend
        .bfv_params()
        .ctx_at_level(0)
        .expect("level-0 context");
    let p0 = Poly::from_bytes(&decoded_pk.p0, ctx).expect("deserialize p0");
    let p1 = Poly::from_bytes(&decoded_pk.p1, ctx).expect("deserialize p1");
    let reconstructed_pk = BfvPublicKey {
        par: backend.bfv_params().clone(),
        c: BfvCiphertext::new(vec![p0, p1], backend.bfv_params()).expect("ciphertext from polys"),
    };

    assert_eq!(
        reconstructed_pk.c.c.len(),
        2,
        "reconstructed public key should have 2 polys"
    );

    let result = backend.encrypt(&pk, b"hello world", &mut rng);

    assert!(
        result.is_ok(),
        "encrypt should succeed with a real public key"
    );
    let ciphertext = result.expect("ciphertext");
    assert!(
        !ciphertext.bytes.is_empty(),
        "ciphertext bytes should be non-empty"
    );
    assert!(
        ciphertext.bytes.len() > 100,
        "ciphertext bytes should be substantial"
    );

    let decoded_ct = BfvCiphertext::from_bytes(&ciphertext.bytes, backend.bfv_params())
        .expect("deserialize ciphertext");
    assert_eq!(
        decoded_ct.c.len(),
        2,
        "fresh BFV ciphertext should have 2 polys"
    );
}
