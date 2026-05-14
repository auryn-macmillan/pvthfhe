//! Integration tests against golden test vectors for the pvthfhe-core mock backend.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::path::PathBuf;

use pvthfhe_fhe::mock::MockBackend;
use pvthfhe_fhe::types::{DecryptShare, KeygenShare, PublicKey};
use pvthfhe_fhe::FheBackend;
use pvthfhe_types::ProtocolBytes;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde::Deserialize;

fn acknowledge_mock_backend() {
    std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
}

#[derive(Debug, Deserialize)]
struct VectorKeygenShare {
    party_id: u32,
    share_bytes: String,
}

#[derive(Debug, Deserialize)]
struct VectorDecryptShare {
    party_id: u32,
    share_bytes: String,
}

#[derive(Debug, Deserialize)]
struct VectorParams {
    n: u32,
    log2_q: u32,
    t_plain: u32,
    #[serde(default = "default_moduli")]
    moduli: Vec<u64>,
    #[serde(default = "default_variance")]
    variance: usize,
    threshold: usize,
    #[allow(dead_code)]
    n_parties: usize,
}

fn default_moduli() -> Vec<u64> {
    vec![288230376173076481, 288230376167047169, 288230376161280001]
}

const fn default_variance() -> usize {
    10
}

#[derive(Debug, Deserialize)]
struct TestVector {
    schema: String,
    description: String,
    params: VectorParams,
    keygen_shares: Vec<VectorKeygenShare>,
    aggregate_pk: String,
    plaintext: String,
    ciphertext: String,
    decrypt_shares: Vec<VectorDecryptShare>,
    recovered_plaintext: String,
}

fn load_backend(params: &VectorParams) -> MockBackend {
    acknowledge_mock_backend();
    let toml = format!(
        "[rlwe]\nn = {}\nlog2_q = {}\nt_plain = {}\nmoduli = {:?}\nvariance = {}\n",
        params.n, params.log2_q, params.t_plain, params.moduli, params.variance
    );
    MockBackend::load_params(&toml).expect("load_params failed")
}

fn vectors_dir() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    PathBuf::from(manifest).join("tests").join("vectors")
}

#[test]
fn all_golden_vectors() {
    let dir = vectors_dir();
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("cannot read vectors dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    entries.sort_by_key(|e| e.path());

    assert!(!entries.is_empty(), "no JSON files found in {:?}", dir);

    let mut failures = 0usize;
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    for entry in &entries {
        let path = entry.path();
        let raw = std::fs::read_to_string(&path).expect("cannot read test vector file");
        let v: TestVector = serde_json::from_str(&raw).expect("cannot parse test vector JSON");

        assert_eq!(
            v.schema, "pvthfhe-test-vector-v1",
            "{:?}: unexpected schema",
            path
        );

        let backend = load_backend(&v.params);

        let keygen_shares: Vec<KeygenShare> = v
            .keygen_shares
            .iter()
            .map(|s| KeygenShare {
                party_id: s.party_id,
                bytes: ProtocolBytes(hex::decode(&s.share_bytes).expect("bad hex in keygen_share")),
            })
            .collect();

        let computed_pk = backend
            .aggregate_keygen(&keygen_shares)
            .expect("aggregate_keygen failed");
        let expected_pk = hex::decode(&v.aggregate_pk).expect("bad hex in aggregate_pk");
        if computed_pk.bytes != expected_pk {
            #[cfg(feature = "trace-test-vectors")]
            eprintln!(
                "FAIL {:?} [{}]: aggregate_pk mismatch\n  expected: {}\n  got:      {}",
                path,
                v.description,
                v.aggregate_pk,
                hex::encode(&computed_pk.bytes)
            );
            failures += 1;
            continue;
        }

        let plaintext_bytes = hex::decode(&v.plaintext).expect("bad hex in plaintext");
        let pk = PublicKey { bytes: expected_pk };
        let computed_ct = backend
            .encrypt(&pk, &plaintext_bytes, &mut rng)
            .expect("encrypt failed");
        let expected_ct = hex::decode(&v.ciphertext).expect("bad hex in ciphertext");
        if computed_ct.bytes != expected_ct {
            #[cfg(feature = "trace-test-vectors")]
            eprintln!(
                "FAIL {:?} [{}]: ciphertext mismatch\n  expected: {}\n  got:      {}",
                path,
                v.description,
                v.ciphertext,
                hex::encode(&computed_ct.bytes)
            );
            failures += 1;
            continue;
        }

        let decrypt_shares: Vec<DecryptShare> = v
            .decrypt_shares
            .iter()
            .map(|s| DecryptShare {
                party_id: s.party_id,
                bytes: ProtocolBytes(hex::decode(&s.share_bytes).expect("bad hex in decrypt_share")),
                nizk_proof_bytes: None,
            })
            .collect();

        let ct = pvthfhe_fhe::types::Ciphertext { bytes: expected_ct };
        let recovered = backend
            .aggregate_decrypt(&ct, &decrypt_shares, v.params.threshold, b"")
            .expect("aggregate_decrypt failed");
        let expected_recovered =
            hex::decode(&v.recovered_plaintext).expect("bad hex in recovered_plaintext");

        if recovered != expected_recovered {
            #[cfg(feature = "trace-test-vectors")]
            eprintln!(
                "FAIL {:?} [{}]: recovered_plaintext mismatch\n  expected: {}\n  got:      {}",
                path,
                v.description,
                v.recovered_plaintext,
                hex::encode(&recovered)
            );
            failures += 1;
            continue;
        }

        if recovered != plaintext_bytes {
            #[cfg(feature = "trace-test-vectors")]
            eprintln!(
                "FAIL {:?} [{}]: round-trip broken: recovered != plaintext\n  plaintext: {}\n  recovered: {}",
                path,
                v.description,
                v.plaintext,
                hex::encode(&recovered)
            );
            failures += 1;
            continue;
        }

        println!("PASS {:?} [{}]", path.file_name().unwrap(), v.description);
    }

    assert_eq!(
        failures,
        0,
        "{} vector(s) failed out of {}",
        failures,
        entries.len()
    );
}
