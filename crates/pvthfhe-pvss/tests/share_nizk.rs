//! Integration tests for PVSS share-encryption NIZKs.

use pvthfhe_fhe::{mock::MockBackend, FheBackend};
use pvthfhe_pvss::nizk_share::ShareNizkProof;
use pvthfhe_pvss::{LatticePvssBfvAdapter, PvssAdapter, PvssContext};
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};

const TEST_PARAMS_TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

fn acknowledge_mock_backend() {
    unsafe {
        std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
    }
}

fn recipient_public_keys(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|index| {
            let backend = MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend");
            let mut rng = ChaCha8Rng::seed_from_u64(100 + index as u64);
            let session_id = [index as u8 + 1; 32];
            let share = backend
                .keygen_share_with_session(&session_id, 1, &mut rng)
                .expect("keygen share");
            backend
                .setup_threshold(1, 1, [0u8; 32])
                .expect("setup threshold");
            backend
                .aggregate_keygen(&[share])
                .expect("aggregate keygen")
                .bytes
        })
        .collect()
}

fn sample_secret() -> Vec<u8> {
    let mut rng = ChaCha8Rng::seed_from_u64(7);
    let mut secret = vec![0u8; 32];
    rng.fill_bytes(&mut secret);
    secret
}

fn sample_context() -> PvssContext {
    PvssContext {
        n: 3,
        t: 2,
        session_id: vec![9; 32],
        epoch: 0,
        dkg_root: vec![],
        dealer_index: pvthfhe_pvss::derive_dealer_index(&[9; 32]),
    }
}

fn corrupt_lattice_binding(proof_bytes: &mut [u8]) {
    let len = proof_bytes.len();
    // layout: [...body...][commitment_binding:32][challenge:32][lattice_binding:32][relation_binding:32][d2_binding:32]
    assert!(
        len >= 64,
        "proof too short for lattice binding (d2_binding added 32 bytes)"
    );
    proof_bytes[len - 64] ^= 0xFF;
    proof_bytes[len - 63] ^= 0xFF;
}

#[test]
fn _debug_trace_proof_bytes() {
    acknowledge_mock_backend();

    let adapter = LatticePvssBfvAdapter::new_with_backend(
        MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend"),
    );
    let ctx = sample_context();

    let encrypted = adapter
        .deal(&sample_secret(), &recipient_public_keys(ctx.n), &ctx)
        .expect("deal encrypted shares");

    let proof = &encrypted.proofs[0];
    eprintln!("proof len: {}", proof.len());
    eprintln!("proof[0] (version): 0x{:02x}", proof[0]);
    eprintln!("proof[1..5] (body_len): {:02x?}", &proof[1..5]);
    let body_len = u32::from_be_bytes(proof[1..5].try_into().unwrap());
    eprintln!("body_len parsed: {}", body_len);
    eprintln!("proof[5..9] (tag): {:02x?}", &proof[5..9]);
    eprintln!(
        "1+4+body_len = {}, actual = {}",
        1 + 4 + body_len,
        proof.len()
    );

    let decoded = ShareNizkProof::from_bytes(proof.clone()).expect("decode");
    let opened = decoded.decode().expect("decode body");
    eprintln!(
        "statement.session_id.len = {}",
        opened.statement.session_id.len()
    );
    eprintln!("commitment_bytes.len = {}", opened.commitment_bytes.len());
    eprintln!("commitment_binding = {:02x?}", &opened.commitment_binding);
    eprintln!("challenge = {:02x?}", &opened.challenge);
    eprintln!("lattice_binding = {:02x?}", &opened.lattice_binding);
    eprintln!("d2_binding       = {:02x?}", &opened.d2_binding);
}

#[test]
fn cheating_dealer_rejected() {
    acknowledge_mock_backend();

    let adapter = LatticePvssBfvAdapter::new_with_backend(
        MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend"),
    );
    let ctx = sample_context();
    let mut encrypted = adapter
        .deal(&sample_secret(), &recipient_public_keys(ctx.n), &ctx)
        .expect("deal encrypted shares");

    encrypted.ciphertexts[0][0] ^= 0x01;

    let result = adapter.verify_shares(&encrypted, &ctx);
    assert!(
        result.is_err(),
        "tampered ciphertext must be rejected (got: {:?})",
        result
    );
}

#[test]
fn tampered_lattice_binding_rejected() {
    acknowledge_mock_backend();

    let adapter = LatticePvssBfvAdapter::new_with_backend(
        MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend"),
    );
    let ctx = sample_context();
    let mut encrypted = adapter
        .deal(&sample_secret(), &recipient_public_keys(ctx.n), &ctx)
        .expect("deal encrypted shares");

    corrupt_lattice_binding(&mut encrypted.proofs[0]);

    let result = adapter.verify_shares(&encrypted, &ctx);
    assert!(
        result.is_err(),
        "tampered lattice binding must be rejected (got: {:?})",
        result
    );
}
