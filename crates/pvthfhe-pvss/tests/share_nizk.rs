//! Integration tests for PVSS share-encryption NIZKs.

use pvthfhe_fhe::{mock::MockBackend, FheBackend};
use pvthfhe_pvss::nizk_share::{ShareNizkProof, SHARE_NIZK_DOMAIN_SEPARATOR};
use pvthfhe_pvss::{LatticePvssBfvAdapter, PvssAdapter, PvssContext, PvssError};
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
            backend.setup_threshold(1, 1).expect("setup threshold");
            backend.aggregate_keygen(&[share]).expect("aggregate keygen").bytes
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
    }
}

fn overwrite_first_share_coeff(proof_bytes: &mut [u8], replacement: i16) {
    let mut offset = 0usize;
    offset += 2;
    for _ in 0..2 {
        let len = read_u32_be(proof_bytes, offset) as usize;
        offset += 4 + len;
    }
    offset += 8;
    offset += 8;
    for _ in 0..5 {
        let len = read_u32_be(proof_bytes, offset) as usize;
        offset += 4 + len;
    }
    let share_len = read_u32_be(proof_bytes, offset) as usize;
    offset += 4 + share_len;
    let coeff_count = read_u32_be(proof_bytes, offset) as usize;
    offset += 4;
    assert!(coeff_count > 0, "proof must contain share coeffs");
    proof_bytes[offset..offset + 2].copy_from_slice(&replacement.to_le_bytes());
}

fn read_u32_be(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("u32 bytes"))
}

#[test]
fn honest_dealer_accepted() {
    acknowledge_mock_backend();

    let adapter = LatticePvssBfvAdapter::new_with_backend(
        MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend"),
    );
    let ctx = sample_context();
    let encrypted = adapter
        .deal(&sample_secret(), &recipient_public_keys(ctx.n), &ctx)
        .expect("deal encrypted shares");

    for proof_bytes in &encrypted.proofs {
        let proof = ShareNizkProof::from_bytes(proof_bytes.clone()).expect("decode proof");
        assert_eq!(proof.domain_separator, SHARE_NIZK_DOMAIN_SEPARATOR);
    }

    adapter
        .verify_shares(&encrypted, &ctx)
        .expect("honest dealer should verify");
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
    assert_eq!(result, Err(PvssError::InvalidShare));
}

#[test]
fn norm_bound_violator_rejected() {
    acknowledge_mock_backend();

    let adapter = LatticePvssBfvAdapter::new_with_backend(
        MockBackend::load_params(TEST_PARAMS_TOML).expect("load mock backend"),
    );
    let ctx = sample_context();
    let mut encrypted = adapter
        .deal(&sample_secret(), &recipient_public_keys(ctx.n), &ctx)
        .expect("deal encrypted shares");

    overwrite_first_share_coeff(&mut encrypted.proofs[0], 300);

    let result = adapter.verify_shares(&encrypted, &ctx);
    assert_eq!(result, Err(PvssError::InvalidShare));
}
