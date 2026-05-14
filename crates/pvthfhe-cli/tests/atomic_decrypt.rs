use pvthfhe_aggregator::decrypt::{aggregate_decrypt, partial_decrypt};
use pvthfhe_fhe::{mock::MockBackend, types::Ciphertext, FheBackend};
use pvthfhe_types::ProtocolBytes;
use rand::thread_rng;

fn acknowledge_mock() {
    unsafe {
        std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
    }
}

#[test]
fn tampered_partial_rejected_no_plaintext() {
    // RED: with one tampered partial decryption share (NIZK proof invalid
    // beyond the trivial nizk[0]==1 check), aggregate_decrypt must return
    // no plaintext and the error must indicate proof verification failure.
    //
    // On current main, aggregate_decrypt returns Ok(plaintext) even with
    // invalid NIZK proofs because verification is the trivial tautology.

    acknowledge_mock();
    let mut rng = thread_rng();
    let backend = MockBackend::load_params(
        "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10"
    ).expect("load mock backend");
    let ct = Ciphertext {
        bytes: vec![0xAA; 16],
    };
    let dkg_root = [3u8; 32];
    let ciphertext_hash = [4u8; 32];
    let epoch = 1;

    let party_pk = vec![0u8; 32];
    let share1 = partial_decrypt(
        &backend,
        &ct,
        1,
        &dkg_root,
        &ciphertext_hash,
        epoch,
        &party_pk,
        None,
        &mut rng,
    )
    .expect("share 1");

    let share2 = partial_decrypt(
        &backend,
        &ct,
        2,
        &dkg_root,
        &ciphertext_hash,
        epoch,
        &party_pk,
        None,
        &mut rng,
    )
    .expect("share 2");

    // Tamper share2's NIZK proof: keep nizk[0]==1 to pass trivial check
    // but corrupt the rest so it's cryptographically invalid.
    let mut tampered_share2 = share2.clone();
    tampered_share2.nizk = ProtocolBytes(vec![1, 0xFF, 0xFF, 0xFF, 0xFF]);

    let result = aggregate_decrypt(
        &backend,
        &ct,
        &[share1, tampered_share2],
        2,
        &[1, 2],
        &dkg_root,
        &ciphertext_hash,
        "test-session",
        epoch,
    );

    match result {
        // RED: plan expects ProofVerifyFailed error, but current code
        // returns Ok(plaintext) because nizk check is trivial.
        Ok(plaintext) => {
            panic!(
                "atomic_decrypt: aggregate_decrypt returned plaintext {:?} despite \
                 tampered NIZK proof. The function must reject with ProofVerifyFailed \
                 BEFORE performing any FHE-backend aggregation.",
                plaintext
            );
        }
        Err(e) => {
            // After GREEN fix, assert the error indicates proof verification failure
            let err_str = format!("{:?}", e);
            let is_proof_failure = err_str.to_lowercase().contains("proof")
                || err_str.to_lowercase().contains("nizk")
                || err_str.to_lowercase().contains("verify");
            assert!(
                is_proof_failure,
                "atomic_decrypt: error variant should indicate proof/NIZK \
                 verification failure, got: {e:?}"
            );
        }
    }
}
