use pvthfhe_aggregator::decrypt::{aggregate_decrypt, partial_decrypt, DecryptError};
use pvthfhe_fhe::{mock::MockBackend, types::Ciphertext, FheBackend};
use rand::thread_rng;

fn acknowledge_mock() {
    unsafe {
        std::env::set_var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK", "1");
    }
}

#[test]
fn no_plaintext_without_valid_nizk_proof() {
    // RED: `aggregate_decrypt` currently accepts any NIZK where nizk[0]==1
    // and returns plaintext. After GREEN, it must verify the NIZK proof
    // and return `ProofVerifyFailed` if invalid.
    acknowledge_mock();
    let mut rng = thread_rng();
    let backend = MockBackend::load_params(
        "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10"
    ).expect("load mock backend");
    let ct = Ciphertext { bytes: vec![1, 2, 3] };
    let dkg_root = [1u8; 32];
    let ciphertext_hash = [2u8; 32];

    let mut share1 = partial_decrypt(
        &backend, &ct, 1, &dkg_root, &ciphertext_hash, 42, &mut rng,
    ).expect("partial decrypt share 1");

    let mut share2 = partial_decrypt(
        &backend, &ct, 2, &dkg_root, &ciphertext_hash, 42, &mut rng,
    ).expect("partial decrypt share 2");

    // Tamper share1's NIZK: pass the trivial nizk[0]==1 check by keeping
    // byte 0 as 1, but set remaining bytes to something invalid (0xDE).
    // Current code only checks nizk[0] — this tampered proof passes
    // validation and `aggregate_decrypt` returns Ok(plaintext).
    share1.nizk = vec![1, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];

    let result = aggregate_decrypt(
        &backend,
        &ct,
        &[share1, share2],
        2,
        &[1, 2],
        &dkg_root,
        &ciphertext_hash,
        42,
    );

    // RED assertion: function should FAIL because the NIZK proof is invalid.
    // On current main, this ASSERTION FAILS — function returns Ok(plaintext)
    // because nizk verification is a trivial nizk[0]==1 check.
    assert!(
        result.is_err(),
        "no_plaintext_without_proof: aggregate_decrypt returned Ok even though \
         share1's NIZK proof was tampered (bytes 1..=8 = 0xDEADBEEFCAFEBABE). \
         Got: {:?}. The current trivial nizk[0]==1 check is insufficient; \
         a proper proof verification must reject this.",
        result
    );
}
