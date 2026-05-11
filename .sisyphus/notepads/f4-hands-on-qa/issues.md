## Genuine Failures (Non-RED)

1. **pvthfhe-fhe :: encoding_golden_real_ascii_roundtrip**
   - Recovered ciphertext does not match original plaintext
   - Left: random-looking bytes
   - Right: [110, 111, 110, 45, ...] ("non-trivial ascii plaintext")
   - File: crates/pvthfhe-fhe/tests/encoding_golden.rs:46

2. **forge :: UltraHonkVerifierTest::test_valid_proof_verifies**
   - "valid proof must verify" — proof verification returns false for a valid proof
   - Gas: 1039504
   - File: test/UltraHonkVerifier.t.sol

## RED/Expected Failures

1. **pvthfhe-pvss :: nizk_decrypt_soundness** (2 tests)
   - "Proof with wrong sk_i must be REJECTED (soundness violation). Currently accepted because derive_secret_share ignores witness data."
   - Stub protocol: derive_secret_share is a no-op placeholder

2. **pvthfhe-keygen :: dkg_correctness** (2 tests)
   - "decoded plaintext length 21203 exceeds max 16382"
   - Mock backend limitation on plaintext size

3. **pvthfhe-compressor :: sonobe_isolated_mem**
   - "RED phase: keep failing until the memory fix lands"
   - Test explicitly a RED gate test
