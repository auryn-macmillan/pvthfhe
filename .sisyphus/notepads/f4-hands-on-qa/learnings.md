## F4 QA Test Matrix Results — 2026-05-09

### Rust Crate Tests

| # | Crate | Result | Details |
|---|-------|--------|---------|
| 1 | pvthfhe-cyclo --lib | PASS | 0 tests |
| 2 | pvthfhe-pvss | FAIL | 2 failed in nizk_decrypt_soundness (RED tests — stubs, derive_secret_share ignores witness) |
| 3 | pvthfhe-fhe | FAIL | 1 failed in encoding_golden: encoding_golden_real_ascii_roundtrip — recovered plaintext != original |
| 4 | pvthfhe-keygen | FAIL | 2 failed in dkg_correctness: mock backend limitation — "decoded plaintext length 21203 exceeds max 16382" |
| 5 | pvthfhe-nizk --lib | PASS | 0 tests |
| 6 | pvthfhe-aggregator --lib | PASS | 0 tests |
| 7 | pvthfhe-compressor | FAIL | 1 failed in sonobe_isolated_mem (RED phase — "keep failing until the memory fix lands") |
| 8 | cargo build | PASS | Workspace compiles |

### Contracts (Forge)

| # | Test | Result | Details |
|---|------|--------|---------|
| 9 | forge test --root contracts | FAIL | 104 passed, 1 failed: UltraHonkVerifierTest::test_valid_proof_verifies |

### Circuits (Noir)

| # | Test | Result | Details |
|---|------|--------|---------|
| 10 | nargo test | PASS | 22 tests all passed |

### Summary

- 5/10 checks passed (50%)
- 3 false failures (RED tests / stub-protocol expected failures: pvss nizk_soundness, keygen dkg, compressor mem)
- 2 genuine failures: encoding_golden_roundtrip (fhe), UltraHonkVerifier valid_proof (forge)
- forge: 104/105 pass — meets "104+" threshold but not ideal
