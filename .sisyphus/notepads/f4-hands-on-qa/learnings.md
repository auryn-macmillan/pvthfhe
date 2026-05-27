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
| 7 | pvthfhe-compressor | FAIL | 1 failed in nova_isolated_mem (RED phase — "keep failing until the memory fix lands") |
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

## F4 QA: D.1 Lattice-Native BFV Encryption Proof — 2026-05-12

### Demo (e2e real crypto, n=10, t=4, seed=1)

**Command:** `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo run --release -p pvthfhe-cli --features "nova-compressor,demo-seeded-rng" -- demo --n 10 --threshold 4 --seed 1`

| Check | Result | Evidence |
|-------|--------|----------|
| Exit code | 0 | Clean exit |
| plaintext_roundtrip | OK | "plaintext_roundtrip: OK" |
| verify | ACCEPT | "verify: ACCEPT", "demo complete: ACCEPT" |
| All 9 steps | PASS | keygen → nizk_prove → nizk_verify → pvss_share_encrypt → cyclo_fold → compressor_prove → compressor_verify → partial_decrypt → aggregate_decrypt |
| Real BFV crypto | CONFIRMED | FHE-ENCODE/DECRYPT with lattice-pvss-bfv-d2 backend, n=8192 slots |
| Timing | ~5.4s total | keygen=28ms, encrypt/enc-proof=295ms, fold=1ms, compress=2402ms proof+598ms verify, decrypt=26ms |

### Focused Tests (pvthfhe-pvss nizk_share)

**Command:** `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-pvss --test nizk_share_soundness --test nizk_share_fs_binding --test nizk_share_real_verify --test nizk_share_batched_tracks`

| Test Binary | Tests | Result |
|-------------|-------|--------|
| nizk_share_soundness | 6 | PASS (6/6) |
| nizk_share_fs_binding | 2 | PASS (2/2) |
| nizk_share_real_verify | 2 | PASS (2/2) |
| nizk_share_batched_tracks | 5 | PASS (5/5) |
| **Total** | **15** | **ALL PASS** |

### Warnings (non-blocking)
- Mock backend warning from pvthfhe-fhe crate (not used by demo; demo uses real fhe.rs)
- Unused variables/methods (cosmetic)
- Missing docs (cosmetic)
- Deprecated HermineAdapter (known F60 finding)
- Seed flag warning (known R3.6 limitation)
- Dead code in test files (cosmetic)

