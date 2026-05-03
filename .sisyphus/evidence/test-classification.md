# Test Classification Audit

**Date:** 2026-05-03  
**Task:** T5 — Enumerate every test; classify REAL / WEAK / TRIVIAL / MOCK.

## Rubric

| Label | Criterion |
|-------|-----------|
| **REAL** | Exercises a cryptographic primitive end-to-end with non-trivial inputs AND checks an invariant that would fail if the primitive were broken. Key assertion quoted. |
| **WEAK** | Exercises primitive but only checks weak invariants (function returns, length, not value). |
| **TRIVIAL** | Smoke test, type check, roundtrip with degenerate inputs (zero/default). |
| **MOCK** | Tests against stub/mock implementation (`SURROGATE` or `MockBackend` paths that delegate to the mock). |

---

## Rust Tests (118 `#[test]` items)

### `crates/pvthfhe-core/tests/vectors.rs`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `all_golden_vectors` | **MOCK** | Uses `MockBackend` (SURROGATE). Checks `computed_pk.bytes != expected_pk`, ciphertext bytes, and `recovered != plaintext_bytes` — all against mock implementation that does not exercise real lattice crypto. If the primitive were broken, the mock would still match its own golden outputs. |

### `crates/pvthfhe-core/tests/noise_budget.rs`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `noise_budget_closes_honest` | **WEAK** | Simulates Gaussian noise aggregation in pure Rust (no FHE backend) and checks `aggregate_noise < budget_bound / SAFETY_DIVISOR`. The Gaussian sampler is hand-rolled (Box-Muller); the assertion is a Monte-Carlo bound, not a cryptographic invariant. The "honest" vs "malicious" distinction is absent in the implementation — both tests are identical code paths. |
| `noise_budget_closes_malicious` | **WEAK** | Identical simulation to `noise_budget_closes_honest` with a different RNG seed. No actual malicious behavior is modeled; the label is aspirational. Assertion: `aggregate_noise < budget_bound / SAFETY_DIVISOR`. |

### `crates/pvthfhe-core/tests/round_trip_props.rs`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `round_trip` (proptest, 10 000 cases) | **MOCK** | Uses `MockBackend`. Assertion: `prop_assert_eq!(recovered, plaintext)`. The round-trip property would still hold even if the underlying lattice operations were replaced by identity or XOR — the mock implementation satisfies it by construction. |

### `crates/pvthfhe-core/tests/tamper_props.rs`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `tampered_share_rejected` (proptest, 10 000 cases) | **MOCK** | Uses `MockBackend`. Asserts `prop_assert_ne!(recovered, plaintext, "tampered share produced correct plaintext (should be wrong)")` but only when `aggregate_decrypt` returns `Ok` — the mock implementation almost always returns `Err` after any byte-flip, making the `Ok` branch effectively dead. The tamper is genuine (`ds0.bytes[pos] ^= tamper_byte`), but the checked invariant is weak because the mock does not enforce lattice correctness. |

### `crates/pvthfhe-keygen-spec/tests/kat_roundtrip.rs`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `kat_vectors_roundtrip_and_derive_bfv_key` | **WEAK** | Tests JSON/wire serde roundtrips and one P4 BFV key derivation via `derive_bfv_public_key`. The serde assertions (`assert_eq!(session_from_trait, vector.session)`) check serialization identity, not cryptographic correctness. The key-derivation assertion `assert_eq!(derived, vector.derived_public_key)` is golden-file-based against spec structs whose correctness is unverified externally. No lattice primitives are exercised. |

### `crates/pvthfhe-keygen/tests/honest_run.rs`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `honest_n_of_n_no_blame` | **MOCK** | Uses `HermineAdapter` (Hermine is the surrogate DKG adapter). Checks `verify_transcript`, `public_verify`, `blame_dealing().is_none()`, and `quorum_key.bytes == all_key.bytes`. All invariants are implemented in the Hermine stub; no real PVSS or DKG cryptography is exercised. |

### `crates/pvthfhe-keygen/tests/adversarial.rs`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `forged_share_blames_forging_participant` | **MOCK** | Hermine stub. Mutates `shares[1].secret_value += 1`. Assertion: `blame.accused_id == shares[1].participant_id`. Hermine's blame logic is a hash-comparison shim, not a real PVSS blame protocol. |
| `replayed_share_from_other_session_is_rejected` | **MOCK** | Hermine stub. Assertion: `blame.accused_id == artifact.dealer_id`. Checks session-ID binding in a shim. |
| `malicious_dealer_bad_commitment_blames_dealer` | **MOCK** | Hermine stub. `artifact.commitments[0][0] ^= 0x55`. Assertion: `blame.accused_id == artifact.dealer_id`. |
| `colluding_below_threshold_cannot_reconstruct` | **MOCK** | Hermine stub. Assertion: `err.message().contains("threshold")`. |
| `abort_blame_correct_names_cheating_participant` | **MOCK** | Hermine stub. Sets `shares[2].commitment = Some(vec![0xAA; 32])`. Assertion: `blame.accused_id == shares[2].participant_id`. |
| `invalid_empty_commitment_artifact_is_rejected` | **MOCK** | Hermine stub with empty commitments. Assertion: `!verify_transcript(...)`. |
| `threshold_tampering_blames_cheating_participant` | **MOCK** | Hermine stub. `shares[0].threshold = Some(2)`. Assertion: `blame.accused_id == shares[0].participant_id`. |
| `duplicate_participant_id_is_rejected` | **MOCK** | Hermine stub. Assertion: `err.message().contains("duplicate participant id")`. |

### `crates/pvthfhe-keygen/tests/protocol_test.rs`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `t1_honest_n_of_n_keygen_yields_valid_bfv_public_key` | **MOCK** | Hermine stub. Assertion: `!key.bytes.is_empty()`. Only checks non-empty bytes, not cryptographic validity. |
| `t1_reconstruction_is_consistent_across_authorized_sets` | **MOCK** | Hermine stub. Assertion: `key_01.bytes == key_12.bytes == key_all.bytes`. Threshold secret sharing consistency — implemented trivially in Hermine stub. |
| `t2_reconstructed_key_does_not_expose_individual_shares` | **MOCK** | Hermine stub. Assertion: `key.bytes != val.to_be_bytes()`. Trivially true because the stub's key derivation XORs or hashes shares. |
| `t2_corrupted_view_stays_bound_to_public_transcript` | **MOCK** | Hermine stub. Sets `corrupted.commitment = Some(vec![0xff; 32])`. Assertion: `blame.is_some()`. |
| `t3_invalid_dealing_is_rejected_by_verify` | **MOCK** | Hermine stub. Empty commitments → `!valid`. |
| `t3_bad_commitment_transcript_does_not_verify` | **MOCK** | Hermine stub. Assertion: `!valid`. |
| `t4_cheating_dealer_produces_blame_proof` | **MOCK** | Hermine stub. `tampered_share.secret_value = Some(99_999_999)`. Assertions: `blame.is_some()`, `proof.reason == "commitment_mismatch"`, `proof.accused_id == Some(1)`. |
| `t4_blame_proof_names_guilty_dealer_not_honest_party` | **TRIVIAL** | Constructs a `BlameProof` directly with `accused_id: Some(7)` and asserts `accused_id == Some(7)`. No behavior is exercised. |
| `t5_session_state_advances_through_protocol_steps` | **MOCK** | Hermine stub. Checks `session.threshold == 2`, `shares.len() == 3`, `valid == true`, `!key.bytes.is_empty()`. |
| `t5_aborted_session_preserves_transition_invariants` | **MOCK** | Hermine stub. `bad_share.secret_value = Some(0)`. Assertion: `verify_transcript(artifact) == true` still holds after abort. |

### `crates/pvthfhe-fhe/tests/lattice_nizk.rs`

> **Note:** All tests in this file are gated `#[cfg(feature = "real-nizk")]`. The `RealNizkAdapter` does not exist as a non-stub at time of audit; the feature is unimplemented. If the feature is unavailable, **all 6 tests are compile-skipped** and never run.

| Test | Classification | Rationale |
|------|---------------|-----------|
| `test_honest_prove_verify` | **WEAK** | If `real-nizk` is enabled: proves and verifies. Assertion: `RealNizkAdapter::verify(...).is_ok()`. With the current unimplemented adapter this is MOCK/skip. Even if wired: checks only that verify returns Ok, not that the proof is sound. |
| `test_tampered_share_rejected` | **REAL** (conditional) | `witness.secret_share = 99` (tampers the secret). Assertion: `RealNizkAdapter::verify(...).is_err()`. If `real-nizk` is implemented, this is a meaningful soundness test. Currently compile-skipped → effectively MOCK. |
| `test_wrong_pvss_commitment_rejected` | **REAL** (conditional) | `statement.pvss_commitment = [0x55; 32]`. Assertion: `verify(...).is_err()`. Currently compile-skipped. |
| `test_batch_verify_correctness` | **WEAK** (conditional) | Only checks `batch_verify().is_ok()`. Does not verify individual proof content. |
| `test_proof_is_deterministic` | **WEAK** | Checks `proof_one.as_bytes() == proof_two.as_bytes()`. Determinism is an API property, not a cryptographic soundness invariant. |
| `test_verify_rejects_mismatched_participant_binding` | **REAL** (conditional) | `statement.participant_id = 8` (mismatch with witness). Assertion: `verify(...).is_err()`. Currently compile-skipped. |

### `crates/pvthfhe-fhe/tests/lattice_nizk_adversarial.rs`

> All tests gated `#[cfg(feature = "real-nizk")]`. Currently compile-skipped.

| Test | Classification | Rationale |
|------|---------------|-----------|
| `test_malformed_proof_bytes_rejected` | **WEAK** (conditional) | `proof_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF]`. Checks format rejection, not soundness. |
| `test_replay_across_sessions_rejected` | **REAL** (conditional) | Valid proof for `sess-A` submitted against `sess-B` statement (different `pvss_commitment`). Assertion: `verify(...).is_err()`. Tests session-binding property. Currently skipped. |
| `test_participant_id_substitution_rejected` | **REAL** (conditional) | Proof built for `participant_id=1`, verified against `participant_id=2` with different commitment. Assertion: `verify(...).is_err()`. |
| `test_wrong_q_parameter_rejected` | **REAL** (conditional) | `wrong_q_statement.params.0 = 65_539`. Assertion: `verify(...).is_err()`. Parameter-binding test. |
| `test_fs_challenge_tamper_rejected` | **REAL** (conditional) | `tampered_bytes[6] ^= 0x01`. Assertions: `Err(NizkError::VerificationFailed(_))`. Tests FS transcript integrity. |
| `test_truncated_proof_bytes_rejected` | **WEAK** (conditional) | Checks format-level rejection of short bytes. |
| `test_batch_with_one_bad_proof_rejected` | **REAL** (conditional) | `proofs[2].proof_bytes[6] ^= 0x01`. Assertion: `batch_verify(...).is_err()`. |
| `test_empty_proof_bytes_rejected` | **TRIVIAL** (conditional) | Empty bytes rejection is a format check. |

### `crates/pvthfhe-fhe/tests/conformance.rs`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `mock_load_params` | **TRIVIAL** | Loads params from TOML string, drops result. |
| `mock_round_trip` | **MOCK** | `MockBackend`. Assertion: `recovered == plaintext.as_ref()`. End-to-end with mock, not real lattice. |
| `mock_keygen_share_party_id` | **TRIVIAL** | Checks `share.party_id == 7`. Party-ID preservation, not crypto. |
| `mock_decrypt_share_party_id` | **TRIVIAL** | Checks `ds.party_id == 5`. |
| `mock_insufficient_shares` | **MOCK** | `MockBackend`. Checks `Err(FheError::InsufficientShares)` when threshold not met. Threshold enforcement is correct but relies on mock. |
| `primary_load_params` | **MOCK** | `FhersBackend` is SURROGATE (delegates to mock). |
| `primary_round_trip` | **MOCK** | `FhersBackend` SURROGATE. Same as `mock_round_trip` under the hood. Assertion: `recovered == plaintext.as_ref()`. |
| `primary_keygen_share_party_id` | **TRIVIAL** | `FhersBackend` SURROGATE. Checks party ID. |
| `primary_decrypt_share_party_id` | **TRIVIAL** | `FhersBackend` SURROGATE. Checks party ID. |
| `primary_insufficient_shares` | **MOCK** | `FhersBackend` SURROGATE. Same as `mock_insufficient_shares`. |

### `crates/pvthfhe-enclave-adapter/tests/smoke.rs`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `smoke_ciphernode_generate_key_share` | **TRIVIAL** | `MockBackend`. Asserts `share.is_ok()`. Smoke check for API. |
| `smoke_aggregator_aggregate_keys` | **TRIVIAL** | `MockBackend` with dummy `EnclaveKeyShare(i.to_le_bytes())`. Asserts `pk.is_ok()`. |
| `smoke_aggregator_aggregate_decrypt` | **TRIVIAL** | `MockBackend`. Asserts `result.is_ok()`. |

### `crates/pvthfhe-aggregator/tests/folding_n64.rs`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `test_folding_n64` | **WEAK** | `FoldingAccumulator` (old surrogate API). Checks `final_snark.proof_size_bytes > 0`, `prover_time_ms < 5000`, `public_inputs.len() == 64`. Does not check cryptographic content; timing bound is very loose. |

### `crates/pvthfhe-aggregator/tests/folding_tamper.rs`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `test_folding_tamper` | **WEAK** | Old `FoldingAccumulator` surrogate. Sets `nizk_bytes = vec![]` for party 42. Assertion: `Err(FoldingError::InvalidLeaf(42))`. Checks format rejection in a hash-chain surrogate, not a real ZK folding scheme. The tamper is genuine but the primitive is a SHA-256 hash chain. |

### `crates/pvthfhe-aggregator/tests/folding.rs`

> Gated `#[cfg(feature = "real-folding")]`.

| Test | Classification | Rationale |
|------|---------------|-----------|
| `test_fold_two_valid_p1_nizks_verifies` | **MOCK** | Hash-chain surrogate (`real-folding` = SHA-256). `verify_acc` checks session/params metadata, not lattice proof validity. |
| `test_fold_of_fold_verifies_depth_three` | **MOCK** | Hash-chain surrogate. Assertion: `acc3.fold_depth() == 3` and `verify_acc` passes. |
| `test_tampered_inner_proof_rejected` | **WEAK** | `wit.nizk_proof.proof_bytes[0] ^= 0xff`. Assertion: `result.is_err()`. The rejection is based on the uniformity check (all bytes must be identical in the surrogate), not cryptographic invalidity. The tamper is non-trivial, but the validator is a placeholder. |
| `test_wrong_fhe_param_across_folds_rejected` | **WEAK** | Different `n` parameter. Assertion: `result.is_err()`. Parameter binding in hash-chain surrogate. |
| `test_accumulator_binding` | **WEAK** | Different tag bytes produce different accumulators. Assertion: `left != right`. This is a determinism/collision-resistance property of SHA-256 rather than of a ZK accumulator. |
| `test_fold_determinism` | **TRIVIAL** | Same inputs produce same accumulator. Checks SHA-256 determinism. |

### `crates/pvthfhe-aggregator/tests/folding_adversarial.rs`

> Gated `#[cfg(feature = "real-folding")]`.

| Test | Classification | Rationale |
|------|---------------|-----------|
| `test_empty_proof_bytes_rejected` | **WEAK** | Empty `proof_bytes`. Assertion: `result.is_err()`. Format check on hash-chain surrogate. |
| `test_two_byte_non_uniform_proof_rejected` | **WEAK** | Non-uniform 2-byte vector triggers surrogate's uniformity validator. |
| `test_non_uniform_proof_bytes_rejected` | **WEAK** | Same uniformity check with 16-byte mixed vector. |
| `test_acc_wrong_session_id_rejected` | **WEAK** | `session-A` acc vs `session-B` stmt. Checks session ID string equality, not a cryptographic binding. |
| `test_acc_wrong_params_rejected` | **WEAK** | Different `n` parameter in acc vs stmt. |
| `test_statement_proof_mismatch_rejected` | **WEAK** | `make_witness(13)` vs `stmt` built with tag `12`. Uniformity check catches this. |
| `test_single_bit_flip_in_proof_rejected` | **WEAK** | Bit-flip triggers non-uniformity check. Not a FS challenge check. |
| `test_last_byte_flipped_in_proof_rejected` | **WEAK** | Same uniformity check. |
| `test_depth_bomb_fold_to_depth_10_exact` | **WEAK** | Folds 10 times, checks `fold_depth() == 10` and `verify_acc` passes. No cryptographic invariant. |
| `test_depth_bomb_fold_to_depth_12_exact` | **WEAK** | Same at depth 12. |
| `test_non_sequential_fold_index_rejected` | **WEAK** | Skips fold index 2 → 3. Assertion: `result.is_err()`. Checks sequence counter in surrogate. |
| `test_q_mismatch_across_fold_boundary_rejected` | **WEAK** | `q` mismatch after fold 1. |
| `test_n_mismatch_across_fold_boundary_rejected` | **WEAK** | `n` mismatch after fold 1. |
| `test_be_mismatch_across_fold_boundary_rejected` | **WEAK** | `B_e` mismatch after fold 1. |
| `test_stmt_from_session_a_folded_into_acc_from_session_b_rejected` | **WEAK** | Cross-session string mismatch. |
| `test_forged_acc_with_mismatched_session_and_params_rejected` | **WEAK** | Forged acc with wrong params. |
| `test_soundness_amplification_harness` | **TRIVIAL** | Pure arithmetic: `(1/3)^d` computed and compared. No FHE or ZK primitive invoked. Assertion: `(1/3)^10 <= 1.7e-5`. |

### `crates/pvthfhe-aggregator/tests/e2e_real.rs`

> Gated `#[cfg(feature = "real-verifier")]`. All constructions are surrogates: MockBackend (P1), hash-chain fold (P2), HMAC-SHA256 (P3 surrogate).

| Test | Classification | Rationale |
|------|---------------|-----------|
| `test_e2e_real_pipeline_p4_p1_p2_p3` | **MOCK** | Full pipeline test but every construction is a surrogate. P3 is HMAC-SHA256 not secp256k1 ecrecover. Assertions: `ok == true` (trusted key), `wrong_ok == false`, `tampered_ok == false`. The adversarial checks are non-trivial but over HMAC, not EVM ecrecover or real NIZK. |

### `crates/pvthfhe-aggregator/tests/p2_bench.rs`

> Gated `#[cfg(feature = "real-folding")]`.

| Test | Classification | Rationale |
|------|---------------|-----------|
| `bench_p2_n128` | **WEAK** | Timing benchmark, not a correctness test. Writes JSON output. No assertion on proof correctness. |
| `bench_p2_n512` | **WEAK** | Same. |
| `bench_p2_n1024` | **WEAK** | Same. |

### `crates/pvthfhe-aggregator/tests/keygen_honest.rs`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `honest_n4_keygen` | **MOCK** | `MockBackend` + `KeygenSimulator` (surrogate). Assertion: `matches!(result, KeygenResult::Complete(_))`. Only checks that keygen completes, not that the resulting key is cryptographically valid. |

### `crates/pvthfhe-aggregator/tests/keygen_malicious.rs`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `malformed_proof_blamed` | **MOCK** | `MockBackend` + `KeygenSimulator` with injected `FaultType::MalformedProof`. Assertion: `ids.contains(&0)`. The fault injection is in a simulator, not a real protocol. |
| `withhold_share_blamed` | **MOCK** | Same pattern for `FaultType::WithholdShare`. |
| `equivocate_blamed` | **MOCK** | Same pattern for `FaultType::Equivocate`. |

### `crates/pvthfhe-aggregator/tests/decrypt_roundtrip.rs`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `decrypt_roundtrip_golden` | **MOCK** | `MockBackend`. Loads `vector_01.json`. Assertion: `recovered == expected_plaintext`. Same as `all_golden_vectors` but via `decrypt` module. Mock golden test. |

### `crates/pvthfhe-aggregator/tests/decrypt_rejections.rs`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `rejects_malformed_share` | **MOCK** | `MockBackend`. Clears `share1.nizk`. Assertion: `Err(DecryptError::InvalidShare { party_id: 1 })`. Checks the aggregator's NIZK-presence check, but the NIZK itself is never verified — MockBackend always returns empty NIZK bytes. |
| `rejects_insufficient_shares` | **MOCK** | `MockBackend`. Assertion: `Err(DecryptError::InsufficientShares { needed: 2, got: 1 })`. |
| `rejects_duplicate_party` | **MOCK** | `MockBackend`. Assertion: `Err(DecryptError::DuplicateParty(1))`. |
| `rejects_unknown_party` | **MOCK** | `MockBackend`. Assertion: `Err(DecryptError::UnknownParty(4))`. |

### `crates/pvthfhe-aggregator/tests/adversarial/` (mod + sub-modules)

| Test | File | Classification | Rationale |
|------|------|---------------|-----------|
| `adversarial_tampered_share_nizk_is_rejected` | `tampered_share.rs` | **MOCK** | `MockBackend`. `shares[0].nizk = vec![0]`. Assertion: `Err(DecryptError::InvalidShare { party_id: 1 })`. Checks NIZK format (non-empty present → must pass length check or hash). Mock backend. |
| `adversarial_tampered_ciphertext_hash_is_rejected` | `tampered_ciphertext.rs` | **MOCK** | `shares[0].ciphertext_hash[0] ^= 0xFF`. Assertion: `Err(DecryptError::InvalidShare { party_id: 1 })`. Hash binding check in aggregator — meaningful protocol check but on MockBackend. |
| `adversarial_replayed_share_is_rejected_as_duplicate_party` | `replay.rs` | **MOCK** | Duplicate share. Assertion: `Err(DecryptError::DuplicateParty(1))`. |
| `adversarial_equivocation_blames_party_one` | `equivocation.rs` | **MOCK** | `KeygenSimulator` surrogate. `FaultType::Equivocate`. Assertion: blamed contains party 1. |
| `adversarial_malformed_nizk_blames_party_zero` | `malformed_nizk.rs` | **MOCK** | `KeygenSimulator` surrogate. `FaultType::MalformedProof`. |
| `adversarial_rogue_key_fault_blames_party_zero` | `rogue_key.rs` | **MOCK** | Uses `FaultType::MalformedProof` (mislabeled as rogue_key). No actual rogue-key attack is modeled. `KeygenSimulator` surrogate. |
| `adversarial_threshold_above_accepts_more_than_t_shares` | `threshold_above.rs` | **MOCK** | `MockBackend`. Assertion: `recovered == fixture.plaintext`. Accepts t+1 shares. |
| `adversarial_threshold_below_rejects_t_minus_one_shares` | `threshold_below.rs` | **MOCK** | `MockBackend`. Assertion: `Err(DecryptError::InsufficientShares { needed, got }) if ...`. |
| `adversarial_withhold_reveal_blames_party_two` | `withhold_reveal.rs` | **MOCK** | `KeygenSimulator` surrogate. `FaultType::WithholdShare`. |

---

## Solidity Tests (39 `function test*` items)

### `contracts/test/Placeholder.t.sol`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `test_placeholder` | **TRIVIAL** | Returns `true`. No behavior tested. |

### `contracts/test/SmokeTest.t.sol`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `test_fixtures_initialized` | **TRIVIAL** | Checks `SAMPLE_EPOCH == 1` and `SAMPLE_HASH != bytes32(0)`. Fixture sanity check. |

### `contracts/test/PvtFheVerifier.t.sol`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `test_abi_signature` | **TRIVIAL** | Calls `verify()` with zero inputs. Assertion: surrogate returns `true`. Tests ABI shape only. |
| `test_gas_budget` | **TRIVIAL** | `gasUsed < 5_000_000`. Gas measurement on surrogate verifier. |
| `test_tampered_proof_reverts_or_returns_false` | **TRIVIAL** | Surrogate always returns `true` regardless of proof. Comment explicitly says "trivially passes." |
| `test_valid_proof_accepted` | **TRIVIAL** | Surrogate returns `true`. Comment: "TODO(T39)". |
| `test_threshold_value` | **TRIVIAL** | `threshold() == 4097`. Constant check. |
| `test_rlwe_degree_value` | **TRIVIAL** | `rlweDegree() == 8192`. Constant check. |
| `test_interface_compliance` | **TRIVIAL** | Interface cast compiles and surrogate returns `true`. |

### `contracts/test/PvtFheVerifier.e2e.t.sol`

> Reads `test/goldens/honest.proof` and `test/goldens/tampered.proof` via `vm.readFileBinary`. These files may not exist in CI, causing the test to fail during setup rather than during assertion.

| Test | Classification | Rationale |
|------|---------------|-----------|
| `test_honest_proof_verifies` | **WEAK** | Uses `HonkVerifier` (generated). Assertion: `result == true`. If golden files exist and verifier is real BB-generated, this would be REAL. Currently the golden-file dependency is fragile. |
| `test_tampered_proof_reverts` | **WEAK** | Reads tampered golden. Assertion: `result == false`. Same fragility; if files exist this tests soundness but the file-generation provenance is unverified. |
| `test_gas_under_5m` | **TRIVIAL** | Gas measurement on HonkVerifier. |

### `contracts/test/KzgBatchVerifier.t.sol`

> `KzgBatchVerifier` uses an internal BN254 pairing surrogate — it calls the EVM `ecPairing` precompile but generates both proof and pubInputs internally via `sampleProof`/`samplePubInputs`. The verifier checks `e(commitment, g2_1) == e(quotient, tau_g2)` pairing but uses randomly sampled points that satisfy the equation by construction.

| Test | Classification | Rationale |
|------|---------------|-----------|
| `testHonestVerifies` | **WEAK** | `_assertVerify(n, true)` at sizes 1,8,32,128. Passes self-generated samples through verifier. No external KZG witness. |
| `testTamperedRejects` | **WEAK** | `_assertVerify(n, false)` — adds 1 to `values[0]` before verify. Assertion: `!ok`. Tests that the pairing equation breaks when a public input value is incremented — a meaningful check but over internally-generated samples. |
| `testGas_verifyBatch_1` | **TRIVIAL** | Gas call, no assertion. |
| `testGas_verifyBatch_8` | **TRIVIAL** | Gas call, no assertion. |
| `testGas_verifyBatch_32` | **TRIVIAL** | Gas call, no assertion. |
| `testGas_verifyBatch_128` | **TRIVIAL** | Gas call, no assertion. |

### `contracts/test/RealVerifier.t.sol`

> Uses `P3RealVerifier` (ECDSA ecrecover over keccak256(publicInputs) against a hardcoded Anvil key). The secp256k1 ecrecover precompile is a real EVM precompile.

| Test | Classification | Rationale |
|------|---------------|-----------|
| `test_honest_proof_verifies` | **REAL** | Real secp256k1 ECDSA via `vm.sign`. Assertion: `assertTrue(ok, "honest proof must verify")`. Would fail if ecrecover or signature generation were broken. **Note**: verifier is a trusted-signer authenticator, not an FHE soundness verifier — see P3VacuityProof. |
| `test_tampered_proof_rejects` | **REAL** | Flips byte 10 of the signature. Assertion: `assertFalse(ok, "tampered proof must not verify")`. Tests ecrecover's sensitivity to signature corruption. |
| `test_wrong_public_inputs_rejects` | **REAL** | Different ciphertext hash in PI. Assertion: `assertFalse(ok, ...)`. Tests that digest commitment binds to PI content. |
| `test_gas_within_budget` | **TRIVIAL** | `gasUsed <= 5_000_000`. Gas measurement. |
| `test_blame_event_on_rejection` | **REAL** | `vm.expectEmit` on `ProofRejected` event. Assertion: event emitted with correct `inputsHash`, `proofHash`, attempt count. Tests router blame logic on bad proof. |
| `test_determinism_across_resubmissions` | **TRIVIAL** | `r1 == r2` from two identical calls. Determinism of pure function. |

### `contracts/test/RealVerifierAdversarial.t.sol`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `test_adv_empty_proof_rejected` | **REAL** | Empty bytes proof. Assertion: `assertFalse(ok)`. Checks length guard in ecrecover path. |
| `test_adv_64byte_proof_rejected` | **REAL** | 64-byte (one short of 65). Assertion: `assertFalse(ok)`. |
| `test_adv_wrong_signer_rejected` | **REAL** | Proof signed by Anvil key #1 instead of #0. Assertion: `assertFalse(ok, "proof from wrong signer must be rejected")`. Tests ecrecover signer identity check. |
| `test_adv_invalid_v_rejected` | **REAL** | `v = 2` raw (normalizes to 29, fails 27/28 guard). Assertion: `assertFalse(ok)`. |
| `test_adv_r_zero_rejected` | **REAL** | `r = bytes32(0)`. Assertion: `assertFalse(ok)`. Tests ecrecover address(0) guard. |
| `test_adv_s_zero_rejected` | **REAL** | `s = bytes32(0)`. Assertion: `assertFalse(ok)`. |
| `test_adv_wrong_pubinputs_length_rejected` | **REAL** | 199-byte PI. Assertion: `assertFalse(ok)`. Length guard. |
| `test_adv_too_long_pubinputs_rejected` | **REAL** | 201-byte PI. Assertion: `assertFalse(ok)`. |
| `test_adv_replay_deterministic` | **TRIVIAL** | `r1 == r2`. Determinism check. |
| `test_adv_gas_griefing_large_proof` | **REAL** | 14 KB garbage proof. Assertions: `assertFalse(ok)` and `gasUsed <= 5_000_000`. Tests early-exit on oversized inputs. |
| `test_adv_cross_input_reuse_rejected` | **REAL** | Proof for PI_A submitted against PI_B. Assertion: `assertFalse(ok, "proof for A must not verify against B")`. Tests digest binding. |
| `test_adv_tampered_r_rejected` | **REAL** | `tampered[5] ^= 0xff`. Assertion: `assertFalse(ok)`. |
| `test_adv_tampered_s_rejected` | **REAL** | `tampered[40] ^= 0xff`. Assertion: `assertFalse(ok)`. |
| `test_adv_router_emits_proof_rejected` | **REAL** | `badProof[0] ^= 0xff`. `vm.expectEmit` on `ProofRejected`. Tests router blame on adversarial proof. |

### `contracts/test/P3VacuityProof.t.sol`

| Test | Classification | Rationale |
|------|---------------|-----------|
| `testVacuousVerifierAcceptsFalseClaim` | **REAL** | Assertion: `assertTrue(accepted, "VACUITY: verifier accepted fabricated FHE result; ...")`. This is an **audit evidence** test that intentionally passes to document a vulnerability: the trusted-signer can attest to arbitrary false FHE results. The assertion exposes the P3 verifier's vacuity. |

---

## Summary: Per-Construction Classification

### Construction P1 — Lattice NIZK Well-Formedness

Tests are in `crates/pvthfhe-fhe/tests/lattice_nizk*.rs`, all gated `#[cfg(feature = "real-nizk")]`. The `real-nizk` feature is currently unimplemented.

| Classification | Count |
|---------------|-------|
| REAL (conditional, compile-skipped) | 7 |
| WEAK (conditional, compile-skipped) | 5 |
| TRIVIAL | 1 |
| **REAL that actually runs** | **0** |

### Construction P2 — LatticeFold+ Accumulation (Surrogate: SHA-256 hash chain)

Tests in `crates/pvthfhe-aggregator/tests/folding*.rs`, gated `real-folding`.

| Classification | Count |
|---------------|-------|
| REAL | 0 |
| WEAK | 18 |
| TRIVIAL | 2 |
| MOCK | 3 |

### Construction P3 — On-Chain Verifier (ECDSA ecrecover surrogate)

Tests in `contracts/test/RealVerifier.t.sol`, `RealVerifierAdversarial.t.sol`, `P3VacuityProof.t.sol`.

| Classification | Count |
|---------------|-------|
| REAL | 18 |
| WEAK | 0 |
| TRIVIAL | 5 |
| MOCK | 0 |

**Critical note:** All 18 REAL tests validate the ECDSA authenticator, not FHE correctness. `P3VacuityProof.t.sol` explicitly proves the verifier cannot distinguish correct from fabricated FHE outputs.

### Construction P4 — Threshold Keygen (Hermine / KeygenSimulator surrogate)

Tests in `crates/pvthfhe-keygen/tests/`, `crates/pvthfhe-aggregator/tests/keygen_*.rs`, `adversarial/`.

| Classification | Count |
|---------------|-------|
| REAL | 0 |
| WEAK | 0 |
| TRIVIAL | 2 |
| MOCK | 24 |

### Other / Cross-Construction

Conformance, vectors, noise budget, enclave smoke, e2e_real:

| Classification | Count |
|---------------|-------|
| REAL | 0 |
| WEAK | 4 |
| TRIVIAL | 14 |
| MOCK | 16 |

---

## Overall Totals

| Classification | Rust | Solidity | Total |
|---------------|------|----------|-------|
| REAL (actually runs) | 0 | 18 | **18** |
| REAL (compile-skipped) | 7 | 0 | 7 |
| WEAK | 22 | 4 | **26** |
| TRIVIAL | 19 | 14 | **33** |
| MOCK | 77 | 0 | **77** |
| **Total** | **118** | **39** | **157** |

> **Key finding:** Zero Rust tests for cryptographic primitives P1–P4 qualify as REAL in the current build. All P4 (keygen) and P2 (folding) tests are MOCK or WEAK against surrogate/stub implementations. P1 tests would be REAL if `real-nizk` were implemented. The only REAL tests are the 18 Solidity P3 ecrecover tests — which validate the ECDSA authenticator, not FHE soundness (see P3VacuityProof).
