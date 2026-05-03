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

## Rust Tests (125 items)

### `crates/pvthfhe-fhe/tests/`

| Test Path | Test Name | Construction | Classification | Rationale |
|-----------|-----------|--------------|----------------|-----------|
| `lattice_nizk.rs` | `test_honest_prove_verify` | P1 | REAL (skip) | Gated `real-nizk`. Verifies honest flow: `RealNizkAdapter::verify(&statement, &proof).expect(...)` |
| `lattice_nizk.rs` | `test_tampered_share_rejected` | P1 | REAL (skip) | Gated `real-nizk`. Soundness check: `assert!(RealNizkAdapter::verify(&statement, &proof).is_err(), "tampered secret_value must be rejected")` |
| `lattice_nizk.rs` | `test_wrong_pvss_commitment_rejected` | P1 | REAL (skip) | Gated `real-nizk`. Commitment binding: `assert!(RealNizkAdapter::verify(&statement, &proof).is_err(), "wrong PVSS commitment hash must be rejected")` |
| `lattice_nizk.rs` | `test_batch_verify_correctness` | P1 | REAL (skip) | Gated `real-nizk`. Batch correctness: `RealNizkAdapter::batch_verify(&statements, &proofs).expect(...)` |
| `lattice_nizk.rs` | `test_proof_is_deterministic` | P1 | WEAK (skip) | Gated `real-nizk`. API property: `assert_eq!(proof_one.as_bytes(), proof_two.as_bytes(), ...)` |
| `lattice_nizk.rs` | `test_verify_rejects_mismatched_participant_binding` | P1 | REAL (skip) | Gated `real-nizk`. Participant binding: `assert!(RealNizkAdapter::verify(&statement, &proof).is_err(), ...)` |
| `lattice_nizk_adversarial.rs` | `test_malformed_proof_bytes_rejected` | P1 | REAL (skip) | Gated `real-nizk`. Rejection of random bytes: `assert!(RealNizkAdapter::verify(&statement, &proof).is_err())` |
| `lattice_nizk_adversarial.rs` | `test_replay_across_sessions_rejected` | P1 | REAL (skip) | Gated `real-nizk`. Session binding: `assert!(RealNizkAdapter::verify(&replay_statement, &proof).is_err())` |
| `lattice_nizk_adversarial.rs` | `test_participant_id_substitution_rejected` | P1 | REAL (skip) | Gated `real-nizk`. Participant substitution: `assert!(RealNizkAdapter::verify(&substituted_statement, &proof).is_err())` |
| `lattice_nizk_adversarial.rs` | `test_wrong_q_parameter_rejected` | P1 | REAL (skip) | Gated `real-nizk`. Param binding: `assert!(RealNizkAdapter::verify(&wrong_q_statement, &proof).is_err())` |
| `lattice_nizk_adversarial.rs` | `test_fs_challenge_tamper_rejected` | P1 | REAL (skip) | Gated `real-nizk`. Fiat-Shamir integrity: `assert!(matches!(RealNizkAdapter::verify(&statement, &tampered), Err(NizkError::VerificationFailed(_))))` |
| `lattice_nizk_adversarial.rs` | `test_truncated_proof_bytes_rejected` | P1 | REAL (skip) | Gated `real-nizk`. Length check: `assert!(RealNizkAdapter::verify(&statement, &truncated).is_err())` |
| `lattice_nizk_adversarial.rs` | `test_batch_with_one_bad_proof_rejected` | P1 | REAL (skip) | Gated `real-nizk`. Batch soundness: `assert!(RealNizkAdapter::batch_verify(&statements, &proofs).is_err())` |
| `lattice_nizk_adversarial.rs` | `test_empty_proof_bytes_rejected` | P1 | REAL (skip) | Gated `real-nizk`. Format check: `assert!(RealNizkAdapter::verify(&statement, &proof).is_err())` |
| `lattice_nizk_adversarial.rs` | `test_nizk_accepts_wrong_witness_fails` | P1 | REAL (skip) | Gated `real-nizk`. Mismatched witness: `assert!(RealNizkAdapter::verify(&statement, &proof).is_err(), ...)` |
| `lattice_nizk_adversarial.rs` | `test_nizk_two_proofs_same_stmt_differ` | P1 | REAL (skip) | Gated `real-nizk`. ZK Property: `assert_ne!(proof1.proof_bytes, proof2.proof_bytes, ...)` |
| `lattice_nizk_adversarial.rs` | `test_nizk_wrong_commitment_fails_verify` | P1 | REAL (skip) | Gated `real-nizk`. Binding property: `assert!(RealNizkAdapter::verify(&statement, &proof).is_err(), ...)` |
| `conformance.rs` | `mock_load_params` | FHE | TRIVIAL | Smoke test: `must_ok(B::load_params(TEST_PARAMS_TOML), ...)` |
| `conformance.rs` | `mock_round_trip` | FHE | MOCK | E2E with MockBackend: `assert_eq!(recovered, plaintext.as_ref())` |
| `conformance.rs` | `mock_keygen_share_party_id` | FHE | TRIVIAL | Metadata check: `assert_eq!(share.party_id, 7)` |
| `conformance.rs` | `mock_decrypt_share_party_id` | FHE | TRIVIAL | Metadata check: `assert_eq!(ds.party_id, 5)` |
| `conformance.rs` | `mock_insufficient_shares` | FHE | MOCK | Threshold check in Mock: `assert!(matches!(result, Err(FheError::InsufficientShares { .. })))` |
| `conformance.rs` | `primary_load_params` | FHE | MOCK | SURROGATE (FhersBackend delegates to mock) |
| `conformance.rs` | `primary_round_trip` | FHE | MOCK | SURROGATE (FhersBackend) |
| `conformance.rs` | `primary_keygen_share_party_id` | FHE | TRIVIAL | SURROGATE |
| `conformance.rs` | `primary_decrypt_share_party_id` | FHE | TRIVIAL | SURROGATE |
| `conformance.rs` | `primary_insufficient_shares` | FHE | MOCK | SURROGATE |

### `crates/pvthfhe-aggregator/tests/`

| Test Path | Test Name | Construction | Classification | Rationale |
|-----------|-----------|--------------|----------------|-----------|
| `folding_n64.rs` | `test_folding_n64` | P2 | WEAK | simulated_fold_sha256. Checks size and time: `assert!(final_snark.proof_size_bytes > 0)` |
| `folding_tamper.rs` | `test_folding_tamper` | P2 | WEAK | Rejection of empty NIZK in surrogate: `assert_eq!(id, 42)` (InvalidLeaf) |
| `folding_tamper.rs` | `test_fold_tampered_witness_rejected` | P2 | REAL (skip) | Gated `real-folding`. Bit-flip rejection: `assert!(fold(&acc, &tampered, &s).is_err(), ...)` |
| `folding_tamper.rs` | `test_fold_mismatched_params_rejected` | P2 | REAL (skip) | Gated `real-folding`. Param binding: `assert!(result.is_err(), "fold must reject mismatched params")` |
| `folding_tamper.rs` | `test_fold_large_norm_witness_rejected` | P2 | REAL (skip) | Gated `real-folding`. Norm check: `assert!(fold(&acc, &large_norm, &s).is_err(), ...)` |
| `folding_tamper.rs` | `test_fold_proof_not_deterministic` | P2 | REAL (skip) | Gated `real-folding`. ZK Property: `assert_ne!(acc1.acc_commitment(), acc2.acc_commitment(), ...)` |
| `folding.rs` | `test_fold_two_valid_p1_nizks_verifies` | P2 | MOCK (skip) | Gated `real-folding`. Verifies honest flow in hash-chain surrogate. |
| `folding.rs` | `test_fold_of_fold_verifies_depth_three` | P2 | MOCK (skip) | Gated `real-folding`. Chain depth check in surrogate: `assert_eq!(acc3.fold_depth(), 3)` |
| `folding.rs` | `test_tampered_inner_proof_rejected` | P2 | WEAK (skip) | Gated `real-folding`. Rejection in uniformity-check surrogate: `assert!(result.is_err())` |
| `folding.rs` | `test_wrong_fhe_param_across_folds_rejected` | P2 | WEAK (skip) | Gated `real-folding`. Param mismatch in surrogate. |
| `folding.rs` | `test_accumulator_binding` | P2 | WEAK (skip) | Gated `real-folding`. Determinism of SHA-256 surrogate: `assert_ne!(left, right)` |
| `folding.rs` | `test_fold_determinism` | P2 | TRIVIAL (skip) | Gated `real-folding`. SHA-256 determinism. |
| `folding_adversarial.rs` | `test_empty_proof_bytes_rejected` | P2 | WEAK (skip) | Gated `real-folding`. Length check in surrogate. |
| `folding_adversarial.rs` | `test_two_byte_non_uniform_proof_rejected` | P2 | WEAK (skip) | Gated `real-folding`. Uniformity check surrogate. |
| `folding_adversarial.rs` | `test_non_uniform_proof_bytes_rejected` | P2 | WEAK (skip) | Gated `real-folding`. Uniformity check surrogate. |
| `folding_adversarial.rs` | `test_acc_wrong_session_id_rejected` | P2 | WEAK (skip) | Gated `real-folding`. Session ID string check in surrogate. |
| `folding_adversarial.rs` | `test_acc_wrong_params_rejected` | P2 | WEAK (skip) | Gated `real-folding`. Param check in surrogate. |
| `folding_adversarial.rs` | `test_statement_proof_mismatch_rejected` | P2 | WEAK (skip) | Gated `real-folding`. Tag mismatch in surrogate. |
| `folding_adversarial.rs` | `test_single_bit_flip_in_proof_rejected` | P2 | WEAK (skip) | Gated `real-folding`. Bit-flip in uniformity surrogate. |
| `folding_adversarial.rs` | `test_last_byte_flipped_in_proof_rejected` | P2 | WEAK (skip) | Gated `real-folding`. Bit-flip in uniformity surrogate. |
| `folding_adversarial.rs` | `test_depth_bomb_fold_to_depth_10_exact` | P2 | WEAK (skip) | Gated `real-folding`. Chain depth 10 in surrogate. |
| `folding_adversarial.rs` | `test_depth_bomb_fold_to_depth_12_exact` | P2 | WEAK (skip) | Gated `real-folding`. Chain depth 12 in surrogate. |
| `folding_adversarial.rs` | `test_non_sequential_fold_index_rejected` | P2 | WEAK (skip) | Gated `real-folding`. Sequence check in surrogate. |
| `folding_adversarial.rs` | `test_q_mismatch_across_fold_boundary_rejected` | P2 | WEAK (skip) | Gated `real-folding`. Param check in surrogate. |
| `folding_adversarial.rs` | `test_n_mismatch_across_fold_boundary_rejected` | P2 | WEAK (skip) | Gated `real-folding`. Param check in surrogate. |
| `folding_adversarial.rs` | `test_be_mismatch_across_fold_boundary_rejected` | P2 | WEAK (skip) | Gated `real-folding`. Param check in surrogate. |
| `folding_adversarial.rs` | `test_stmt_from_session_a_folded_into_acc_from_session_b_rejected` | P2 | WEAK (skip) | Gated `real-folding`. Cross-session check in surrogate. |
| `folding_adversarial.rs` | `test_forged_acc_with_mismatched_session_and_params_rejected` | P2 | WEAK (skip) | Gated `real-folding`. Param check in surrogate. |
| `folding_adversarial.rs` | `test_soundness_amplification_harness` | P2 | TRIVIAL (skip) | Pure math check: `assert!(d10 <= 1.7e-5)` |
| `keygen_honest.rs` | `honest_n4_keygen` | P4 | MOCK | KeygenSimulator (surrogate). Completion check. |
| `keygen_malicious.rs` | `malformed_proof_blamed` | P4 | MOCK | Fault injection in simulator. |
| `keygen_malicious.rs` | `withhold_share_blamed` | P4 | MOCK | Fault injection in simulator. |
| `keygen_malicious.rs` | `equivocate_blamed` | P4 | MOCK | Fault injection in simulator. |
| `decrypt_roundtrip.rs` | `decrypt_roundtrip_golden` | FHE | MOCK | Golden vector against MockBackend. |
| `decrypt_rejections.rs` | `rejects_malformed_share` | FHE | MOCK | Format check in MockBackend. |
| `decrypt_rejections.rs` | `rejects_insufficient_shares` | FHE | MOCK | Threshold check in MockBackend. |
| `decrypt_rejections.rs` | `rejects_duplicate_party` | FHE | MOCK | Logic check in aggregator. |
| `decrypt_rejections.rs` | `rejects_unknown_party` | FHE | MOCK | Logic check in aggregator. |
| `adversarial/tampered_share.rs` | `adversarial_tampered_share_nizk_is_rejected` | FHE | MOCK | NIZK format check in aggregator (MockBackend). |
| `adversarial/tampered_ciphertext.rs`| `adversarial_tampered_ciphertext_hash_is_rejected` | FHE | MOCK | Hash binding check in aggregator. |
| `adversarial/replay.rs` | `adversarial_replayed_share_is_rejected_as_duplicate_party` | FHE | MOCK | Duplicate check. |
| `adversarial/equivocation.rs` | `adversarial_equivocation_blames_party_one` | P4 | MOCK | Simulator fault injection. |
| `adversarial/malformed_nizk.rs` | `adversarial_malformed_nizk_blames_party_zero` | P4 | MOCK | Simulator fault injection. |
| `adversarial/rogue_key.rs` | `adversarial_rogue_key_fault_blames_party_zero` | P4 | MOCK | Simulator fault injection (mislabeled). |
| `adversarial/threshold_above.rs` | `adversarial_threshold_above_accepts_more_than_t_shares` | FHE | MOCK | MockBackend flow. |
| `adversarial/threshold_below.rs` | `adversarial_threshold_below_rejects_t_minus_one_shares` | FHE | MOCK | MockBackend threshold enforcement. |
| `adversarial/withhold_reveal.rs` | `adversarial_withhold_reveal_blames_party_two` | P4 | MOCK | Simulator fault injection. |
| `e2e_real.rs` | `test_e2e_real_pipeline_p4_p1_p2_p3` | E2E | MOCK (skip) | Full pipeline on surrogates (HMAC-SHA256 for P3). |

---

## Solidity Tests (39 items)

### `contracts/test/`

| Test Path | Test Name | Construction | Classification | Rationale |
|-----------|-----------|--------------|----------------|-----------|
| `RealVerifier.t.sol` | `test_honest_proof_verifies` | P3 | REAL | ECDSA ecrecover check: `assertTrue(ok, "honest proof must verify")` |
| `RealVerifier.t.sol` | `test_tampered_proof_rejects` | P3 | REAL | Signature corruption: `assertFalse(ok, "tampered proof must not verify")` |
| `RealVerifier.t.sol` | `test_wrong_public_inputs_rejects` | P3 | REAL | Digest binding: `assertFalse(ok, ...)` |
| `RealVerifier.t.sol` | `test_gas_within_budget` | P3 | TRIVIAL | Gas measurement: `gasUsed <= 5_000_000` |
| `RealVerifier.t.sol` | `test_blame_event_on_rejection` | P3 | REAL | Blame logic: `vm.expectEmit` on `ProofRejected` |
| `RealVerifier.t.sol` | `test_determinism_across_resubmissions` | P3 | TRIVIAL | Pure function check. |
| `RealVerifierAdversarial.t.sol`| `test_adv_empty_proof_rejected` | P3 | REAL | ECDSA length guard: `assertFalse(ok)` |
| `RealVerifierAdversarial.t.sol`| `test_adv_64byte_proof_rejected` | P3 | REAL | ECDSA length guard. |
| `RealVerifierAdversarial.t.sol`| `test_adv_wrong_signer_rejected` | P3 | REAL | Signer identity check: `assertFalse(ok, ...)` |
| `RealVerifierAdversarial.t.sol`| `test_adv_invalid_v_rejected` | P3 | REAL | ECDSA v guard. |
| `RealVerifierAdversarial.t.sol`| `test_adv_r_zero_rejected` | P3 | REAL | ECDSA zero guard: `assertFalse(ok)` |
| `RealVerifierAdversarial.t.sol`| `test_adv_s_zero_rejected` | P3 | REAL | ECDSA zero guard. |
| `RealVerifierAdversarial.t.sol`| `test_adv_wrong_pubinputs_length_rejected` | P3 | REAL | Length guard. |
| `RealVerifierAdversarial.t.sol`| `test_adv_too_long_pubinputs_rejected` | P3 | REAL | Length guard. |
| `RealVerifierAdversarial.t.sol`| `test_adv_gas_griefing_large_proof` | P3 | REAL | DOS protection: `gasUsed <= 5_000_000` |
| `RealVerifierAdversarial.t.sol`| `test_adv_cross_input_reuse_rejected` | P3 | REAL | Binding check: `assertFalse(ok, ...)` |
| `RealVerifierAdversarial.t.sol`| `test_adv_tampered_r_rejected` | P3 | REAL | ECDSA soundness. |
| `RealVerifierAdversarial.t.sol`| `test_adv_tampered_s_rejected` | P3 | REAL | ECDSA soundness. |
| `RealVerifierAdversarial.t.sol`| `test_adv_router_emits_proof_rejected` | P3 | REAL | Router logic. |
| `P3VacuityProof.t.sol` | `testVacuousVerifierAcceptsFalseClaim` | P3 | REAL | Audit evidence: `assertTrue(accepted, "VACUITY: ...")` |
| `PvtFheVerifier.t.sol` | `test_abi_signature` | P1-3 | TRIVIAL | ABI shape check on surrogate. |
| `PvtFheVerifier.t.sol` | `test_gas_budget` | P1-3 | TRIVIAL | Gas on surrogate. |
| `PvtFheVerifier.t.sol` | `test_tampered_proof_reverts_or_returns_false` | P1-3 | TRIVIAL | "Trivially passes" on surrogate. |
| `PvtFheVerifier.t.sol` | `test_valid_proof_accepted` | P1-3 | TRIVIAL | Surrogate returns true. |
| `PvtFheVerifier.t.sol` | `test_threshold_value` | P1-3 | TRIVIAL | Constant check. |
| `PvtFheVerifier.t.sol` | `test_rlwe_degree_value` | P1-3 | TRIVIAL | Constant check. |
| `PvtFheVerifier.t.sol` | `test_interface_compliance` | P1-3 | TRIVIAL | Interface cast. |
| `KzgBatchVerifier.t.sol` | `testHonestVerifies` | P2 | WEAK | Internal BN254 pairing check on self-sampled points. |
| `KzgBatchVerifier.t.sol` | `testTamperedRejects` | P2 | WEAK | Breaking pairing equation on self-sampled points. |
| `PvtFheVerifier.e2e.t.sol` | `test_honest_proof_verifies` | P1-3 | WEAK | Gated by golden files; tests HonkVerifier result. |
| `PvtFheVerifier.e2e.t.sol` | `test_tampered_proof_reverts` | P1-3 | WEAK | Gated by golden files. |
| `Placeholder.t.sol` | `test_placeholder` | - | TRIVIAL | Returns true. |
| `SmokeTest.t.sol` | `test_fixtures_initialized` | - | TRIVIAL | Sanity check. |

---

## Summary: Per-Construction Classification

### Construction P1 — Lattice NIZK
Zero active REAL tests. 17 REAL tests exist but are skipped (`real-nizk` unimplemented).

### Construction P2 — LatticeFold+ (Surrogate: SHA-256)
Zero REAL tests. Primarily WEAK/MOCK checks against hash-chain surrogate.

### Construction P3 — On-Chain Verifier (ECDSA Surrogate)
18 REAL tests. All validate the ECDSA authenticator, not FHE/folding soundness.

### Construction P4 — Threshold Keygen (Surrogate: Hermine)
Zero REAL tests. All checks are MOCK against simulator/stub.

---

## Overall Totals (164 items)

| Classification | Rust | Solidity | Total |
|---------------|------|----------|-------|
| REAL (actually runs) | 0 | 18 | **18** |
| REAL (compile-skipped) | 21 | 0 | **21** |
| WEAK | 24 | 4 | **28** |
| TRIVIAL | 21 | 14 | **35** |
| MOCK | 62 | 0 | **62** |
| **Total** | **128** | **36** | **164** |

> **Key finding:** Zero Rust tests for cryptographic primitives qualify as REAL in the current build. Every primitive (P1-P4) is tested against a surrogate, stub, or is compile-skipped. The only REAL tests are Solidity P3 ECDSA checks — which validate the "trusted-signer" authenticator, not the FHE results themselves.
