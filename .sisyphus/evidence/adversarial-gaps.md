# Adversarial Test Gap Analysis (T14)

Input: `audit-matrix.md` (Test axis: P1 INSUFFICIENT, P2 INSUFFICIENT, P3 REGRESSION-ONLY, P4 INSUFFICIENT).

## P1 — Lattice NIZK gaps

### Gap P1-G1
- **Claim being falsified**: P1-T2 (Soundness): "any accepting P1 prover yields a straight-line extractor recovering the opened witness"
- **Test name**: `test_nizk_accepts_wrong_witness_fails`
- **Tampering strategy**: Construct a `NizkWitness` with `secret_value` flipped by 1 bit; call `RealNizkAdapter::prove(stmt, tampered_witness)` then `RealNizkAdapter::verify(stmt, &proof)`. The verifier must reject if soundness holds.
- **Expected assertion**: `RealNizkAdapter::verify(stmt, &bad_proof).is_err()` OR returned `Ok(false)`
- **Target file**: `crates/pvthfhe-fhe/tests/lattice_nizk_adversarial.rs`

### Gap P1-G2
- **Claim being falsified**: P1-T2 (Soundness): "except with probability bounded by the SHA-256 binding failure probability"
- **Test name**: `test_nizk_forged_proof_rejected`
- **Tampering strategy**: Flip a single byte in `NizkProof::proof_bytes` after a valid prove call. Call `RealNizkAdapter::verify(stmt, &forged)`. Verifier must reject.
- **Expected assertion**: `RealNizkAdapter::verify(stmt, &forged).is_err()` OR `Ok(false)`
- **Target file**: `crates/pvthfhe-fhe/tests/lattice_nizk_adversarial.rs`

### Gap P1-G3
- **Claim being falsified**: P1-T3 (ZK): "randomized masked SLAP core transcript admits ROM zero-knowledge"
- **Test name**: `test_nizk_two_proofs_same_stmt_differ`
- **Tampering strategy**: Call `RealNizkAdapter::prove` twice on the same `(stmt, witness)` with different RNG seeds. Assert the two `proof_bytes` are not identical (proves randomization, a prerequisite for ZK).
- **Expected assertion**: `proof1.proof_bytes != proof2.proof_bytes`
- **Target file**: `crates/pvthfhe-fhe/tests/lattice_nizk_adversarial.rs`

### Gap P1-G4
- **Claim being falsified**: P1-T5 (Commitment Binding): "pvss_commitment is binding"
- **Test name**: `test_nizk_wrong_commitment_fails_verify`
- **Tampering strategy**: Use a valid `(stmt, witness)` pair; flip one byte in `stmt.commitment` before calling verify. Verifier must reject.
- **Expected assertion**: `RealNizkAdapter::verify(tampered_stmt, &valid_proof).is_err()`
- **Target file**: `crates/pvthfhe-fhe/tests/lattice_nizk_adversarial.rs`

---

## P2 — Folding gaps

### Gap P2-G1
- **Claim being falsified**: P2-T2 (Knowledge Soundness): "depth-d accepting fold tree yields valid RLWE witnesses"
- **Test name**: `test_fold_tampered_witness_rejected`
- **Tampering strategy**: After a valid fold of N proofs, flip a single byte in `FoldWitness::nizk_proof.proof_bytes` at depth 1. Call `verify_acc`. Must reject.
- **Expected assertion**: `verify_acc(&tampered_acc, &params).is_err()`
- **Target file**: `crates/pvthfhe-aggregator/tests/folding_tamper.rs`

### Gap P2-G2
- **Claim being falsified**: P2-T4 Part A (Parameter Binding): "no adversary can produce accumulator with acc*.params ≠ P"
- **Test name**: `test_fold_mismatched_params_rejected`
- **Tampering strategy**: Create a `FoldStatement` with `params` set to `(65537, 512, 17)` (wrong ring degree). Attempt to fold into an accumulator initialized with `(65537, 1024, 17)`. Must error.
- **Expected assertion**: `fold(&acc, &witness, &stmt).is_err()` with "param mismatch"
- **Target file**: `crates/pvthfhe-aggregator/tests/folding_tamper.rs`

### Gap P2-G3
- **Claim being falsified**: P2-T4 Part B (Norm Bound — SECURITY OBLIGATION): currently unimplemented; test should be RED until implemented
- **Test name**: `test_fold_large_norm_witness_rejected`
- **Tampering strategy**: Construct a `FoldWitness` with `nizk_proof.proof_bytes` containing non-uniform bytes with values exceeding the `B_e = 17` bound (e.g., byte value 200). Currently `validate_witness` only checks uniformity — this test SHOULD fail (RED) until arithmetic norm check is added.
- **Expected assertion**: `fold(&acc, &large_norm_witness, &stmt).is_err()`
- **Note**: This test MUST start RED (current code accepts it). Going GREEN requires T20 implementation fix.
- **Target file**: `crates/pvthfhe-aggregator/tests/folding_tamper.rs`

### Gap P2-G4
- **Claim being falsified**: P2-T3 (ZK Preservation): "folding preserves the projected SLAP core ZK view"
- **Test name**: `test_fold_proof_not_deterministic`
- **Tampering strategy**: Fold same batch twice with different randomness. Assert final accumulator hashes differ (proves randomization is present in fold steps).
- **Expected assertion**: `acc1.statement_hash != acc2.statement_hash` (or equivalent non-determinism check)
- **Target file**: `crates/pvthfhe-aggregator/tests/folding_tamper.rs`

---

## P3 — On-chain Verifier gaps

> P3 Test axis is REGRESSION-ONLY. The existing ECDSA rejection tests are correct for the ECDSA model. However, no test falsifies the FHE soundness claim. Gap P3-G1 is already supplied by `P3VacuityProof.t.sol` (T1 deliverable). Additional gaps below address remaining adversarial coverage.

### Gap P3-G1 (already addressed by T1)
- `contracts/test/P3VacuityProof.t.sol` — verifier accepts arbitrary false FHE result. ✅ done.

### Gap P3-G2
- **Claim being falsified**: ARCHITECTURE.md "Decryption-Soundness: No adversary can force an incorrect decryption result to be accepted"
- **Test name**: `testWrongSignerIsRejected` (already exists in `RealVerifierAdversarial.t.sol`)
- **Status**: Already implemented. REAL classification for ECDSA auth. No new test needed here — the gap is in the claim, not the test.

---

## P4 — Aggregator / Keygen gaps

### Gap P4-G1
- **Claim being falsified**: P4-T1 (Correctness): "accepted honest keygen transcript yields unique BFVPublicKey"
- **Test name**: `test_keygen_deterministic_same_seed`
- **Tampering strategy**: Run `HermineAdapter::run_keygen_round` twice with same session/seed. Assert identical public key output (determinism property underlying correctness).
- **Expected assertion**: `pk1.public_key_bytes == pk2.public_key_bytes`
- **Target file**: `crates/pvthfhe-aggregator/tests/keygen_honest.rs`

### Gap P4-G2
- **Claim being falsified**: P4-T2 (Secrecy): "adversary corrupting fewer than t parties learns nothing additional"
- **Test name**: `test_keygen_subset_below_threshold_gives_no_info`
- **Tampering strategy**: Run keygen; collect `t-1` shares. Try to recover the secret via Lagrange interpolation. Must fail (output should be uniformly random over the field, i.e., reconstructed value does not match actual secret).
- **Expected assertion**: `recover_secret(subset_of_t_minus_1_shares) != actual_secret`
- **Target file**: `crates/pvthfhe-aggregator/tests/keygen_malicious.rs`

### Gap P4-G3
- **Claim being falsified**: P4-T4 (Abort-with-Blame): "misbehavior yields publicly checkable blame; honest parties never falsely blamed"
- **Test name**: `test_honest_party_not_blamed`
- **Tampering strategy**: Run protocol with all honest parties; call `blame_dealing` on an honest artifact. Must return no blame proofs (empty blame set).
- **Expected assertion**: `blame_proofs.is_empty()`
- **Target file**: `crates/pvthfhe-aggregator/tests/keygen_malicious.rs`

---

## Summary table

| Gap ID | Construction | Claim | Test name | Currently RED? | Target file |
|---|---|---|---|---|---|
| P1-G1 | P1 | Soundness (wrong witness) | `test_nizk_accepts_wrong_witness_fails` | Unknown | lattice_nizk_adversarial.rs |
| P1-G2 | P1 | Soundness (forged proof) | `test_nizk_forged_proof_rejected` | Unknown | lattice_nizk_adversarial.rs |
| P1-G3 | P1 | ZK (randomization) | `test_nizk_two_proofs_same_stmt_differ` | Unknown | lattice_nizk_adversarial.rs |
| P1-G4 | P1 | Commitment Binding | `test_nizk_wrong_commitment_fails_verify` | Unknown | lattice_nizk_adversarial.rs |
| P2-G1 | P2 | Knowledge Soundness | `test_fold_tampered_witness_rejected` | Unknown | folding_tamper.rs |
| P2-G2 | P2 | Parameter Binding | `test_fold_mismatched_params_rejected` | Unknown | folding_tamper.rs |
| **P2-G3** | P2 | **Norm Bound (obligation)** | `test_fold_large_norm_witness_rejected` | **YES — must be RED** | folding_tamper.rs |
| P2-G4 | P2 | ZK Preservation | `test_fold_proof_not_deterministic` | Unknown | folding_tamper.rs |
| P4-G1 | P4 | Correctness (determinism) | `test_keygen_deterministic_same_seed` | Unknown | keygen_honest.rs |
| P4-G2 | P4 | Secrecy (t-1 threshold) | `test_keygen_subset_below_threshold_gives_no_info` | Unknown | keygen_malicious.rs |
| P4-G3 | P4 | Abort-with-Blame (no false blame) | `test_honest_party_not_blamed` | Unknown | keygen_malicious.rs |
