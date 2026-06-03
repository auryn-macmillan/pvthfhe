# OPEN PROBLEM BLOCKERS

This document records the cryptographic guarantees that are deliberately WITHHELD and kept fail-closed in the PVTHFHE research prototype. These blockers must be resolved before the system can be considered production-ready.

> ⚠️ **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**

---

### P4 — On-chain IVC decider verification

1.  **Stable ID**: `P4` (On-chain IVC decider verification)
2.  **Status**: `OPEN — production disabled`
3.  **Security claim withheld**: The on-chain verifier does not cryptographically verify the Nova/LatticeFold IVC proof chain.
4.  **Affected code paths**:
    *   `contracts/src/PvtFheVerifier.sol`: `verifyWithIvc`, `verifyAndConsumeWithIvc`, `_verifyIvcDecider`, `ivcDeciderVerifier` storage.
    *   `crates/pvthfhe-compressor`: Future location of the real decider generation.
5.  **Current fail-closed behavior**: The verifier reverts with `"PVTHFHE: IVC decider not configured"` because `ivcDeciderVerifier` is initialized to `address(0)`. If a decider is configured but empty, it reverts with `"PVTHFHE: empty IVC proof"`.
    *   Tests: `contracts/test/IvcFailClosed.t.sol` (`testIvcRequiresDecider`, `testIvcConsumeRequiresDecider`) and `contracts/test/IvcDeciderWiring.t.sol` (`testUnconfiguredRevertsBeforeReadingResult`).
6.  **Missing artifact**: An audited on-chain Nova/LatticeFold decider verifier contract and matching wrapper proof.
7.  **Forbidden shortcuts**: Mock verifiers returning `true`, hash-only circuits treated as a relation, or trusting the `ivcVerifyResult` field in the `IvcBinding` struct.
8.  **Future acceptance criteria**: A real decider verifier contract must pass positive-proof tests and negative tests (forged proofs, wrong statement hashes, modified step counts).
9.  **Deployment rule**: Leave `ivcDeciderVerifier` at `address(0)` in all production-like environments.
10. **Verification commands**:
    *   `forge test --root contracts --match-test testIvcRequiresDecider`
    *   `forge test --root contracts --match-test testUnconfiguredRevertsBeforeReadingResult`

---

### C7 — Final aggregation / threshold-decryption correctness

1.  **Stable ID**: `C7` (Final aggregation / threshold-decryption correctness)
2.  **Status**: `OPEN — production disabled`
3.  **Security claim withheld**: The final aggregation circuit proves only hash binding and does not verify the correctness of the threshold-decryption arithmetic.
4.  **Affected code paths**:
    *   `circuits/aggregator_final/src/main.nr`: `main` function performs Poseidon hash checks but lacks decryption-correctness relations.
5.  **Current fail-closed behavior**: No production verifier path may accept the output of `aggregator_final` as a proof of decryption correctness. The circuit only asserts that the plaintext commitment matches the hash of the provided plaintext limbs.
    *   Tests: `circuits/aggregator_final/src/main.nr` (`test_simplified_honest`, `test_plaintext_mismatch`).
6.  **Missing artifact**: A full C7 Noir relation proving that the aggregated shares correctly reconstruct the plaintext from the ciphertext under the threshold logic.
7.  **Forbidden shortcuts**: Treating the current Poseidon-only circuit as a decryption relation or local recomputation of the result.
8.  **Future acceptance criteria**: The C7 relation must be implemented in Noir and verified against test vectors with valid/invalid partial shares and manipulated lagrange coefficients.
9.  **Deployment rule**: Mark all threshold-decryption results as "Unverified Correctness" in UI/API until C7 is resolved.
10. **Verification commands**:
    *   `(cd circuits && nargo test --package aggregator_final)`

    **Statement-hash binding-invariant clarification**: Current seam-level tests prove that the canonical `VerificationStatementV1` Poseidon hash is field-sensitive and that the IVC decider seam rejects a mismatched statement hash when all separately passed IVC parameters are correct. They do **not** complete deployed Noir/Honk public-input binding: `aggregator_final::main()` still does not source and constrain all 19 statement fields, and the VK / `HonkVerifier.sol` have not been regenerated. Full deployed public-input binding remains OPEN and out-of-scope for the seam invariant.

---

### C5 — Aggregate public-key formation proof (pk_agg = Σ pk_i)

1.  **Stable ID**: `C5` (Aggregate public-key formation proof)
2.  **Status**: `OPEN — production disabled`
3.  **Security claim withheld**: There is no public cryptographic proof that the aggregate public key was correctly formed from the sum of participant public keys.
4.  **Affected code paths**:
    *   `crates/pvthfhe-aggregator/src/keygen/simulator.rs`: `run` function calls `backend.aggregate_keygen(&shares)` without producing a proof.
    *   `crates/pvthfhe-types/src/verification_statement.rs`: `c5_proof_root` exists as a field but is currently a zero-placeholder.
5.  **Current fail-closed behavior**: The `c5_proof_root` in the verification statement is forced to `bytes32(0)`, and the verifier does not attempt to validate it.
6.  **Missing artifact**: A public C5 aggregation proof (e.g., a SNARK or Sigma-aggregate proof) and its on-chain verification logic.
7.  **Forbidden shortcuts**: Local re-summation by the verifier or assuming the aggregator is honest.
8.  **Future acceptance criteria**: Verification that `pk_agg` matches the sum of keys in the DKG transcript, including protection against rogue-key attacks.
9.  **Deployment rule**: Treat `aggregate_pk` as "Self-Certified" and not "Publicly-Verifiable".
10. **Verification commands**:
    *   `grep -r "c5_proof_root" crates/pvthfhe-types/src/verification_statement.rs` (showing zero-initialization in practice).

---

### C6 — Committed-smudge enforcement

1.  **Stable ID**: `C6` (Committed-smudge enforcement)
2.  **Status**: `PARTIAL — legacy fallback removed; full binding pending`
3.  **Security claim withheld**: Full enforcement of DKG-committed smudging (binding slot, round, ciphertext, and session) is not yet complete.
4.  **Affected code paths**:
    *   `crates/pvthfhe-pvss/src/nizk_decrypt.rs`: `proof_secret_share` rejects missing `sk_agg_share` even in legacy mode.
    *   `crates/pvthfhe-pvss/src/encrypt.rs`: Legacy local smudge fallback removed.
5.  **Current fail-closed behavior**: The system rejects `LegacyLocalSmudge` attempts that lack an explicit `sk_agg_share`.
    *   Tests: `crates/pvthfhe-pvss/tests/nizk_decrypt_committed_smudge.rs` (`committed_smudge_legacy_missing_sk_agg_share_fails_closed`).
6.  **Missing artifact**: Full SessionRegistry integration for committed-smudge slot consumption and binding to the decryption round and ciphertext hash.
7.  **Forbidden shortcuts**: Allowing non-committed Gaussian noise in any threshold-decryption path.
8.  **Future acceptance criteria**: All decryption proofs must require a valid `CommittedSmudge` witness that binds to a unique registry slot for the given epoch.
9.  **Deployment rule**: Reject all `LegacyLocalSmudge` proofs in verifier logic.
10. **Verification commands**:
    *   `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-pvss committed_smudge -- --nocapture`

---

### A1 — Cyclo accumulator transcript verification

1.  **Stable ID**: `A1` (Cyclo accumulator transcript verification)
2.  **Status**: `OPEN — production disabled`
3.  **Security claim withheld**: Cyclo accumulator transcript verification is NOT implemented; folded-accumulator soundness is unverified.
4.  **Affected code paths**:
    *   `crates/pvthfhe-nizk/src/adapter.rs`: `cyclo_accumulator_bytes` field and `verify` fail-closed seam.
    *   `crates/pvthfhe-cyclo`: Cyclo fold verifier modules.
    *   Any downstream proof path that would rely on folded-accumulator soundness.
5.  **Current fail-closed behavior**: Nonzero accumulator bytes are rejected with `"cyclo accumulator present but unverified (fail-closed)"`; only the empty (`acc_len=0`) non-folded placeholder is accepted.
    *   Tests: `crates/pvthfhe-nizk/tests/accumulator_fail_closed.rs` (`accumulator_nonzero_transcript_bytes_fail_closed`, `accumulator_empty_placeholder_honest_proof_still_verifies`).
6.  **Missing artifact**: A real versioned accumulator transcript plus a verifier wired to the actual Cyclo fold relation and the NIZK statement.
7.  **Forbidden shortcuts**: Hash-only binding; fake Merkle/commitment roots; parser-only/framing-only validation; dummy or verifier-supplied folded instances; norm-bound checks over claimed metadata; treating `pvthfhe-cyclo` `verify_fold` unit tests as adapter integration evidence.
8.  **Future acceptance criteria**: An honest real accumulator passes; random bytes, wrong statement hash, wrong challenge, wrong final commitment/root, norm-bound violation, and wrong instance count all reject.
9.  **Deployment rule**: No production mode may treat `acc_len = 0` as folded-accumulator verification; deployment stays blocked until A1 is solved.
10. **Verification commands**:
    *   `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-nizk accumulator -- --nocapture`
    *   `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-cyclo fold_verify -- --nocapture`
