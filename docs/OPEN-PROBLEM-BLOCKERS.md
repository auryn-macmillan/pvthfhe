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
2.  **Status**: `RESOLVED (2026-06-04)` — Schwartz-Zippel Lagrange recombination implemented in-circuit; G3/G4 binding complete
3.  **Implementation**:
    *   `circuits/aggregator_final/src/main.nr`: Full Schwartz-Zippel constraints: `sum(lambda_i) = 1`, `sum(lambda_i * d_i(r)) = pt(r)`, G4 Merkle-path PK binding (depth=8, Poseidon).
    *   `crates/pvthfhe-cli/src/full_pipeline.rs`: Witness generation (`build_c7_prover_toml`) with 5 new params (challenge_r, n_shares, share_evals, lagrange_coeffs_fr, pt_eval). G3 full plaintext binding via `aggregate_decrypt_raw_result_poly()`.
    *   Circuit size: 7,959 ACIR opcodes, 27,602 UltraHonk circuit size.
4.  **Test coverage**: 18 tests pass (`nargo test --package aggregator_final`), including 8 C7-specific tests (honest recombination, wrong Lagrange sum, wrong recombination/pt_eval, wrong share eval, manipulated coefficients, zero-padded shares, plaintext commitment inconsistency, n_shares zero) + 4 G4 PK binding tests.
5.  **Verification commands**:
    *   `(cd circuits && nargo test --package aggregator_final)` — 18/18 pass
    *   `cargo test -p pvthfhe-cli -- c7_plaintext` — G3 binding verified

---

### C5 — Aggregate public-key formation proof (pk_agg = Σ pk_i)

1.  **Stable ID**: `C5` (Aggregate public-key formation proof)
2.  **Status**: `RESOLVED (2026-06-04)` — Full formation proof with PoP, on-chain binding, adversarial tests
3.  **Implementation**:
    *   `crates/pvthfhe-aggregator/src/keygen/c5_proof.rs`: `prove_pk_formation` + `verify_pk_formation` with SHA256-based commit-reveal PoP per party.
    *   `crates/pvthfhe-aggregator/src/keygen/simulator.rs`: C5 proof generation wired in `run()` after `aggregate_keygen`.
    *   `crates/pvthfhe-aggregator/src/keygen/types.rs`: `c5_proof_root: [u8; 32]` field on `Round3Aggregate`.
    *   `contracts/src/PvtFheVerifier.sol`: `c5ProofRoot` integrated into `IvcBinding` struct and `_computeIvcStatementHash()`.
    *   `crates/pvthfhe-cli/src/full_pipeline.rs`: `PipelineReport.c5_proof_root` populated from transcript, verified nonzero in integration test.
4.  **Test coverage**: 9 tests pass (`cargo test -p pvthfhe-aggregator --test c5_formation_proof --features mock`), including honest n-party, manipulated pk, rogue aggregate, duplicate party, mismatched counts, nonce uniqueness, session binding, deterministic root, and empty-set rejection.
5.  **Verification commands**:
    *   `cargo test -p pvthfhe-aggregator --test c5_formation_proof --features mock` — 9/9 pass

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
2.  **Status**: `RESOLVED (2026-06-04)` — Versioned codec with real verification dispatch, adversarial tests
3.  **Implementation**:
    *   `crates/pvthfhe-cyclo/src/accumulator_codec.rs` (618 lines): Versioned wire format with encode/decode, `AccumulatorInstanceRef`, validation (version, params_digest, lengths, norm ≤ beta_at_t, duplicate IDs, depth == instance_count, no trailing bytes).
    *   `crates/pvthfhe-nizk/src/adapter.rs`: Fail-closed stub replaced with `verify_accumulator_transcript` dispatch. Checks session_id, params_digest, norm_bound, fold_depth, commitment/pub_io lengths, participant membership, per-instance ajtai_commitment_hash.
    *   `append_accumulator_to_proof()` for post-prove accumulator encoding.
4.  **Test coverage**: 21 tests pass:
    *   10 codec unit tests (`cargo test -p pvthfhe-cyclo accumulator_codec`)
    *   5 fail-closed tests (`cargo test -p pvthfhe-nizk --test accumulator_fail_closed`)
    *   6 adversarial tests (`cargo test -p pvthfhe-nizk --test accumulator_transcript_adversarial`)
5.  **Verification commands**:
    *   `cargo test -p pvthfhe-cyclo accumulator_codec` — 10/10 pass
    *   `cargo test -p pvthfhe-nizk --test accumulator_fail_closed` — 5/5 pass
     *   `cargo test -p pvthfhe-nizk --test accumulator_transcript_adversarial` — 6/6 pass

---

### G-N8 — N=8 Circuit Prototype vs Production N=8192

1.  **Stable ID**: `G-N8` (Circuit coefficient dimension mismatch)
2.  **Status**: `OPEN — prototype limitation`
3.  **Severity**: CRITICAL
4.  **Security claim withheld**: The Noir circuits correctly prove the threshold decryption relation for N=8 polynomials, but production RLWE uses N=8192. The mapping from N=8192 to N=8 occurs in native Rust (`aggregate_decrypt_raw_result_poly`) and is **not provably correctness-preserving**.
5.  **Affected circuits**:
    *   `circuits/aggregator_final/src/main.nr` — `global N: u32 = 8` (primary verifier anchor)
    *   `circuits/decrypt_share/src/main.nr` — `global N: u32 = 8` (per-share R3 verification)
    *   `circuits/nova_state_commitment/src/main.nr` — `nova_final_plaintext: [Field; 8]` (IVC binding)
6.  **Impact**: A malicious aggregator (untrusted by design) can choose N=8 projections that satisfy circuit constraints but correspond to an incorrect N=8192 plaintext. Since the circuit is the on-chain verifier's trust anchor, anything the circuit accepts is treated as valid.
7.  **Resolution**: Scale circuits to N=8192 (requires Noir `generic_const_exprs` or specialization) OR provide a formal reduction from N=8192 correctness to N=8 verification.
8.  **Target**: T42 (pre-audit milestone)
9.  **Found in**: MPC deep audit 2026-06-05 (Finding 2 — CRITICAL).
