# Remediate Soundness and Completeness Audit

**Status**: draft for Momus review
**Scope**: soundness/completeness remediation for private-verifiable threshold FHE verification paths

## Findings To Remediate

### F1: Caller-Controlled IVC Result Accepted On-Chain : HIGH

`contracts/src/PvtFheVerifier.sol` `verifyWithIvc` and `verifyAndConsumeWithIvc` accept caller-supplied `IvcBinding.ivcVerifyResult == 1` and then verify only the seven legacy public inputs with `HonkVerifier`. No Solidity or Noir verifier checks the IVC proof, verifier key, public parameters, or `z0`/`zi` commitments.

### F2: `aggregator_final` Proves A Weak Relation : HIGH

`circuits/aggregator_final/src/main.nr` proves only `plaintext_commitment == hash(nova_final_plaintext)`, nonzero metadata, threshold bounds, and nonzero `ivc_snark_proof_hash`. It does not prove C7 threshold-decryption correctness.

### F3: Aggregate Public Key Formation Lacks Public Proof : HIGH

The current stack lacks a public C5 proof that `pk_agg` equals the sum of accepted participant key contributions under the DKG root.

### F4: Cyclo Accumulator Bytes Are Skipped : HIGH

`crates/pvthfhe-nizk/src/adapter.rs` reads the Cyclo accumulator byte length and skips those bytes without verifying the accumulator transcript.

### F5: Legacy Decrypt Binding Remains Reachable : MEDIUM

`crates/pvthfhe-pvss/src/nizk_decrypt.rs` still accepts `LegacyLocalSmudge` and can fall back to `derive_party_binding(&stmt.party_pk)` when `sk_agg_share` is absent.

### F6: Legacy Hermine Transcript Verification Is Shape-Only : MEDIUM

`crates/pvthfhe-keygen/src/hermine.rs` is deprecated and feature-blocked, but if compiled its `verify_transcript()` only checks artifact shape.

### F7: Documentation Overstates Implemented Guarantees : MEDIUM

`README.md`, `SECURITY.md`, `WARNING.md`, and `ARCHITECTURE.md` overstate default cryptographic guarantees relative to the implemented relations.

## Phase 0: Safety Freeze And Failing Regression Tests

**Files**: `contracts/src/PvtFheVerifier.sol`, contract tests, `circuits/aggregator_final` tests, `SECURITY.md`, `WARNING.md`, `ARCHITECTURE.md`, `README.md`.

**Actions**:

1. Change docs/status tables to say P4 on-chain IVC verification, C5 pk aggregation, C7 final aggregation, and Cyclo accumulator verification are `OPEN` unless and until later phases land.
2. Change production `verifyWithIvc` and `verifyAndConsumeWithIvc` to fail closed for IVC mode unless a real on-chain decider verifier is configured.
3. If compatibility is needed, move old behavior to a clearly named research-only function or feature that cannot be used by production deployment scripts.
4. Add RED tests before implementation:
   - Solidity: arbitrary nonzero `IvcBinding` with `ivcVerifyResult = 1` is rejected when no decider verifier is configured.
   - Noir: arbitrary plaintext vector with matching hash but no valid C7 witness fails once production C7 mode is enabled.
   - Rust: Cyclo proof carrying nonempty random accumulator bytes is rejected.
   - Rust: `LegacyLocalSmudge` without DKG-committed `sk_agg_share` is rejected in production verification mode.

**Acceptance Commands**:

```bash
forge test --root contracts --match-test 'testRejectsForgedIvcBinding|testIvcRequiresDecider'
(cd circuits && nargo test --package aggregator_final)
cargo test -p pvthfhe-nizk accumulator -- --nocapture
cargo test -p pvthfhe-pvss committed_smudge -- --nocapture
```

**Expected Result**: New RED tests fail before the hardening change and pass after Phase 0 fail-closed behavior.

## Phase 1: Canonical Public Statement And Encoding

**Files**: shared types in `crates/pvthfhe-types`, Solidity mirror definitions, Noir mirror definitions.

**Actions**:

1. Define `VerificationStatementV1` with canonical length-prefixed encoding and a domain separator.
2. Include: protocol version, chain/context id, `dkgRoot`, `epoch`, `participantSetHash`, `aggregatePkHash`, `ciphertextHash`, `plaintextHash`, `dCommitment`, C5 proof root, C6 proof-set root, Cyclo accumulator root, IVC vk hash, IVC pp hash, IVC proof hash, `z0` commitment, `zi` commitment, `ivcSteps`, and `bootstrapResultHash`.
3. Bind this exact statement into Solidity public inputs and Noir/Rust proof generation.
4. Forbid verifier-result-only metadata fields in production statements.
5. Add Rust/Solidity/Noir round-trip and cross-language test vectors.

**Acceptance Commands**:

```bash
cargo test -p pvthfhe-types verification_statement_vectors
forge test --root contracts --match-test testVerificationStatementVector
(cd circuits && nargo test --package aggregator_final)
```

**Expected Result**: All three surfaces derive the same statement hash for fixed vectors and reject reordered or omitted fields.

## Phase 2: Single Concrete IVC Decider Path

**Decision**: Use an audited off-chain Nova/LatticeFold decider that emits a SNARK/wrapper proof whose verifier is run by the on-chain verifier contract. Do not implement a placeholder Noir hash-binding circuit as a production milestone. If the selected decider cannot be verified on-chain within gas/toolchain limits, production IVC remains disabled from Phase 0.

**Files**: compressor decider/wrapper module, contracts verifier interface, deployment config, proof serialization.

**Actions**:

1. Implement `IIvcDeciderVerifier.verify(bytes proof, bytes32 statementHash, bytes32 vkHash, bytes32 ppHash, bytes32 z0, bytes32 zi, uint64 steps) returns (bool)` or equivalent using the selected real verifier.
2. Update `PvtFheVerifier` so `verifyWithIvc` calls this verifier and accepts only if the verifier accepts.
3. Delete or ignore `ivcVerifyResult` in production calldata.
4. Populate wrapper proof bytes from the compressor; empty proof bytes are invalid.
5. Add tests for forged `ivcVerifyResult = 1`, wrong vk/pp hash, wrong `z0`/`zi`, wrong steps, tampered proof bytes, and empty proof bytes.

**Acceptance Commands**:

```bash
cargo test -p pvthfhe-compressor decider_wrapper -- --nocapture
forge test --root contracts --match-test 'testIvcDeciderAcceptsValid|testIvcDeciderRejectsTamper|testIvcRejectsEmptyProof|testIvcIgnoresCallerVerifyResult'
```

**Expected Result**: A valid generated decider proof accepts and every tampering test rejects. If no real decider verifier exists, the only passing state is fail-closed production IVC mode.

## Phase 3: Production C7 Final Aggregation Relation

**Files**: `circuits/aggregator_final/src/main.nr` or replacement package, Rust witness generator, contract public-input packing.

**Actions**:

1. Replace the current hash-only circuit with constraints for selected participant membership and uniqueness, threshold satisfaction, Lagrange coefficient derivation, share-chain/C6 proof-set binding, CRT reconstruction over configured BFV RNS limbs, plaintext decode, and equality to `plaintextHash`.
2. Bind `ciphertextHash`, `aggregatePkHash`, `dkgRoot`, `epoch`, `participantSetHash`, `dCommitment`, C5 root, C6 root, and IVC statement hash into public inputs.
3. Remove any production path where arbitrary plaintext with matching hash can prove.

**Acceptance Commands**:

```bash
(cd circuits && nargo test --package aggregator_final)
cargo test -p pvthfhe-compressor c7_witness -- --nocapture
```

**Expected Result**: Honest C7 witness passes; duplicate participant, insufficient threshold, tampered share, wrong Lagrange coefficient, wrong CRT limb, and wrong plaintext hash all fail.

## Phase 4: C5 PK Aggregation And Committed-Smudge C6 Only

**Files**: keygen/DKG crates, PVSS decrypt NIZK, contracts anchors.

**Actions**:

1. Produce and verify a public C5 proof/root that `pk_agg` equals accepted participants' BFV key contributions under the DKG root.
2. Bind the C5 root into `VerificationStatementV1` and C7 public inputs.
3. Remove production acceptance of `LegacyLocalSmudge`.
4. Require `CommittedSmudge` plus DKG-committed `sk_agg_share` and `esm_agg_share` commitments.
5. Bind smudge slot id, decrypt round, and ciphertext hash into the C6 statement and `SessionRegistry` consumption.

**Acceptance Commands**:

```bash
cargo test -p pvthfhe-keygen c5_pk_aggregation -- --nocapture
cargo test -p pvthfhe-pvss committed_smudge -- --nocapture
forge test --root contracts --match-test 'testSmudgeSlotBoundToCiphertext|testLegacySmudgeRejected'
```

**Expected Result**: Tampered pk contribution/root rejects; legacy smudge rejects; reused or wrong smudge slot rejects.

## Phase 5: Cyclo Accumulator Verification

**Files**: `crates/pvthfhe-nizk/src/adapter.rs`, Cyclo fold verifier modules.

**Actions**:

1. Replace `cur.skip(acc_len)` with parsing of a versioned accumulator transcript.
2. Verify transcript domain separator, statement hash, Fiat-Shamir challenges, fold equations, final accumulator commitment/root, norm bounds, and expected number of folded instances.
3. Reject zero-length accumulator in production folded mode.
4. Permit zero length only in an explicitly named non-folded unit-test mode if still needed.

**Acceptance Commands**:

```bash
cargo test -p pvthfhe-nizk accumulator -- --nocapture
cargo test -p pvthfhe-cyclo fold_verify -- --nocapture
```

**Expected Result**: Honest accumulator passes; random bytes, wrong statement hash, wrong challenge, wrong final commitment, and norm-bound violation reject.

## Phase 6: Legacy And Mock Quarantine

**Files**: Cargo feature config, CI, deployment scripts, docs.

**Actions**:

1. Ensure Hermine, surrogate compressor, mock FHE, placeholder proof, and attestation-only paths are test/research-only and impossible in production feature sets.
2. CI asserts production profile does not enable these features.
3. Deployment scripts use fail-closed verifier configuration unless the Phase 2 decider exists.

**Acceptance Commands**:

```bash
cargo test --workspace --no-default-features --features production-profile
cargo tree -e features
```

**Expected Result**: Production profile compiles without legacy/mock features; forbidden feature combinations fail or are absent from the feature tree.

## Phase 7: End-To-End Gates

**Actions**:

1. Run `just phase1-gate`, `just phase2-gate`, and `just phase3-gate` only after Phases 1-6 pass.
2. Run an end-to-end forged-proof harness that attempts arbitrary plaintext hash, forged IVC result, tampered C5 root, tampered C6 root, bogus Cyclo accumulator, and legacy smudge fallback.

**Expected Result**: Honest end-to-end flow accepts; all forged end-to-end cases reject.

## Explicit Non-Goals And Guardrails

1. Do not count hash-binding circuits as IVC verification.
2. Do not expose caller-supplied native verifier result as a production public input.
3. Do not update docs to say resolved until acceptance tests exist and pass.
4. If a real on-chain decider is not available, leave production IVC disabled and document the blocker instead of shipping a shortcut.
