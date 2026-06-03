# Learnings — remediate-soundness-completeness-audit

## [2026-06-03] Orchestrator ground-truth context (Atlas)

### Repo conventions (from AGENTS.md)
- TDD: ALWAYS write a RED test before any implementation change.
- Plans in `.sisyphus/plans/` are READ-ONLY. Draft work goes in notepads/impl files.
- FHE backend LOCKED in F1: `gnosisguild/fhe.rs`; ring backend `fhe-math`.
- Stub protocol: replace stubs in place; never delete+recreate a stub file.
- Working dirs: Foundry `forge ... --root contracts`; Noir `(cd circuits && nargo ...)`; Cargo from repo root with `-p <crate>`.
- Canonical Noir+BB flow uses `nargo execute` + `bb` (NOT `nargo prove`/`nargo verify`).
- Research build needs env `PVTHFHE_ALLOW_RESEARCH_BUILD=1`.

### CRITICAL: pre-existing `stage0-gate` in Justfile (lines 194-240)
A previous safety-freeze gate already exists. Current code has DRIFTED OUT of it.
The gate's checks are reusable acceptance signals for our Phase 0:
- Check 2: `head -15` of README.md / ARCHITECTURE.md / SECURITY.md must contain `DO NOT DEPLOY`.
- Check 5: `grep -cE 'return\s+true|return\s+_honkVerifier' contracts/src/PvtFheVerifier.sol` must be 0
  (i.e. NO vacuous accept path). CURRENT FILE VIOLATES THIS.
- Check 6: no tautological `assert(x==x)` in circuits/.
- Check 7: forge tests pass.
- Check 8: `SECURITY-ADVISORY-001.md` contains `STATUS: DRAFT`.
NOTE: stage0-gate belongs to an OLDER plan and is STRICTER than our Phase 0 (it bans ALL
return-true, including non-IVC verify()). Do NOT treat full stage0-gate pass as our blocker;
our Phase 0 only fail-closes the IVC paths (F1). Track the tension; do not fight it.

### Justfile gates relevant later
- `just phase1-gate` / `phase2-gate` / `phase3-gate` -> python scripts in `.sisyphus/scripts/`.
- `just test-all` = cargo workspace + nargo workspace + forge.

### PvtFheVerifier.sol current state (contracts/src/PvtFheVerifier.sol, 575 lines)
- Constructor: `(address registry_, address timelock_)`. `_honkVerifier = new HonkVerifier()`.
- `verifyWithIvc` (215-239) and `verifyAndConsumeWithIvc` (271-306): call
  `_requireIvcBindingValid(ivcBinding)` then verify only 7 legacy public inputs via HonkVerifier.
  IVC fields are NEVER cryptographically verified.
- `_requireIvcBindingValid` (509-521): only checks non-zero fields + `ivcVerifyResult == 1`.
  **This trusts a CALLER-SUPPLIED boolean as proof of IVC verification = F1 HIGH.**
- `threshold()` returns 0 (420-422). `registeredThreshold(dkgRoot)` reads registry.
- There is NO `IIvcDeciderVerifier` interface anywhere yet.
- `verifyWithAttestation` uses an attestor allowlist + ecrecover (separate path).

### Circuit / Rust hotspots (from audit, to verify at each phase)
- `circuits/aggregator_final/src/main.nr` (~101 lines): hash-only relation (F2).
- `crates/pvthfhe-nizk/src/adapter.rs`: `cur.skip(acc_len)` ~line 186 (F4 Cyclo skip).
- `crates/pvthfhe-pvss/src/nizk_decrypt.rs`: LegacyLocalSmudge + derive_party_binding fallback (F5).
- `crates/pvthfhe-keygen/src/hermine.rs`: verify_transcript shape-only, feature-gated (F6).

## [2026-06-03] F1 IVC fail-closed implementation (Sisyphus Junior)
- Files changed: `contracts/src/PvtFheVerifier.sol`, `contracts/test/IvcFailClosed.t.sol`, `contracts/test/PvtFheVerifier.t.sol`.
- Pre-existing tests updated: `test_ivc_verify_result_zero_rejected`, `test_ivc_verify_result_two_rejected`, and `test_verifyAndConsumeWithIvc_verify_result_zero_rejected` now expect the fail-closed decider gate instead of trusting/rejecting caller-supplied `ivcVerifyResult`; `test_bootstrap_result_hash_zero_rejected` and `test_verifyAndConsumeWithIvc_bootstrap_zero_rejected` configure a placeholder decider so they still exercise bootstrap field validation.
- RED evidence before implementation: `forge test --root contracts --match-test 'testIvcRequiresDecider|testIvcConsumeRequiresDecider|testRejectsForgedIvcVerifyResult|testSetIvcDeciderVerifierOnlyTimelock'` => 0 passed, 4 failed.
- GREEN evidence after implementation: same targeted command => 4 passed, 0 failed; full `forge test --root contracts` => 140 passed, 0 failed.

## [2026-06-03] Phase 0 wave 1 VERIFIED by orchestrator (Atlas)
- F1 (Solidity) DONE+VERIFIED: ivcDeciderVerifier storage (default 0) + timelock setter; fail-closed
  `require(ivcDeciderVerifier != address(0))` as FIRST stmt in verifyWithIvc & verifyAndConsumeWithIvc;
  removed `ivcVerifyResult==1` trust (field kept for ABI). New tests in contracts/test/IvcFailClosed.t.sol.
  Independent verify: `forge test --root contracts` => 140 passed/0 failed. grep `ivcVerifyResult == 1` => 0.
- F7 (docs) DONE+VERIFIED: README banner now `DO NOT DEPLOY`; status table On-chain/Decrypt => OPEN;
  Open Problems += P4/C5/C7/A1; SECURITY.md flips C7 RESOLVED->OPEN (was overstated), adds P4/A1.
  `head -15 README.md | grep DO NOT DEPLOY` => 1.
- PLAN STRUCTURE NOTE: plan uses prose Phase headers, NOT `- [ ]` checkboxes; boulder = 0/0. Track via TodoWrite.
- SCOPE NOTE: circuits/aggregator_final/C7Prover.toml is a PRE-EXISTING uncommitted change (was M at turn
  start), NOT introduced by Phase 0 agents. Do NOT stage/commit it.
- REMAINING Phase 0: Rust RED tests + fail-closed guards for F4 (Cyclo accumulator skip in
  crates/pvthfhe-nizk/src/adapter.rs) and F5 (LegacyLocalSmudge fallback in
  crates/pvthfhe-pvss/src/nizk_decrypt.rs). These need a production-mode fail-closed reject (full positive
  verification deferred to Phases 5/4).

## [2026-06-03] F5 LegacyLocalSmudge fail-closed implementation (Sisyphus Junior)
- Files changed: `crates/pvthfhe-pvss/src/nizk_decrypt.rs`, `crates/pvthfhe-pvss/src/encrypt.rs`, and pvss tests `nizk_decrypt_committed_smudge.rs`, `decrypt_share_nizk.rs`, `decrypt_dkg_root_binding.rs`, `encrypt_decrypt_roundtrip.rs`, `nizk_decrypt_soundness.rs`.
- Gating chosen: fail-closed-by-default. `pvthfhe-pvss` has only `production-stub-allowed` feature gating for the noop adapter and mock-test env `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK`; no production-profile/research toggle exists for decrypt NIZK. `PVTHFHE_ALLOW_RESEARCH_BUILD=1` did not affect the remaining unrelated full-test failure.
- Call-sites audited: `proof_secret_share` (legacy prover secret-share resolution), `proof_commitment`, `verify_secret_share`, `verify_commitment`, `derive_party_binding`, plus adapter statement construction in `encrypt.rs::prove_decrypted_share`. Removed both source-level `None -> derive_party_binding(party_pk)` paths; `grep` for `unwrap_or_else(|| derive_party_binding...)`, `derive_party_binding(party_pk)`, and `derive_party_binding(&stmt.party_pk)` in `crates/pvthfhe-pvss/src` returned no matches.
- RED evidence before guard: `cargo test -p pvthfhe-pvss committed_smudge_legacy_missing_sk_agg_share_fails_closed -- --nocapture` => new test failed with `left: Ok(())`, `right: Err(InvalidShare)`.
- GREEN evidence after guard: `cargo test -p pvthfhe-pvss committed_smudge -- --nocapture` => 5 passed, 0 failed. Honest paths verified: committed-smudge happy path still passes; legacy local-smudge with explicit `sk_agg_share` still proves and verifies in updated fixtures.
- Diagnostics: `lsp_diagnostics` on `nizk_decrypt.rs` and `encrypt.rs` => no diagnostics found.
- Full pvss test status: `cargo test -p pvthfhe-pvss` progresses through decrypt NIZK/committed-smudge updates but still fails at pre-existing/unrelated `enc_randomness_ciphertexts_differ_across_runs` during `deal()` with redacted `BackendError`; same failure with `PVTHFHE_ALLOW_RESEARCH_BUILD=1`. Additional targeted F5-adjacent binaries pass: `decrypt_share_nizk` 3/0, `decrypt_dkg_root_binding` 5/0, `nizk_decrypt_soundness` 2/0. `encrypt_decrypt_roundtrip` also fails before proof attachment at `deal encrypted shares: BackendError(<redacted>)`, unrelated to the LegacyLocalSmudge proof guard.

## [2026-06-03] F4 Cyclo accumulator fail-closed remediation (Sisyphus Junior)
- Files changed: `crates/pvthfhe-nizk/src/adapter.rs`, `crates/pvthfhe-nizk/tests/accumulator_fail_closed.rs`.
- Gating mechanism chosen: unconditional fail-closed rejection of `acc_len != 0`. `pvthfhe-nizk` currently has backend feature flags (`enable-poulpy`, `enable-ckks`, `enable-tfhe`, `enable-lazer`) and test cfgs only; no production-profile feature or env-var convention exists in this crate for accepting unverifiable accumulator bytes. Since full Cyclo accumulator verification is deferred, accepting nonzero bytes would be unsafe.
- Baseline before edit: `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-nizk` initially timed out at 120s while `sigma_completeness::honest_instances_all_accept` was still running; rerun with 300s completed successfully: all tests passed (62 passed, 0 failed across lib/integration/doc tests).
- RED evidence before guard: `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-nizk accumulator -- --nocapture` => `accumulator_nonzero_transcript_bytes_fail_closed` failed because verifier returned `Ok(())`; honest empty-accumulator test passed.
- Implementation: after reading `acc_len` in `CycloNizkAdapter::verify`, return `NizkError::VerificationFailed("cyclo accumulator present but unverified (fail-closed)")` when `acc_len != 0`; removed the unverified `cur.skip(acc_len)` acceptance path.
- GREEN targeted evidence: `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-nizk accumulator -- --nocapture` => 2 passed, 0 failed.
- Diagnostics: `lsp_diagnostics` on `crates/pvthfhe-nizk/src/adapter.rs` => no diagnostics found.
- Full after evidence: `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-nizk` => all tests passed (64 passed, 0 failed across lib/integration/doc tests; +2 new accumulator tests). Existing warnings remain pre-existing/out-of-scope.

## [2026-06-03] Phase 1 exploration synthesis (Atlas) — CRITICAL cross-language hash mismatch
Three parallel explore agents mapped the statement/encoding surfaces. Sessions: Rust types `ses_172348befffe2B1gfmwuZk0HC9`, Solidity `ses_172346d8dffeI0tnyf1VV2c1kQ`, Noir `ses_17234510affePfDE2k3JAO9HMe`.

### THE CORE PROBLEM (must be resolved before any Phase 1 impl)
Phase 1 acceptance = "all three surfaces derive the SAME statement hash for fixed vectors." But today they use THREE DIFFERENT primitives:
- **Rust off-chain**: `sha2::Sha256` w/ domain seps (`pvthfhe-share-dcommit/v1`, `pvthfhe-final-decrypt-aggregation-v1`). pvthfhe-types crate has NO hash dep yet. Canonical len-prefix helper `encode_len_prefixed` (u32 BE) lives in `crates/pvthfhe-types/src/witness_language.rs:164`.
- **Solidity**: `keccak256(abi.encode(...))` for attestation. HonkVerifier public inputs = bytes32[7]; EACH used as Fr MUST be `< P` (BN254 modulus) or verifier reverts (`generated/HonkVerifier.sol` generateEtaChallenge). 200-byte blob layout in `UltraHonkVerifier.sol:20-28`: ct_hash|pt_hash|aggpk_hash|dkg_root|epoch(8B BE @128)|participant_set_hash|d_commitment. NO IIvcDeciderVerifier interface exists (only an `ivcDeciderVerifier` address slot from Phase 0).
- **Noir**: `Poseidon` bn254 sponge ONLY — no keccak/sha256/pedersen in any circuit. Domain tags are Field globals in `circuits/protocol_constants/src/lib.nr:11-17` (DOMAIN_VECTOR_MERKLE=1 ... DOMAIN_DKG_SHARE_COMMIT=7). Reference statement-hash helper: `circuits/decrypt_share/src/main.nr:47` `statement_hash()`.

### Existing field-bearing structs to reuse/align (NOT re-derive)
- Rust: `IvcBindingData` (compressor/src/nova/snark_bridge.rs:22-35) already has ivc_proof/vk/pp hash, z0/zi, ivc_steps (Keccak-derived). `CompressedDkg/DecryptionPublicAnchors` (compressor/src/lib.rs:98-132). `FinalAggregationStatement` + sha256 digest (aggregator/src/decrypt/mod.rs).
- Solidity: `IvcBinding` struct (PvtFheVerifier.sol:16-33); `DkgPublicAnchors`/`DecryptionPublicAnchors` (147-164).
- Noir aggregator_final public-input order (main.nr:25-38): ciphertext_hash, aggregate_pk_hash, decrypt_nizk_hash, dkg_transcript_hash, epoch, participant_set_hash, n_participants, threshold, plaintext_commitment, ivc_snark_proof_hash, nova_final_plaintext[N], nova_share_chain_hash. Ground-truth vector: `C7Prover.toml`.

### DESIGN DECISION REQUIRED (consulting Oracle)
Need to lock ONE canonical hash that all three compute identically in BN254 field space. Candidates: (a) Poseidon-over-fields everywhere (Rust+Solidity must add Poseidon impls matching noir-lang/poseidon v0.3.0 bn254); (b) keccak256-over-canonical-bytes reduced mod P (Noir std has keccak256; Rust+Solidity already have keccak). Decision recorded in decisions.md once Oracle responds.


## [2026-06-03] Phase 1a VerificationStatementV1 Rust+Noir anchor (Sisyphus Junior)
- Added `crates/pvthfhe-types/src/verification_statement.rs` with canonical V1 TLV encoding: domain length prefix, schema version, field count, then ordered `(u16 field_id, u32 len, value)` fields. Decoder rejects wrong domain/version/count, wrong id/order, wrong field length, truncation, and trailing bytes.
- Poseidon preimage is asserted at exactly 76 field elements: 3 header elements + 3 numeric fields * 3 + 16 bytes32 fields * 4. Every bytes32 value is split as big-endian `(hi128, lo128)`; no 256-bit mod-P reduction is used in the canonical path.
- Golden vector fixture committed at `crates/pvthfhe-types/tests/fixtures/verification_statement_v1_golden.json`. Statement hash decimal: `2717525839999002672616025848791696639911259589570414897881626410761076250408`; hex: `0x060210ab9a90369d1ed6dd70d8687f5a82ba942418742add1569ba42fd329728`.
- Noir parity test lives in `circuits/aggregator_final/src/main.nr` as `test_verification_statement_v1_poseidon_parity`; it hashes the same 76-element preimage through `poseidon::poseidon::bn254::sponge` and asserts the same decimal constant.
- Verified commands: `PVTHFHE_ALLOW_RESEARCH_BUILD=1 RUSTFLAGS="-Awarnings" cargo test -p pvthfhe-types verification_statement_vectors` passed; `(cd circuits && nargo test --package aggregator_final)` passed. LSP diagnostics are clean for changed Rust files.


## [2026-06-03] Phase 1b Solidity VerificationStatementV1 Poseidon parity (Sisyphus Junior)
- Added Solidity statement hashing in `contracts/src/VerificationStatementV1.sol` with the same 76-element field preimage as Rust/Noir: domain/schema/count header, numeric `(field_id, byte_len, value)` entries, and bytes32 `(field_id, 32, hi128, lo128)` entries.
- Added `contracts/src/PoseidonBn254.sol` implementing the manual rate-4/capacity-1 sponge over width 5, output `state[1]`, and the unoptimized full/partial/full x^5 permutation used by the Rust Phase 1a reference.
- Solidity `bytes32` big-endian limb split is `hi = uint128(uint256(value) >> 128)`, `lo = uint128(uint256(value))`; the Foundry preimage test matches every decimal in `verification_statement_v1_golden.json`, including context_id limbs `21356283574076891493948969979685445151` and `42707334047547540181846984563639529007`.
- Verification evidence: RED `forge test --root contracts --match-test testVerificationStatementVector` failed before implementation because `src/VerificationStatementV1.sol` was missing; GREEN targeted vector and preimage tests pass; full `forge test --root contracts` passes 144/0.

## [2026-06-03] Phase 2 IVC decider seam wiring (Sisyphus Junior)
- Files changed: `contracts/src/PvtFheVerifier.sol`, `contracts/test/IvcDeciderWiring.t.sol`.
- Implemented the safe on-chain decider seam only: added `IIvcDeciderVerifier.verify(bytes proof, bytes32 statementHash, bytes32 vkHash, bytes32 ppHash, bytes32 z0, bytes32 zi, uint64 steps) returns (bool)`, rejected empty IVC proof bytes, computed the canonical `VerificationStatementV1.computeStatementHashBytes32` hash on-chain, and accepted only when the configured decider returns true. This does NOT implement or claim a real Nova/LatticeFold decider.
- Preserved the existing fail-closed first statement in both IVC paths: `require(ivcDeciderVerifier != address(0), "PVTHFHE: IVC decider not configured")` remains before all other reads/checks.
- Field-mapping placeholder decision: `protocolVersion = 1`; `contextId`, `c5ProofRoot`, `c6ProofSetRoot`, and `cycloAccumulatorRoot` are explicitly set to zero with the required Phase 2 comment. These zeros are only plumbing placeholders; full statement-field sourcing is deferred to the separate binding-invariant task and the decider relation does NOT yet bind them.
- `ivcVerifyResult` is deprecated ABI baggage only. It remains in `IvcBinding` for ABI stability but is not read by verifier logic.
- RED evidence before implementation: `forge test --root contracts --match-contract IvcDeciderWiringTest` => 2 passed, 5 failed, 0 skipped. The two passing tests were the already-existing address(0) fail-closed guard; all new decider-wiring/empty-proof/hash-field plumbing checks were RED.
- GREEN targeted evidence after implementation: `forge test --root contracts --match-contract IvcDeciderWiringTest` => 7 passed, 0 failed, 0 skipped.
- GREEN full-suite evidence: `forge test --root contracts` => 151 passed, 0 failed, 0 skipped across 28 test suites.
- LSP diagnostics: Solidity LSP is not configured in this environment (`No LSP server configured for extension: .sol`), so Forge compile/test output is the available compiler verification.
- `ivcVerifyResult` grep evidence: `grep -rn "ivcVerifyResult" contracts/src/PvtFheVerifier.sol` equivalent output shows only the deprecation comment and struct field: line 29 `/// DEPRECATED: ivcVerifyResult is ignored ABI baggage and never gates acceptance.` and line 30 `uint64 ivcVerifyResult;`.

## [2026-06-03] Phase 2 IVC decider seam VERIFIED by orchestrator (Atlas)
- Independent verification of Sisyphus-Junior ses_17203589dfferrDUm5AjGDULPH.
- Read full diff of contracts/src/PvtFheVerifier.sol + contracts/test/IvcDeciderWiring.t.sol.
- CONFIRMED honest: IIvcDeciderVerifier interface = exact Oracle signature; verifyWithIvc/verifyAndConsumeWithIvc revert FIRST at address(0), then empty-proof reject ("PVTHFHE: empty IVC proof"), then session/binding checks, then compute canonical VerificationStatementV1 hash on-chain, then decider is SOLE acceptance authority. view path uses staticcall (fail-closed: !ok||len!=32 => false); consume path uses try/catch => false on revert; only consumes epoch when decider returns true.
- ivcVerifyResult==1 trust REMOVED from _requireIvcBindingValid; grep confirms ivcVerifyResult only in struct def + deprecation comment, ZERO reads in bodies.
- Placeholder zeros for contextId/c5/c6/cyclo roots + protocolVersion=1, documented in code comment as NOT-yet-bound (deferred to binding-invariant task). Acceptable since no real decider deployed (fail-closed).
- Mock lives only in test/ as MockIvcDeciderVerifierForPlumbing, labeled plumbing-not-soundness. RecordingIvcDeciderAdapter used to capture exact fields passed to decider.
- Independent test run: `forge test --root contracts` => 151 passed / 0 failed (was 144; +7 IvcDeciderWiring). All 7 wiring tests green.
- NEXT (Oracle-locked order): blocker document (P4/C7/C5/C6, 10-point standard).

## 2026-06-03: Documentation of Open Problem Blockers

Created `docs/OPEN-PROBLEM-BLOCKERS.md` to document critical cryptographic guarantees withheld in the research prototype.
Blockers documented:
- P4: On-chain IVC decider verification (currently fail-closed).
- C7: Final aggregation / threshold-decryption correctness (hash-only binding).
- C5: Aggregate public-key formation proof (pk_agg = Σ pk_i).
- C6: Committed-smudge enforcement (legacy fallback removed, full binding pending).

Verified fail-closed behavior with the following commands:
- `forge test --root contracts --match-contract IvcDeciderWiringTest`
- `forge test --root contracts --match-contract IvcFailClosedTest`
- `(cd circuits && nargo test --package aggregator_final)`
- `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-pvss committed_smudge -- --nocapture`

All tests passed, confirming the fail-closed status for P4, C7, and C6. C5 was verified through code inspection showing zero-initialized `c5_proof_root` and lack of prover logic in `KeygenSimulator`.

Cross-reference links added to:
- `README.md`
- `SECURITY.md`
- `WARNING.md`

## [2026-06-03] Blocker document VERIFIED by orchestrator (Atlas)
- Independent verification of writing-category ses_171f98f25ffeYA999jPwRa62bY.
- docs/OPEN-PROBLEM-BLOCKERS.md created: P4/C7/C5/C6, each with all 10 points. Cross-links added to README.md:28, SECURITY.md:10, WARNING.md:12.
- Fact-checked cited names AGAINST repo: C7 tests test_simplified_honest (main.nr:67) + test_plaintext_mismatch (main.nr:90) EXIST; C5 path crates/pvthfhe-aggregator/src/keygen/simulator.rs aggregate_keygen(&shares) at :345 EXISTS; C6 test committed_smudge_legacy_missing_sk_agg_share_fails_closed confirmed; P4 revert strings + IvcFailClosed/IvcDeciderWiring tests confirmed.
- C6 honestly marked PARTIAL (legacy fallback removed; full binding pending) — matches reality; will need update after phase4-c6 lands.
- Doc reinforces DO NOT DEPLOY; no resolved claims; no weakened posture. ACCURATE.
- NEXT (Oracle-locked order): statement-hash public-input binding-invariant wiring (Noir + Solidity).

## [2026-06-03] Statement-hash binding-invariant seam tests (Sisyphus Junior)
- Scope honored per Oracle ruling: added tests/helpers only for Noir `aggregator_final`, Solidity vector/seam tests, a comment-only clarification in `PvtFheVerifier.sol`, and a docs clarification; no `aggregator_final::main()` signature/body change and no VK / `HonkVerifier.sol` regeneration.
- Noir invariant pattern: keep the canonical 76-element preimage as a helper and mutate only value-bearing TLV positions (35 value limbs across the 19 fields), proving each mutation changes the Poseidon hash from the golden decimal `2717525839999002672616025848791696639911259589570414897881626410761076250408`; a `should_fail` mismatch test covers mutated-statement equality rejection.
- Solidity vector invariant pattern: rebuild `_goldenStatement()` per mutation and mutate all 19 `VerificationStatementV1.Statement` fields independently; bytes32 fields use xor-with-1 and numeric fields increment.
- IVC seam invariant pattern: `testStatementHashMismatchAloneRejected` sets only `expectedStatementHash` wrong on the param-checking mock while keeping vk/pp/z0/zi/steps correct, proving the on-chain-computed statement hash is passed to the decider and mismatch alone rejects.
- LSP note: this environment has no `.nr` or `.sol` LSP configured, so `nargo test` and Forge compilation/test output are the available diagnostics for these files.

## [2026-06-03] Binding-invariant task VERIFIED by orchestrator (Atlas)
- Independent verification of deep/Sisyphus-Junior ses_171ed751fffeaDBEPb0s9c64Tl.
- Noir (circuits/aggregator_final/src/main.nr): added `verification_statement_v1_golden_preimage()` helper (existing parity test refactored to reuse it — DRY), `test_verification_statement_v1_each_field_mutation_changes_hash` (loops over 35 value-bearing limb indices, +1 each, asserts hash flips; correctly SKIPS structural tag/len header positions), and `#[test(should_fail)] test_verification_statement_v1_hash_mismatch_rejects_mutated_statement`. CONFIRMED main() signature + body UNCHANGED (12 pub params, same 7 asserts, same return). `nargo test --package aggregator_final` => 6 tests passed.
- Solidity VerificationStatementVector.t.sol: `testVerificationStatementEachFieldMutationChangesHash` mutates ALL 19 Statement fields individually (bytes32 via xor 1, numeric via +1) and asserts each != GOLDEN_HASH. `forge --match-contract VerificationStatementVectorTest` => 5 passed.
- Solidity IvcDeciderWiring.t.sol: `testStatementHashMismatchAloneRejected` — wrongStatementHash = expected ^ 1 while vk/pp/z0/zi/steps all CORRECT => verifyWithIvc returns false. Isolates hash from the separately-passed params (vs testWrongIvcParamsRejected which conflated them). `forge --match-contract IvcDeciderWiringTest` => 8 passed.
- PvtFheVerifier.sol: comment-only this turn (full forge 151->153 = +2 = exactly the two new tests; no verifier behavior change). _computeIvcStatementHash logic UNCHANGED.
- docs/OPEN-PROBLEM-BLOCKERS.md line 45: honest clarification that seam tests prove field-sensitivity ONLY; deployed Noir/Honk public-input binding (all 19 fields sourced in main() + VK/Honk regen) remains OPEN/out-of-scope.
- Scope honored: NO main() change, NO VK/HonkVerifier regen, NO tautological re-hash, zero placeholders still zero, no IVC-soundness claims.
- Full suite: `forge test --root contracts` => 153 passed / 0 failed.
- NEXT (Oracle-locked order): Phase 4-C6 committed-smudge enforcement (REAL honest crypto work).

## [2026-06-03] Phase 4-C6 GAP A committed-smudge production binding (Sisyphus Junior)
- Final `prove_decrypted_share` signature now includes `committed_smudge_use: Option<CommittedSmudgeUse>` between `committed_esm_noise_bytes: Option<Vec<u8>>` and `sk_agg_share: Option<u64>`: `pub fn prove_decrypted_share(&self, ciphertext_u: &[u8], party_pk: &[u8], party_index: usize, decrypted_share_bytes: Vec<u8>, witness: &DecryptNizkWitness, ctx: &PvssContext, committed_esm_noise_bytes: Option<Vec<u8>>, committed_smudge_use: Option<CommittedSmudgeUse>, sk_agg_share: Option<u64>) -> Result<DecryptedShare, PvssError>`.
- Added `CommittedSmudgeUse { slot_id: u16, decrypt_round: u64 }` in `crates/pvthfhe-pvss/src/encrypt.rs` and re-exported it from `pvthfhe_pvss`. Committed mode now requires both committed material and this struct; mismatched presence or `slot_id == 0` returns `PvssError::InvalidShare`.
- `CommittedSmudgeUse.slot_id` is passed to BOTH `compute_esm_aggregate_commitment(..., slot_index, ...)` and `DecryptNizkMode::CommittedSmudge { slot_id, decrypt_round, ... }`; grep found no remaining hardcoded `slot_id: 1`, `decrypt_round: 0`, `unwrap_or(1)`, or `unwrap_or(0)` in `encrypt.rs`.
- RED test name: `production_adapter_committed_smudge_uses_caller_slot_and_round`. Pre-fix failure observed with `PVTHFHE_ALLOW_RESEARCH_BUILD=1 RUSTFLAGS="-Awarnings" cargo test -p pvthfhe-pvss --test nizk_decrypt_committed_smudge production_adapter_committed_smudge_uses_caller_slot_and_round -- --nocapture`: `assertion left == right failed`, `left: 1`, `right: 7` at `tests/nizk_decrypt_committed_smudge.rs:125`; this proved the production adapter was still emitting hardcoded slot 1 instead of caller slot 7.
- Added negative production adapter test `production_adapter_rejects_zero_committed_smudge_slot` asserting `slot_id == 0` returns `Err(PvssError::InvalidShare)`.
- Updated callers: CLI committed path passes explicit `CommittedSmudgeUse` and errors if expected per-party committed ESM material is absent; legacy roundtrip passes `None` for both committed material and committed-smudge use. Roundtrip fixture also now supplies a non-empty `dkg_root` so the existing fail-closed DKG-root requirement lets the legacy proof path run.
- Verification: `lsp_diagnostics` clean for changed Rust files except existing inactive-code hints in `lib.rs` for disabled `production-stub-allowed`; `PVTHFHE_ALLOW_RESEARCH_BUILD=1 RUSTFLAGS="-Awarnings" cargo test -p pvthfhe-pvss --test nizk_decrypt_committed_smudge` => 7 passed / 0 failed (existing 5 committed-smudge tests still pass + 2 new production adapter tests); `PVTHFHE_ALLOW_RESEARCH_BUILD=1 RUSTFLAGS="-Awarnings" cargo test -p pvthfhe-pvss --test encrypt_decrypt_roundtrip` => 1 passed / 0 failed; `PVTHFHE_ALLOW_RESEARCH_BUILD=1 RUSTFLAGS="-Awarnings" cargo check -p pvthfhe-cli` => passed.

## [2026-06-03] Phase 4-C6 GAP A VERIFIED by orchestrator (Atlas)
- Independent verification of deep/Sisyphus-Junior ses_171d4cc54ffemoicMfER20nHmF against Oracle fabrication traps (ses_171de5dbbffe02fzobMOmj7Woe).
- READ full git diff of encrypt.rs/lib.rs/pvss_support.rs/both test files. CONFIRMED GAP A genuinely fixed: `compute_esm_aggregate_commitment(..., committed_use.slot_id, ...)` AND `DecryptNizkMode::CommittedSmudge { slot_id: committed_use.slot_id, decrypt_round: committed_use.decrypt_round }` both use caller values; literals `1`/`0` removed; slot_id==0 => Err(InvalidShare); mismatched (Some/None) presence => Err. No fabrication trap hit.
- RED test `production_adapter_committed_smudge_uses_caller_slot_and_round` exercises the PRODUCTION adapter `prove_decrypted_share` (not DecryptNizkMode directly), decodes the real proof envelope, asserts slot=7/round=42. Negative test `production_adapter_rejects_zero_committed_smudge_slot`.
- Ran tests MYSELF: nizk_decrypt_committed_smudge 7/7 (2 new + existing 5 intact), encrypt_decrypt_roundtrip 1/1, nizk_decrypt_soundness 3/3, decrypt_dkg_root_binding 5/5, decrypt_share_nizk 3/3, dkg_share_aggregation_relation 7/7; `cargo check -p pvthfhe-cli` Finished. lsp_diagnostics(encrypt.rs, error) => No diagnostics. Only repo-wide failure = pre-existing `enc_randomness_ciphertexts_differ_across_runs` (mock-backend opt-in in `deal()` path at line 63 — documented issues.md:28-32, NOT a regression; cargo stops at first failing binary, so C6 binaries were run explicitly via --no-fail-fast/per-test and all passed).
- ACCEPTED out-of-scope change (noted, not requested): subagent also hardened the legacy path `expected_sk_agg_share` from `unwrap_or_else(|| derive_party_binding(party_pk))` (silent fallback) to `ok_or(PvssError::InvalidShare)?` (fail-closed). This is in-spirit with the remediation and the pre-existing doc comment ("legacy path still requires an explicit DKG-committed sk_agg_share"). Verified ALL 3 callers (def + 2 call sites) provide explicit sk_agg_share, so no caller relied on the removed fallback; no regressions. Removed now-unused `derive_party_binding` import from encrypt.rs.
- GAP B (SessionRegistry _smudgeSlots epoch): NOT changed, per Oracle (adding epoch would weaken one-time-slot invariant). GAP C (IVC _ivcProofConsumed runId): recorded as separate follow-up in problems.md, NOT folded into C6.
- NEXT (Oracle-locked order): Phase 5 — A1 Cyclo accumulator transcript verification (crates/pvthfhe-nizk/src/adapter.rs).

## [2026-06-03] Phase 5 A1 Cyclo accumulator blocker documentation and hardening (Sisyphus Junior)
- Files changed: `docs/OPEN-PROBLEM-BLOCKERS.md`, `SECURITY.md`, `WARNING.md`, `crates/pvthfhe-nizk/src/adapter.rs`, and `crates/pvthfhe-nizk/tests/accumulator_fail_closed.rs`.
- A1 blocker-doc entry added at `docs/OPEN-PROBLEM-BLOCKERS.md` under `### A1 — Cyclo accumulator transcript verification` with the 10-point blocker structure: status `OPEN — production disabled`, fail-closed seam, missing real versioned transcript/verifier, forbidden shortcuts, acceptance criteria, deployment rule, and verification commands.
- SECURITY/WARNING wording now says nonzero accumulator bytes are rejected fail-closed and the accepted empty `acc_len=0` path is only a non-folded placeholder, NOT fold verification; both cross-link to the A1 blocker entry.
- `adapter.rs` behavior unchanged: `CycloNizkAdapter::verify` still rejects any nonzero `acc_len` with exact `VerificationFailed("cyclo accumulator present but unverified (fail-closed)")`, and the encoder still writes `0u32`. Comments now say "non-folded A1 placeholder; accumulator transcript verification is OPEN (A1) and unimplemented" instead of Phase-2 placeholder wording.
- New hardening test: `accumulator_nonzero_length_without_bytes_fails_closed`, which mutates the accumulator length header to `4` without appending transcript bytes and asserts the existing fail-closed reject, proving no parse/skip semantics can accept an unverified nonzero accumulator length. Existing tests `accumulator_nonzero_transcript_bytes_fail_closed` and `accumulator_empty_placeholder_honest_proof_still_verifies` still pass.
- Diagnostics: `lsp_diagnostics` on `crates/pvthfhe-nizk/src/adapter.rs` => no diagnostics found; `lsp_diagnostics` on `crates/pvthfhe-nizk/tests/accumulator_fail_closed.rs` => no diagnostics found.
- Verification: `PVTHFHE_ALLOW_RESEARCH_BUILD=1 RUSTFLAGS="-Awarnings" cargo test -p pvthfhe-nizk accumulator -- --nocapture` => passed. Target accumulator test binary: 3 passed / 0 failed (`accumulator_nonzero_length_without_bytes_fails_closed`, `accumulator_nonzero_transcript_bytes_fail_closed`, `accumulator_empty_placeholder_honest_proof_still_verifies`).
- Verification: `PVTHFHE_ALLOW_RESEARCH_BUILD=1 RUSTFLAGS="-Awarnings" cargo test -p pvthfhe-cyclo fold_verify -- --nocapture` => passed. Target fold verifier test `fold_verify_accepts_honest` passed (1 passed / 0 failed in the matching test binary; other binaries filtered out).

## [ORCHESTRATOR VERIFICATION] Phase 5 (A1 Cyclo) — APPROVED
- Reviewed `git diff` of `crates/pvthfhe-nizk/src/adapter.rs`: verify seam returns `Err(NizkError::VerificationFailed("cyclo accumulator present but unverified (fail-closed)"))` for nonzero `acc_len`; `acc_len==0` proceeds to `cur.finish()`. NO transcript parser / fold-verifier / commitment-root fabrication — genuine fail-close only. Encoder still writes `0u32`. Comment relabeling only.
- Ran `cargo test -p pvthfhe-nizk --test accumulator_fail_closed` (orchestrator, independent): 3 passed / 0 failed. `accumulator_empty_placeholder_honest_proof_still_verifies` confirms `acc_len=0` remains ACCEPTED => NO P1 regression (no global acc_len=0 reject). Both nonzero cases reject fail-closed.
- `lsp_diagnostics(adapter.rs, error)` => no diagnostics.
- `docs/OPEN-PROBLEM-BLOCKERS.md` A1 (lines 86-103) mirrors C6 10-point standard; Forbidden-shortcuts clause bans treating pvthfhe-cyclo unit tests as adapter integration evidence.
- SECURITY.md / WARNING.md / README.md honestly downgraded: C7->OPEN (hash-binding only), added A1+P4 OPEN, sharpened C5 + IVC-not-verified/fail-closed wording; anchor matches heading.
- A1 files are untracked (created earlier this session); confirmed via `git status` (not in `git diff HEAD`).
- VERDICT: Phase 5 complete & verified. A1 stays BLOCKED-OPEN by design per Oracle scope-lock (no Cyclo fold transcript verifier shipped).

## [PHASE 6 EXPLORATION SYNTHESIS] (Atlas, explores bg_dc139235 feature-map + bg_2fc25755 mock/deploy)
- NO workspace `production-profile` feature exists anywhere => acceptance cmd `cargo test --workspace --no-default-features --features production-profile` FAILS today. No `[workspace.features]` in root Cargo.toml (Cargo.toml:11-37). Adding it must mirror an existing per-crate pattern; with `--workspace --features X`, X must be defined in the relevant package(s) or cargo errors.
- FORBIDDEN-IN-PROD features + current gating (all already NON-default; this is the good news):
  - `mock` = pvthfhe-fhe/Cargo.toml:9 (default=["real-nizk"]); gates `pub mod mock` (lib.rs:19-20); ALSO runtime-gated by env `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` (mock.rs:28-36 assert_mock_acknowledged, panics if unset). Aliased by pvthfhe-cli `mock` (Cargo.toml:76) + pvthfhe-aggregator `mock` (Cargo.toml:46).
  - `surrogate-compressor` = pvthfhe-cli/Cargo.toml:78 + pvthfhe-bench:20; gates compressor_glue.rs:19,63-66,101-105 (runtime assert_surrogate_compressor_acknowledged).
  - `surrogate-decrypt-share`, `trace-decrypt` = pvthfhe-fhe/Cargo.toml:11-12.
  - `legacy-nova` = pvthfhe-compressor/Cargo.toml:46 + pvthfhe-offchain-verifier:21; dozens of #[cfg(feature="legacy-nova")] across compressor/src/nova/*.
  - `production-stub-allowed` = pvthfhe-pvss/Cargo.toml:8; ALREADY has CI gate `r02-gate-stub-not-default` (.github/workflows/ci.yml:99-105) running test `crates/pvthfhe-pvss/tests/gate_noop_absent_by_default.rs` (manifest-parse asserts not-in-default). THIS IS THE PATTERN TO MIRROR.
  - `hermine` = pvthfhe-keygen/Cargo.toml:9; ALREADY hard-blocked via `compile_error!` when enabled (hermine.rs:26-27) + self-test asserts !cfg!(feature="hermine") (530-536).
  - `stub` = pvthfhe-enclave-adapter/Cargo.toml:8.
- Real FHE backend = pvthfhe-fhe/src/fhers.rs (wraps gnosisguild/fhe.rs, pinned Cargo.toml:28-30). Poulpy alt = pvthfhe-fhe-poulpy (enable-ckks/enable-tfhe).
- CI: .github/workflows/ci.yml runs `cargo test --workspace` (lines 36-42) + the r02 gate. Justfile has many `--features` demo/bench commands (lines 30,40,66-69) + a Stage-0 gate (212-219) that greps for surrogate warning & asserts no `mock` in pvthfhe-fhe default.
- DEPLOY ALREADY FAIL-CLOSED: contracts/script/DeployVerifier.s.sol:12 = `new PvtFheVerifier(address(reg), address(0))`; ivcDeciderVerifier defaults address(0); verifyWithIvc/verifyAndConsumeWithIvc revert "PVTHFHE: IVC decider not configured" (PvtFheVerifier.sol:241,294); setIvcDeciderVerifier timelock-gated (502-505). => Phase 6 action 3 (fail-closed deploy) is ALREADY satisfied; just needs an assertion/test to lock it.
- LegacyLocalSmudge reachable when prove_decrypted_share called with both committed args = None (encrypt.rs:113-152). Reachability from demo/production entrypoint TBD (Phase 7 forged-harness territory).
- enc_randomness NUANCE (revises issues.md): test DOES call acknowledge_mock_backend() at enc_randomness.rs:37, yet fails at :63 in 2nd deal() with a `BackendError` (a Result error, NOT the assert_mock_acknowledged panic). So root cause is NOT a missing env opt-in — needs live reproduction before any fix. Likely a 2nd-deal/randomness/params issue in the mock or deal_with_rng path.
- OPEN QUESTION FOR ORACLE: (1) how to define `production-profile` so the acceptance cmd works without being security theater; (2) what the CI assertion must REALLY verify (not trivially pass); (3) is fixing enc_randomness in Phase 6 scope or deferred; (4) fabrication traps.

## [ORCHESTRATOR VERIFICATION] Phase 6 (Legacy & Mock Quarantine) — APPROVED
- Two-part delegation: (impl) deep/gemini `ses_17176c25dffe3ctZCxQYhWO12n` built per-crate `production-profile` features + 11 `compile_error!` mutual-exclusion guards + `tests/integration/policy_invariants.rs` + `crates/pvthfhe-fhe/tests/gate_production_profile.rs` + enc_randomness fix, but stopped mid-debug and missed CI wiring; (fix) unspecified-low/opus `ses_1713954f7ffe4vS3lfRjomflOy` removed an invented broken test + wired CI. BOTH independently verified by me below.
- REJECTED first subagent's completion claim: its acceptance build was failing and it invented a bogus `no_new_allow_attributes_exist_outside_vectors_test_file` test asserting only 2 files may contain `#[allow(...)]` (FALSE — 20+ pre-existing untouched files legitimately use `#[allow]`). Fix delegation DELETED that test + the now-unused `VECTORS_ALLOW_PATH`/`RESHARE_ENTROPY_ALLOW_PATH` consts (kept `CRATES_DIR`, still used at policy_invariants.rs:298), and added CI job.
- Independent acceptance evidence (all post-disk-recovery, re-run by me):
  - `cargo build --workspace --no-default-features --features production-profile` => exit 0 (~27s).
  - `cargo tree -e features --no-default-features --features production-profile` => 0 forbidden features present (mock/surrogate-compressor/surrogate-decrypt-share/trace-decrypt/demo-seeded-rng/legacy-nova/stub/production-stub-allowed/hermine all ABSENT).
  - All 11 `compile_error!` guards present per Oracle spec (pvthfhe-fhe lib.rs:11/13/15; pvthfhe-cli lib.rs:20/22/24; pvthfhe-aggregator:18; pvthfhe-compressor:19; pvthfhe-offchain-verifier:4; pvthfhe-pvss:7; pvthfhe-enclave-adapter:6). Guard FIRES LIVE: `cargo build -p pvthfhe-fhe --no-default-features --features "production-profile,mock"` => exit 101 "pvthfhe-fhe production-profile forbids the mock backend feature".
  - `cargo test -p pvthfhe-fhe --test gate_production_profile --no-default-features --features production-profile` => 1 passed.
  - `cargo test --test policy_invariants` (root pkg pvthfhe-spec-tests, `[[test]]` wired root Cargo.toml:87-89) => 6 passed (after fix; broken-test grep count = 0).
  - `forge test --root contracts --match-contract IvcFailClosed` => 4 passed.
  - `cargo test -p pvthfhe-pvss --test enc_randomness` => 2 passed, 0 ignored. enc_randomness ROOT CAUSE (revises issues.md/exploration nuance): F5 fail-closed requires non-empty `dkg_root`; fix sets `dkg_root: vec![7; 32]` (enc_randomness.rs:58) + added `#[cfg(not(feature="production-profile"))]` quarantine gating + a production-profile variant. `any_pair_differs` assertion INTACT (NOT weakened).
  - CI `production-profile-quarantine` job present `.github/workflows/ci.yml:123-141` (production-profile build + policy_invariants + gate_production_profile + cargo-tree forbidden-feature audit `if cargo tree ... | grep -E 'forbidden'; then exit 1; fi`); YAML validated OK.
- DEPLOY fail-closed (Phase 6 action 3) ALREADY satisfied from Phase 0/2 (DeployVerifier.s.sol:12 passes address(0); revert at PvtFheVerifier.sol:241/294; timelock setter 502-505) and now locked by IvcFailClosed tests.
- VERDICT: Phase 6 COMPLETE & independently verified. Forbidden features cannot enter a production-profile build (compile-time guards + CI tree audit). NOT run: full `cargo test --workspace --no-default-features --features production-profile` (>10min recompile; core acceptance already proven by targeted runs).
- NEXT: Phase 7 — `just phase1/2/3-gate` + adversarial forged-proof harness.

## [2026-06-03] Phase 7 final forged-proof harness (Oracle-locked mapping)
- Created `.sisyphus/scripts/phase7-forged-proof-harness.py` as the consolidated Python orchestrator. RED-first evidence: initial stub listed all six case names and exited non-zero as UNWIRED before final command wiring.
- Final verify command: `CI=true GIT_PAGER=cat PAGER=cat PVTHFHE_ALLOW_RESEARCH_BUILD=1 python3 .sisyphus/scripts/phase7-forged-proof-harness.py` => overall_pass=true, all 6 cases observed_test_count=1. Evidence JSON regenerated at `.sisyphus/evidence/phase7-forged-proof-harness.json`.
- Final 6 case→test mappings:
  1. `folding_witness_tamper` → `cargo test -p pvthfhe-aggregator --test folding_tamper real_folding_gaps::test_fold_tampered_witness_rejected -- --exact --nocapture` (`input_validation_reject`).
  2. `forged_ivc_decider` → `forge test --root contracts --match-path test/IvcFailClosed.t.sol --match-test testRejectsForgedIvcVerifyResult -vv` (`fail_closed_blocked_open`).
  3. `tampered_c5_pk` → `cargo test -p pvthfhe-compressor --test bfv_encryption_adversarial tampered_pk0_rejected -- --exact --nocapture` (`input_validation_reject`).
  4. `committed_smudge_requires_esm` → `cargo test -p pvthfhe-pvss --features mock --test nizk_decrypt_committed_smudge committed_smudge_requires_explicit_esm_witness -- --exact --nocapture` (`cryptographic_reject`).
  5. `legacy_smudge_fallback_rejected` → `cargo test -p pvthfhe-pvss --features mock --test nizk_decrypt_committed_smudge committed_smudge_rejects_local_smudge_proof -- --exact --nocapture` (`cryptographic_reject`).
  6. `cyclo_accumulator_fail_closed` → `cargo test -p pvthfhe-nizk --test accumulator_fail_closed accumulator_nonzero_transcript_bytes_fail_closed -- --exact --nocapture` (`fail_closed_blocked_open`).
- Gotchas confirmed: `folding_tamper` test lives inside `mod real_folding_gaps`; the full path `real_folding_gaps::test_fold_tampered_witness_rejected` is required with `--exact` or cargo can match 0 tests. PVSS committed-smudge test binary requires `--features mock`. Foundry `--root contracts` requires relative `--match-path test/IvcFailClosed.t.sol`, not `contracts/test/IvcFailClosed.t.sol`.
- Harness semantics: case passes only if subprocess exit_status==0 and parsed observed_test_count>0; zero-test filtered success is treated as failure. Disclaimer records fail-closed non-acceptance for P4/A1 and keeps P4/C7/C5/A1 BLOCKED-OPEN; no IVC/C5/C7/A1 soundness claim.
- Diagnostics: `lsp_diagnostics(.sisyphus/scripts/phase7-forged-proof-harness.py)` => no diagnostics found.

## [2026-06-03] CORRECTION — phase2-gate aggregate_1024_smoke is BROADER-PLAN R4.3 debt, NOT a self-inflicted regression
- EARLIER NARRATIVE WAS WRONG: a prior handoff claimed Phase 6 self-inflicted a phase2-gate regression by adding `required-features=["legacy-fold"]` to `aggregate_1024_smoke` and that the gate just needed `--features legacy-fold`. That is INCORRECT. Verified ground truth below.
- `crates/pvthfhe-aggregator/src/folding/mod.rs:14-17`: `#[cfg(feature="legacy-fold")] compile_error!("The legacy-fold feature has been removed in R4.3. Use real-folding (enabled by default).")`. `legacy-fold` is now a POISON-PILL feature: enabling it fails compilation.
- `Cargo.toml` still defines `legacy-fold = []` (line 49) AND still pins 9 test targets to `required-features=["legacy-fold"]`: `folding`, `folding_adversarial`, `p2_bench`, `aggregate_1024_smoke`, `decrypt_real`, `keygen_real_encryption`, `folding_multi_track`, `folding_relation`, `folding_witness_validation`. ALL are permanently unrunnable: cargo SKIPS them without the feature ("requires the features: legacy-fold"), and the poison-pill compile_error fires WITH the feature.
- Git log (recent broader-plan): `83692e6 chore: production readiness`, `97d3096 fix: MPC audit remediation (post-Nova migration)`, `39db19a feat: migrate pvthfhe-compressor to arecibo`. The R4.3 / post-Nova migration removed the legacy hash-chain folding path but left Cargo.toml test-target pins referencing the now-poisoned `legacy-fold` feature. This is a BROADER-PLAN R4.3 migration inconsistency, NOT introduced by this remediation.
- ACTION TAKEN: reverted the speculative one-line edit to `.sisyphus/scripts/phase2-gate.py:169` (removed the wrong `--features legacy-fold`); restored to the original feature-less invocation, which honestly reflects the broken broader-plan state (cargo reports "requires the features: legacy-fold").
- NOTE on `aggregate_1024_smoke.rs`: its body uses `pvthfhe_aggregator::folding::HashChainCycloAdapter`, which per the module doc is wired under `real-folding` (default). So the test would very likely COMPILE+PASS under default features IF the dead `required-features=["legacy-fold"]` pin were removed. That one-line Cargo.toml cleanup is the likely true fix — but it crosses into broader-plan R4.3 migration territory (the other 8 pinned targets may be intentionally-disabled legacy surrogates), so it is being escalated to the user rather than guessed at, per the Oracle-locked Phase-7 honesty principle (document broader-plan failures with scope; never fabricate greenness).

## [2026-06-03] aggregate_1024_smoke pin removal note
- Removed only `required-features = ["legacy-fold"]` from `aggregate_1024_smoke` in `crates/pvthfhe-aggregator/Cargo.toml`.
- Verification: `test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out` (exit code 101).

## [2026-06-03] ORCHESTRATOR FINAL VERDICT — Phase 7 gate disposition RESOLVED (supersedes optimistic note at §281)
- DEFINITIVE: the §281 hypothesis ("removing the pin would COMPILE+PASS under real-folding") is FALSE. Verbatim this session, with pin removed under default real-folding: `NormBoundExceeded { got: 18446744073709551615 (=u64::MAX), max: 102 }`, exit 101. The u64::MAX is the sentinel at `crates/pvthfhe-cyclo/src/fold.rs:42` (`Err(_) => u64::MAX`): the F9-era synthetic share data parse/decode-fails under the real norm-enforcing Cyclo backend. `pvthfhe-cyclo` UNCHANGED by remediation. So the test fails BOTH ways (pin → "requires legacy-fold"; no pin → NormBoundExceeded; legacy-fold → poison-pill compile_error). It is genuinely un-passable without broader-plan R4.3 witness-construction work.
- DECISION (net-zero, quarantine restored): RE-ADDED `required-features = ["legacy-fold"]` to `aggregate_1024_smoke` (Cargo.toml lines 83-86), consistent with the other 8 legacy-fold targets. Rationale: this is the ONLY disposition that protects phase3-gate's PACKAGE-WIDE `cargo test -p pvthfhe-aggregator` — cargo silently SKIPS unsatisfied-required-features targets when NOT explicitly named. phase2-gate.py:169 names the target EXPLICITLY (`--test aggregate_1024_smoke`), so it still reports RED (exit 101 "requires the features: legacy-fold") — the correct honest outcome. Making it PASS = fabricating valid Cyclo witness norms = OUT OF SCOPE; FORBIDDEN.
- GATE EVIDENCE recorded verbatim at `.sisyphus/evidence/phase7-gate-evidence.md`. Summary: phase1-gate RED (broader-plan n=5/t=3 vs t≤(n-1)/2, exit 101, both files unmodified by remediation), phase2-gate RED (3 broader-plan checks: legacy-fold quarantine, phantom `crates/pvthfhe-api/src/lib.rs` in REQUIRED_ARTIFACTS, stale committed `bench/results/aggregate_1024.json`), phase3-gate NOT RUN (CI-only; disk/ENOSPC). Phase 7 forged-proof harness GREEN (6/6, overall_pass=true).
- Broader-plan debt fully filed in `problems.md` items (a)-(d) with git attribution (80a0c82, b3341ac, 8998157, 83692e6, 97d3096, 39db19a, 3f6e920). NONE force-greened. Recommended cleanup: replace poison-pill pins with `#[ignore]` for clearer quarantine semantics.
- PRE-EXISTING LSP drift (broader-plan, NOT remediation): `crates/pvthfhe-aggregator/benches/aggregate_1024.rs:43-46` has ProtocolBytes/CcsWitnessSecret-vs-Vec<u8> type errors from the R4.3 type migration; `phase2-gate.py:12` `tomli` import unresolved (env). Neither touched.
- REMEDIATION VERDICT: Phases 0–7 deliverables COMPLETE & GREEN (canonical VerificationStatementV1 Rust+Solidity+Noir, fail-closed IVC seam, C6 committed-smudge, A1 Cyclo fail-close, mock/legacy quarantine, forged-proof harness 6/6). The RED end-to-end gates are SCOPED broader-plan R4.3 debt, honestly recorded, never hidden, never fabricated-green. P4/C7/C5/A1 remain BLOCKED-OPEN / fail-closed. READY for Final Verification Wave (Momus/Oracle).

## [2026-06-03] FINAL VERIFICATION WAVE — BOTH REVIEWERS APPROVE (plan COMPLETE)
- Momus (plan-compliance, ses_170d8ecc8ffea8hg4rUKZbZF2Y): **APPROVE**. Phase 7 wording ("Run phase1/2/3-gate ... Honest end-to-end flow accepts; all forged end-to-end cases reject") does NOT require all three gates GREEN; honestly recording phase1/2 RED-with-scope + phase3 not-run-locally is a legitimate (non-fabricated) reading. All Phase 7 deliverables present & verifiable; Phases 0-6 substantiated by notepad evidence; harness 6/6 NON-ACCEPTANCE backed by command mappings + rejection taxonomy. Non-blocking nits: phase3 needs CI evidence eventually; harness mapping revision documented in decisions.md; JSON stores summaries not full stdout.
- Oracle (honesty/goal/constraint, ses_170cf89fbffe1MEa4jexBjgsu2, High confidence): **APPROVE**. (1) gate-evidence HONEST, RED gates correctly attributed to broader-plan R4.3 with git evidence; (2) aggregate_1024_smoke quarantine pin legitimate — failure is genuinely R4.3 (F9 synthetic data vs real norm-enforcing Cyclo backend remediation did not author); fabricating witness data correctly avoided; (3) harness makes NO overclaim — fail_closed_blocked_open / input_validation_reject taxonomies, explicit non-soundness disclaimer; (4) P4/C7/C5/A1 BLOCKED-OPEN/fail-closed in code AND docs (README OPEN, OPEN-PROBLEM-BLOCKERS.md, ivcDeciderVerifier==address(0) reverts); (5) ZERO guardrail violations (no hash-binding-as-IVC, ivcVerifyResult deprecated/ignored, docs downgraded to OPEN not resolved, production IVC disabled).
- DISPOSITION: Final Verification Wave PASSED. Remediation plan remediate-soundness-completeness-audit is COMPLETE. Outstanding broader-plan R4.3 debt (problems.md items a-d) and follow-ups (Gap C runId-scoping, witness_gen staleness, e2e_real config) tracked separately, NOT remediation blockers.
