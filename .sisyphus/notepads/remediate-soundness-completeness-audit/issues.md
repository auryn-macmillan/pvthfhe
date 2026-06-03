## Documentation Correction (F7 Remediation)
Corrected overstated cryptographic guarantees across project documentation.

### Changes:
- **README.md**:
    - Added `DO NOT DEPLOY` to the top banner.
    - Updated Status table: "On-chain" and "Decrypt" marked as `⚠️ OPEN` with footnotes.
    - Added P4, C5, C7, and A1 to "Open Problems" table as `OPEN`.
- **SECURITY.md**:
    - Updated "On-chain verifier" and "On-Chain Verification: IVC Binding" sections to reflect lack of cryptographic verification and fail-closed state.
    - Updated C5 and C7 descriptions to accurately reflect their `OPEN` status.
    - Added P4 and A1 (Cyclo accumulator) as `OPEN`.
    - Updated "Trust Boundary" table to reflect unverified states.
- **WARNING.md**:
    - Explicitly listed the 4 unverified guarantees: On-chain IVC, C7 hash-only binding, C5 missing proof, and Cyclo transcript skipping.
- **ARCHITECTURE.md**:
    - Updated "On-Chain Verification", "Transparent IVC", and "C7 Merkle aggregation" descriptions to include caveats about unverified status.
    - Added a "CAVEATS" section to "End-to-End Verifiability".
- **STATUS.md**:
    - Aligned implementation claims with actual unverified status of IVC, C7, and C5.

### Corrected Overstatements:
1. **P4 On-chain IVC**: Previously implied full binding and verification; now marked as not cryptographically verified and fail-closed.
2. **C5 PK Aggregation**: Documented that there is no public proof that `pk_agg = Σ pk_i`.
3. **C7 Final Aggregation**: Previously marked as RESOLVED; now marked as OPEN, proving only hash binding and not decryption correctness.
4. **Cyclo Accumulator**: Explicitly noted that transcript bytes are skipped and not verified.

## [Phase 0 closure] Pre-existing pvss test failure — NOT a regression
- `cargo test -p pvthfhe-pvss --test enc_randomness enc_randomness_ciphertexts_differ_across_runs` FAILS with `BackendError(<redacted>)` panicking at `tests/enc_randomness.rs:63` inside `deal()`.
- PROVEN pre-existing: `git stash` of ONLY `src/encrypt.rs` + `src/nizk_decrypt.rs`, re-ran the test → fails IDENTICALLY (same line 63, same BackendError). Our F5 fail-closed edits are clean.
- Root cause: mock FHE backend not opted in (`deal()` path). Error type is FHE `BackendError`, NOT our `PvssError::InvalidShare`. Unrelated to soundness remediation.
- ACTION for later phases: this test needs the mock backend env opt-in or a real backend; track under Phase 6 (mock quarantine) / backend wiring, not Phase 0.

## [2026-06-03] Phase 2 IVC decider seam gotchas
- Solidity LSP diagnostics are unavailable in this environment (`No LSP server configured for extension: .sol`); used `forge test --root contracts` as compiler/build verification instead.
- `verifyWithIvc` is `view`, so a recording mock cannot persist calldata from that path under `staticcall`. The exact-field recording test uses `verifyAndConsumeWithIvc`; `verifyWithIvc` still exercises the same statement-hash and decider-call construction through the non-recording/param-checking tests.

## [2026-06-03] Phase 4-C6 DISCOVERY: committed-smudge infra largely PRE-EXISTS (Atlas, explore bg_9687d86a + bg_fa8cb6ed)
Two explore agents mapped the C6 surface. Sessions: committed-smudge ses_171e26854ffeB4g5X51LLnOGJ5, SessionRegistry ses_171e2479dffeJaOBJBOjqLaQCA. These files are PRE-EXISTING (not in this session's changed-files list), so C6 infra predates the remediation plan.

ALREADY BOUND in DecryptNizkMode::CommittedSmudge (crates/pvthfhe-pvss/src/nizk_decrypt.rs:34-54): slot_id, decrypt_round, ciphertext_hash, accepted_participant_ids, sk_agg_commit, esm_agg_commit. DecryptNizkStatement (56-81) carries session_id, party_index, ciphertext_u/v, epoch, dkg_root, expected_sk_agg_share, dealer_index. validate_mode checks ciphertext_hash recompute (292-296). validate_witness cross-checks witness sk_agg_share/esm_agg_share vs compute_sk/esm_aggregate_commitment (336-356). Commitment hashing in dkg_aggregation.rs:169-213 absorbs session_id+dkg_root+recipient_id+accepted set.
SessionRegistry.sol: _consumed key=(dkgRoot,epoch,runId) (markEpochConsumed 122-129); _smudgeSlots key=(dkgRoot,runId,partyId,slot) storing {consumed,ciphertextHash,decryptRound} (recordSmudgeSlotUse 136-162, reverts SmudgeSlotAlreadyBound on conflicting reuse). PvtFheVerifier.verifyAndConsumeWithSmudgeSlots records each slot then markEpochConsumed (386-389). _ivcProofConsumed key=(dkgRoot,epoch)->ivcProofHash (188-191,623-627).
Rust SmudgeSlotRegistry slot_registry.rs key=(session_id,party_id,slot_id); keygen-spec variant "session_id:party_id:slot_index".
Existing tests (nizk_decrypt_committed_smudge.rs): committed_smudge_requires_explicit_esm_witness, committed_smudge_rejects_local_smudge_proof, committed_smudge_legacy_missing_sk_agg_share_fails_closed, committed_smudge_binds_slot_round_and_aggregate_commitments, red_committed_smudge_esm_share_binding.

RESIDUAL GAPS (candidate Phase 4-C6 honest work):
- GAP A (real soundness): encrypt.rs::prove_decrypted_share HARDCODES slot_id:1, decrypt_round:0 (lines 124-130). Production proving path never varies slot/round => per-round replay binding inert in practice.
- GAP B: _smudgeSlots key omits epoch => potential cross-epoch slot reuse within a run.
- GAP C: _ivcProofConsumed not runId-scoped (abort+restart reuse).
ACTION: consult Oracle to lock precise honest scope + fabrication traps before delegating.
