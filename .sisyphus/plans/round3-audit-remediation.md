# Round 3 Remediation Plan

**Created**: 2026-05-12
**Trigger**: 5-dimensional Round 3 audit — 36/36 checks PASS, 6 remaining integration gaps
**Findings**: 0 CRITICAL, 0 HIGH, 3 MEDIUM, 3 LOW

---

## MEDIUM — Batch A

### A.1 — Wire CommittedSmudge mode into demo pipeline
- [ ] **Code**: `crates/pvthfhe-cli/src/full_pipeline.rs` line 359 — change `DecryptNizkMode::LegacyLocalSmudge` to `DecryptNizkMode::CommittedSmudge { ... }` when committed esm data is available from the DKG transcript. Extract `slot_id`, `decrypt_round`, `ciphertext_hash`, `accepted_participant_ids`, `sk_agg_commit`, `esm_agg_commit` from `transcript.round3_aggregate` or the `KeygenSimulator` output.
- [ ] **Code**: `crates/pvthfhe-cli/src/pvss_support.rs` lines 102-103 — pass actual committed esm noise bytes and sk_agg_share from the DKG transcript instead of `None`
- [ ] **Theory**: `.sisyphus/design/smudging.md` — update §12.2 to note C6 is now exercised in the demo pipeline
- [ ] **Docs**: `README.md` — update C6 status from "partial" to "implemented"
- [ ] **Gate**: `just demo-e2e 10` passes with CommittedSmudge mode active

### A.2 — Populate sk_agg_share/esm_agg_share from DKG commitments
- [ ] **Code**: `crates/pvthfhe-cli/src/full_pipeline.rs` — after `compute_party_sk_sums`, extract per-party `sk_agg_share` values from the `party_states` and store them. Pass them into the `DecryptNizkWitness` at the partial-decrypt step.
- [ ] **Code**: `crates/pvthfhe-pvss/src/encrypt.rs` — the `prove_decrypted_share` function already accepts `sk_agg_share: Option<u64>` and `committed_esm_noise_bytes: Option<Vec<u8>>` — ensure these flow end-to-end from the DKG transcript through the PVSS adapter into the NIZK witness.
- [ ] **Gate**: `just demo-e2e 10` passes. Per-share decrypt NIZK proofs carry `CommittedSmudge` mode with real DKG-derived values.

### A.3 — Fix aggregator NIZK trivial check
- [ ] **Code**: `crates/pvthfhe-aggregator/src/decrypt/mod.rs` line 139 — replace `nizk: ProtocolBytes(vec![1])` with a real `DecryptNizkProof` produced by the backend's `partial_decrypt_with_witness`. Line 212-216 — replace `nizk[0] != 1` tautology with actual `DecryptNizkVerifier::verify` call.
- [ ] **Gate**: PVSS tests pass. No trivial NIZK checks remain in the aggregator path.

---

## LOW — Batch B

### B.1 — Use transcript.dkg_root instead of session_id
- [ ] **Code**: `crates/pvthfhe-cli/src/full_pipeline.rs` line 358 — replace `dkg_root: session_id.as_bytes().to_vec()` with `dkg_root: transcript.dkg_root.to_vec()`
- [ ] **Code**: `crates/pvthfhe-cli/src/pvss_support.rs` line 50 — same replacement
- [ ] **Gate**: Build passes. `dkg_root` now carries the actual Merkle root from the DKG transcript.

### B.2 — Replace C1 key component stubs
- [ ] **Code**: `crates/pvthfhe-keygen-spec/src/lib.rs` lines 734-735 — replace `format!("{}01", self.transcript_root.0)` and `format!("{}02", self.proof_bytes.0)` with actual BFV public key component serialization. Extract `crp` and `b_poly` from the keygen shares and serialize them as hex blobs.
- [ ] **Gate**: KAT tests pass. No hex-label stubs remain in BFVPublicKey derivation.

### B.3 — Document onchain/noir stubs
- [ ] **Docs**: `SECURITY.md` — add note: "`onchain_verify`, `noir_decrypt_share`, `noir_aggregator_final`, `noir_sonobe_wrap` phases in the bench binary are timing-only markers. No Solidity verifier or Noir circuit is executed." 
- [ ] **Gate**: Documentation only.

---

## Execution order

| Batch | Tasks | Depends on | Effort |
|-------|-------|------------|--------|
| **A** (MEDIUM) | 3 | None | ~2h |
| **B** (LOW) | 3 | None | ~30min |

All tasks independent. Delegate in parallel.

## Acceptance criteria

- [ ] A.1: `just demo-e2e 10` runs with CommittedSmudge mode
- [ ] A.2: Per-share NIZK proofs carry DKG-derived sk_agg_share/esm_agg_share
- [ ] A.3: Aggregator NIZK check is real, not trivial tautology
- [ ] B.1: `dkg_root` uses `transcript.dkg_root`, not `session_id`
- [ ] B.2: C1 key components are real serialization, not hex-label stubs
- [ ] B.3: onchain/noir stub status documented
- [ ] `just demo-e2e 10` passes (`plaintext_roundtrip: OK`, `verify: ACCEPT`)
- [ ] 15 focused PVSS tests pass
- [ ] `cargo build` passes
