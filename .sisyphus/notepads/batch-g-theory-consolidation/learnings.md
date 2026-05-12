# Batch G — Theory Consolidation Learnings

## 2026-05-12 — G.1, G.2, G.3 Executed

### G.1 — Threat Model Update

**Items verified present (already existed):**
- §2.2 Threshold convention: FHE threshold = PVSS threshold ✓
- §7.2 item 8: Logging hygiene ✓

**Items added:**
- §7.2 item 9: Memory hygiene (`Secret<T>` + `ZeroizeOnDrop`) — covers `nizk_decrypt.rs`, `nizk_share.rs`, `encrypt.rs`, `lib.rs`, `fhers.rs`
- §7.2 item 10: Sigma ZK masking seeds fresh per proof (OsRng, non-deterministic) — covers `build_algebraic_proof` and `build_bfv_encryption_proof` in `nizk_share.rs`
- §7.2 item 11: Aggregate key consistency (PB-08 enforcement) — covers `full_pipeline.rs` assertion

**P1/P2/P3 status updated in §7.1:**
- P1: Added note about sigma masking seeds fix (A.1), T2 skeleton, D.1 blocker
- P2: Added note about challenge space |C|=2^16, Lemma 9 heuristic, Sonobe substitute
- P3: Added note about hash-accumulate (3 hashed field elements), not full Ajtai fold

**Document version bumped:** 1.1 → 1.2, date 2026-05-11 → 2026-05-12

### G.2 — Soundness Budget Reconciliation

Created `docs/security-proofs/soundness-budget-reconciliation.md` with:
- Executive summary table mapping aspirational vs actual
- Per-proof-system sections: sigma, bfv_sigma, cyclo_lemma9, sonobe_nova, aggregate_decrypt
- Aspirational bound → actual status mapping table
- Assumption dependency graph
- 5 concrete recommendations

### G.3 — Cross-Verification

**Git analysis:**
- All batches A-F are in a single squash commit `aaacb9e`
- Code (`crates/`): 26 files modified
- Theory (`.sisyphus/design/`): 4 files modified
- Docs (`docs/`, `README.md`, `SECURITY.md`): 3 files modified

**Consistency verified:**
- P1/P2 status: OPEN/conditional across README, SECURITY.md, threat model ✓
- Logging hygiene: SECURITY.md + threat model aligned ✓
- Sigma masking seeds: OsRng/fresh per proof in README, SECURITY.md, threat model ✓
- Soundness budget: All aspirational bounds clearly labeled ✓

**Build:** `cargo build --workspace` passes (pre-existing deprecation warnings only)
