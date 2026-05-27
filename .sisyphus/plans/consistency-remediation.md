# Consistency Remediation Plan

**Created**: 2026-05-12
**Trigger**: Deep consistency review across all documentation, architecture specs, soundness claims, and demo path vs actual code.
**Source**: `.sisyphus/notepads/consistency-review/` (to be created)

## Scope

Address all discrepancies identified in the five-dimensional consistency review:
1. Architecture docs vs actual code structure
2. README/SECURITY.md vs implementation status
3. Backend lock compliance (clean — no changes needed)
4. NIZK soundness claim overstatements
5. Demo-e2e claims vs actual code paths

## Batch A — Phase 1.1: Documentation staleness (immediate fix, no code changes)

### A.1 — Fix SECURITY.md line 17: stale "not yet implemented" claim
- [x] **File**: `SECURITY.md`
- [x] **Change**: Replace `Greco / well-formedness ZK proofs: **not yet implemented**.` with `Greco / well-formedness ZK proofs: **Implemented** (CycloNizkAdapter + bfv_sigma.rs, conditional soundness — see P1).`
- [x] **Gate**: `cargo test -p pvthfhe-cli --test demo_banner` and the integration test `tests/integration/docs_truthful.rs` pass (or adapt them)

### A.2 — Fix WARNING.md: remove stale surrogates claims
- [x] **File**: `WARNING.md`
- [x] **Change**: Remove "Noir circuits are tautological surrogates" and "verifier accepts any proof bytes". Replace with accurate summary of current pipeline: Nova Nova IVC over ToyStepCircuit, conditional soundness, on-chain verify not run by demo.
- [x] **Gate**: Manual review

### A.3 — Fix STATUS.md: identical stale claims to WARNING.md
- [x] **File**: `STATUS.md`
- [x] **Change**: Same as A.2 for the two stale sentences.
- [x] **Gate**: Manual review

### A.4 — Fix ARCHITECTURE.md header banner
- [x] **File**: `ARCHITECTURE.md`
- [x] **Change**: Lines 6-8 — remove "no on-chain cryptographic verification" and "Noir circuits are tautological surrogates" from the header banner. The body of the document is already accurate.
- [x] **Gate**: Manual review

## Batch B — Phase 1.2: Ghost references and soundness overstatements

### B.1 — Fix README.md NIZK row: remove Greco/MPCitH, add conditional caveat
- [x] **File**: `README.md`
- [x] **Change**: Line 24 `NIZK | Greco primary / MPCitH fallback, D2-preimage binding | ✅ Real (witness-free proofs, Ajtai CRS)` → `NIZK | Cyclo-companion Ajtai D2 sigma + BFV sigma (conditional, P1 OPEN) | ⚠️ Real with conditional soundness`
- [x] **Gate**: `tests/integration/docs_truthful.rs` adapts or passes

### B.2 — Fix README.md Soundness Budget: add aspirational qualifiers
- [x] **File**: `README.md`
- [x] **Change**: Lines 50-57 — add parenthetical "(aspirational — depends on P1, P2, P3 resolution)" to `ε_fold = 2⁻¹⁶⁰` and `Composed soundness ≥ 2⁻¹²⁸`. Or move the Soundness Budget table into a clearly labeled "Design Targets" section.
- [x] **Gate**: No automated check; manual review

### B.3 — Fix README.md: add "honest-but-curious" caveat for FHE path
- [x] **File**: `README.md`
- [x] **Change**: Audit Status table — add footnote to FHE row: "† FHE backend assumes honest-but-curious threshold parties (see SECURITY.md §Threat Model)."
- [x] **Gate**: Manual review

### B.4 — Fix `paper/claims-table.md`: P2-T2 status + P3-T1 name
- [x] **File**: `paper/claims-table.md`
- [x] **Change**:
  - Row 14 (P2-T2): Change `PROVED` to `CONTINGENT (depends on Lemma 9/C9 — see docs/security-proofs/lemma9.md)`
  - Row 18 (P3-T1): Rename `On-chain Soundness` to `On-chain Attestation Authorization` and add a footnote clarifying it proves ECDSA authorization, not cryptographic proof soundness.
- [x] **Gate**: Manual review

### B.5 — Fix `docs/security-proofs/p2/T2.md`: add Lemma 9 dependency header
- [x] **File**: `docs/security-proofs/p2/T2.md`
- [x] **Change**: Add front-matter block before the theorem: `**Status: SKELETON — contingent on Lemma 9 (CONJECTURE). See docs/security-proofs/lemma9.md.**`
- [x] **Gate**: Manual review

### B.6 — Fix `crates/pvthfhe-nizk/src/sigma.rs` line 14: qualify soundness claim
- [x] **File**: `crates/pvthfhe-nizk/src/sigma.rs`
- [x] **Change**: Line 14 `//! Binary challenges give negligible soundness error (2^{-N}).` → `//! Binary challenges give negligible special-soundness error (2^{-N}) for the sigma layer. The composed NIZK soundness is conditional — see crate-level docs.`
- [x] **Gate**: `cargo build -p pvthfhe-nizk`

### B.7 — Fix `ARCHITECTURE.md` line 82: aspirational language
- [x] **File**: `ARCHITECTURE.md`
- [x] **Change**: `Cryptographically verified decryption soundness is an implementation task` → `Full decryption soundness is a design goal; the current prototype uses conditional NIZK soundness (see SECURITY.md §P1).`
- [x] **Gate**: Manual review

### B.8 — Fix `SECURITY-ADVISORY-001.md`: mark as RESOLVED or update exploit sketches
- [x] **File**: `SECURITY-ADVISORY-001.md`
- [x] **Change**: Either close as RESOLVED with a post-remediation note, or update exploit sketches C1/C2/C3 to reflect that real constraints now exist (circuits have Poseidon/Lagrange, fold has Ajtai commitments, verifier has real Nova Nova). Remove `STATUS: DRAFT` line.
- [x] **Gate**: Manual review

### B.9 — Fix `docs/security-proofs/interfold-equivalent-pvss.md` line 11: ghost references
- [x] **File**: `docs/security-proofs/interfold-equivalent-pvss.md`
- [x] **Change**: Line 11 `Greco/MPCitH and Sigma protocols` → `Cyclo-companion Ajtai D2 sigma protocol and lattice-native BFV sigma protocol`
- [x] **Gate**: Manual review

## Batch C — Phase 1.3: Architecture design docs sync

### C.1 — Document `bfv_sigma.rs` in `nizk-construction.md`
- [x] **File**: `.sisyphus/design/nizk-construction.md`
- [x] **Change**: Add a new section or table row documenting `bfv_sigma.rs` (533 loc): purpose (BFV encryption well-formedness sigma protocol), relation (proves ct0 = pk0*u + e0 + Δ*m, ct1 = pk1*u + e1 over RNS), integration (wired as v4 proof in nizk_share.rs, uses bfv_sigma::prove/verify), and soundness caveat (conditional on P1).
- [x] **Gate**: Manual review

### C.2 — Update `CycloAdapter` trait documentation in `spec-real-p2p3.md`
- [x] **File**: `.sisyphus/design/spec-real-p2p3.md`
- [x] **Change**: §4.5 — replace the documented trait methods (`init`/`fold`/`verify_final`/`serialise_for_p3`) with the actual methods (`fold_one`/`verify_accumulator`/`fold_all`/`backend_id`/`params`). Update error type from `FoldingError` to `CycloError`.
- [x] **Gate**: Manual review

### C.3 — Add two-track DKG architecture to `spec-real-p2p3.md`
- [x] **File**: `.sisyphus/design/spec-real-p2p3.md`
- [x] **Change**: Add a new subsection documenting the two-track sk/e_sm architecture: `FoldTrackKind::Sk` + `FoldTrackKind::ESm`, `MultiTrackFoldMetadata`, `BatchedShareComputationStatement`, `RecipientDkgAggregationStatement`, and the cross-track replay rejection from D.2/D.3.
- [x] **Gate**: Manual review

### C.4 — Update `CcsPShareInstance` and `CycloAccumulator` field documentation
- [x] **File**: `.sisyphus/design/spec-real-p2p3.md`
- [x] **Change**: §4.5 — add `ccs_matrix_bytes` to `CcsPShareInstance` fields; update `CycloAccumulator` field names to match actual struct (`acc_commitment_bytes`, `acc_public_io_bytes`).
- [x] **Gate**: Manual review

### C.5 — Remove or mark `MicroNovaAdapter` / `pvthfhe-p3-encoder` as deferred
- [x] **Files**: `.sisyphus/design/spec-real-p2p3.md` §5, §7.1
- [x] **Change**: Mark `MicroNovaAdapter` trait and `pvthfhe-p3-encoder` crate as **DEFERRED** with a note that the current implementation uses Nova Nova directly via `ProofCompressor` trait without an intermediate P2→P3 encoding crate.
- [x] **Gate**: Manual review

### C.6 — Document PVSS `encrypt.rs` in `interfold-equivalence.md`
- [x] **File**: `.sisyphus/design/interfold-equivalence.md`
- [x] **Change**: Add `crates/pvthfhe-pvss/src/encrypt.rs` (`LatticePvssBfvAdapter`) to the component mapping table, noting it implements the PvssAdapter trait and wires Shamir split → BFV encrypt → NIZK prove.
- [x] **Gate**: Manual review

### C.7 — Update C2b and C7 status in `interfold-equivalence.md`
- [x] **File**: `.sisyphus/design/interfold-equivalence.md`
- [x] **Change**: C2b (e_sm shares): change `missing` to `partial` since `dkg_aggregation.rs` and `share_computation.rs` have two-track infrastructure. C7 (decryption aggregation): keep `missing` but note the toy Noir circuit at `circuits/aggregator_final/src/main.nr` (N=8, Poseidon, not production C7-equivalent).
- [x] **Gate**: Manual review

### C.8 — Update smudging.md for current implementation state
- [x] **File**: `.sisyphus/design/smudging.md`
- [x] **Change**: §5.1 — update to reflect that `partial_decrypt` already samples Gaussian noise (σ=3.5e12), not zero `esi_poly`. §8.3 — clarify that `partial_decrypt_committed_smudge` IS implemented in `FhersBackend` (concrete impl) but the `FheBackend` trait default returns "not implemented". §5.3 — note that `sample_smudge_poly()` standalone function was not created; smudge sampling is inlined.
- [x] **Gate**: Manual review

## Batch D — Phase 1.4: Design doc Noir circuit accuracy

### D.1 — Update Noir circuit description in `spec-real-p2p3.md`
- [x] **File**: `.sisyphus/design/spec-real-p2p3.md`
- [x] **Change**: §6.5 — replace the description of a circuit that verifies `MicroNovaProof` with the actual circuit behavior: direct Lagrange recombination over N=8, Poseidon hash checks for commitment binding, no MicroNova proof verification. Note this is a toy circuit, not a production C7-equivalent verifier.
- [x] **Gate**: Manual review

## Batch E — Phase 2: Demo path fixes (code changes)

### E.1 — Replace hardcoded NIZK error witness with real BFV encryption error
- [x] **File**: `crates/pvthfhe-cli/src/demo_nizk.rs`
- [x] **Change**: Line 85 — `error: vec![1, -1, 0, 2]` (4-element placeholder) → extract real BFV encryption error from `FhersBackend::encrypt_with_witness()`. The witness already contains `e0_poly_bytes` and `e1_poly_bytes`. Pass these through `build_demo_nizk_inputs` and use `poly_bytes_to_i64()` to get the real N=8192 error polynomial.
- [x] **Gate**: `cargo test -p pvthfhe-cli --test demo_banner` and demo-e2e run still pass

### E.2 — Wire `CycloFoldStepCircuit` into compressor (replacing ToyStepCircuit)
- [x] **File**: `crates/pvthfhe-cli/src/compressor_glue.rs` and `crates/pvthfhe-compressor/src/nova/mod.rs`
- [x] **Change**: Line 55 — `NovaCompressor::<ToyStepCircuit<Fr>>` → `NovaCompressor::<CycloFoldStepCircuit<Fr>>`. The `CycloFoldStepCircuit` already exists at `nova/mod.rs:122-167` and encodes `folded_hash = z[0] * ext[0] + z[0]` — it needs to be extended to encode the actual Ajtai commitment folding relation (commitment hash + norm escalation + accumulator parity). If full commitment folding is too heavy for a Nova step circuit, document the gap and keep `CycloFoldStepCircuit` with a clear caveat comment.
- [x] **VERIFY**: Demo-e2e still passes with new step circuit; IVC step count, RSS, and timing within acceptable bounds.

### E.3 — Switch demo decrypt to committed_smudge mode
- [x] **BLOCKED**: DKG transcript does not carry committed `e_sm` polynomial data. The `FheBackend` trait has `partial_decrypt_committed_smudge` but no data source in the current demo pipeline. Blocked on two-track DKG implementation (plan C.1/C.2 from interfold-equivalent-pvss). Documented as gap in notepad.

### E.4 — Fix `demo_banner.rs` test backend ID expectation
- [x] **File**: `crates/pvthfhe-cli/tests/demo_banner.rs`
- [x] **Change**: Line 16 — `contains("backend_id_p3: ultra-honk-micronova")` → `contains("backend_id_p3: nova-bn254-grumpkin")`
- [x] **Gate**: `cargo test -p pvthfhe-cli --test demo_banner` passes

### E.5 — Fix seed-flag behavior to match RED test expectation
- [x] **File**: `crates/pvthfhe-cli/src/demo_nizk.rs` (and/or `full_pipeline.rs`)
- [x] **Change**: When `seed != 0` and `demo-seeded-rng` is NOT enabled, return an error instead of falling back to `OsRng` with a warning. This makes the RED test at `tests/demo_seed_flag.rs:42-50` turn GREEN.
- [x] **Gate**: `cargo test -p pvthfhe-cli --test demo_seed_flag` passes

### E.6 — (Optional) Replace dummy keygen encrypted_shares with real data — SKIPPED
- [x] **File**: `crates/pvthfhe-aggregator/src/keygen/simulator.rs`
- [x] **Change**: SKIPPED — low priority, the encrypted_shares field is vestigial in the DKG transcript. Real key distribution uses backend state, not these marker bytes.

### E.7 — (Optional) Replace PVSS secret derivation with independent secret — SKIPPED
- [x] **File**: `crates/pvthfhe-cli/src/pvss_support.rs`
- [x] **Change**: SKIPPED — changing SHA256(aggregate_pk) to OsRng would break determinism needed for demo reproducibility.

## Batch F — Phase 2: Extend docs_truthful.rs integration test

### F.1 — Add WARNING.md and STATUS.md assertions
- [x] **File**: `tests/integration/docs_truthful.rs`
- [x] **Change**: Add assertions that `WARNING.md` and `STATUS.md` do NOT contain the stale claims "verifier accepts any proof bytes" or "Noir circuits are tautological surrogates". This prevents future staleness.
- [x] **Gate**: `cargo test -p pvthfhe-cli --test integration::docs_truthful` passes

## Execution order

| Phase | Batches | Depends on | Effort |
|-------|---------|------------|--------|
| 1.1 | A.1–A.4 | None | ~30 min (doc edits only) |
| 1.2 | B.1–B.9 | None | ~60 min (doc edits only) |
| 1.3 | C.1–C.8 | None | ~90 min (doc edits only) |
| 1.4 | D.1 | None | ~15 min |
| 2 | E.1–E.7, F.1 | None (independent of Phase 1) | ~3-4 hours (code changes + test verification) |

Phase 1 (all doc batches) can be executed in any order and delegated in parallel.
Phase 2 (code changes) should be sequential: E.1 → E.4 → E.5 → E.2 → E.3, then F.1.

## Acceptance criteria

- [x] `SECURITY.md` no longer claims NIZK is "not yet implemented"
- [x] `README.md` no longer references Greco, MPCitH, or presents aspirational bounds as achieved
- [x] `WARNING.md`, `STATUS.md`, `ARCHITECTURE.md` no longer have stale surrogate claims
- [x] `paper/claims-table.md` correctly marks P2-T2 as CONTINGENT and P3-T1 as attestation authorization
- [x] `docs/security-proofs/p2/T2.md` carries Lemma 9 dependency header
- [x] All 4 design docs include `bfv_sigma.rs`
- [x] `spec-real-p2p3.md` CycloAdapter trait matches actual code
- [x] `spec-real-p2p3.md` documents two-track DKG architecture
- [x] Demo NIZK error witness uses real-derived error polynomial, not hardcoded placeholder
- [x] Demo compressor uses CycloFoldStepCircuit (gap documented)
- [x] `demo_banner.rs` test passes with correct backend ID
- [x] `demo_seed_flag.rs` test passes (RED→GREEN)
- [x] `docs_truthful.rs` covers WARNING.md and STATUS.md
- [x] Demo-e2e passes with all changes

### Blocked / Deferred
- E.3: committed_smudge decrypt — blocked on two-track DKG `e_sm` data in demo pipeline
- E.6: dummy keygen encrypted_shares — low priority (vestigial field)
- E.7: independent PVSS secret — would break demo determinism
