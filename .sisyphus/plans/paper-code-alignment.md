# Paper-Code Alignment Plan

**Created**: 2026-05-13
**Trigger**: Deep comparison of `paper/main.tex` (278 lines, 20 theorems) against current codebase state (post Round 3 remediation).
**Key Finding**: Paper describes a research prototype with surrogates. Code has moved past that — real BFV sigma proof (v4), committed smudge, two-track DKG, real Sonobe Nova IVC with verify_shares enabled. The paper header is frozen at a pre-remediation state.

---

## Scope

Two-way alignment:
1. **Paper → Code**: Update the paper to reflect what the codebase ACTUALLY implements now
2. **Code → Paper**: For ideal protocol features described in the paper but not yet implemented, create a plan to bring code in line

Plus a deep review of the `paper/claims-table.md` (22 formal claims) against code reality.

---

## Batch A — Fix paper header staleness (blocks all other batches)

### A.1 — Update paper header surrogate claims (lines 3-8)
- [ ] **File**: `paper/main.tex` lines 3-8
- [ ] **Change**: Replace the stale header comment:
  ```
  % no on-chain cryptographic verification — verifier accepts any proof bytes
  % Noir circuits are tautological surrogates (assert(x == x) — no real constraints)
  ```
  With current reality:
  ```
  % Lattice-native BFV sigma protocol (v4) with per-share NIZK verification
  % Sonobe Nova IVC with CycloFoldStepCircuit; committed-smudge decryption
  % Research prototype — do not use for The Interfold or any production deployment
  ```
- [ ] **Gate**: Paper header reflects current code reality; "do not use for The Interfold" warning preserved

### A.2 — Update architecture section (§1, lines 40-49) to reflect current state
- [ ] **File**: `paper/main.tex` lines 40-49
- [ ] **Change**: Add mention of:
  - `bfv_sigma.rs` (533 loc): lattice-native BFV encryption sigma protocol proving `ct0 = pk0*u + e0 + Δ*m` and `ct1 = pk1*u + e1` over RNS
  - Committed-smudge decryption (wired via `partial_decrypt_committed_smudge`)
  - Two-track sk/e_sm DKG (`FoldTrackKind::Sk` + `FoldTrackKind::ESm`)
  - v4 proof format (`PROOF_VERSION = 4` in `nizk_share.rs`)
  - `verify_shares` enabled in demo path (no longer compiled out)
- [ ] **Gate**: Architecture section matches `crates/*/src/*.rs` actual module structure

### A.3 — Update P1 NIZK description (§5) to mention bfv_sigma.rs
- [ ] **File**: `paper/main.tex` §5 (lines 112-148)
- [ ] **Change**: Add paragraph describing the lattice-native BFV sigma proof as a second P1 sub-component. Currently only describes the SLAP-style sigma for RLWE well-formedness. Mention:
  - Proves knowledge of bounded (m, u, e0, e1) satisfying BFV equations per CRT limb
  - Binary challenges {0,1}^N, masking bound 2^30, RNS verification
  - Deterministic masking upgraded to OsRng (round 1 remediation)
- [ ] **Gate**: P1 section accurately describes BOTH sigma protocols in use

### A.4 — Update P3 description (§7) to note Sonobe IVC, not ecrecover-only
- [ ] **File**: `paper/main.tex` §7 (lines 181-222)
- [ ] **Change**: The paper describes P3 as an `ecrecover`-based ECDSA surrogate. Update to mention that Sonobe Nova IVC (`CycloFoldStepCircuit`) is now the active compression path, with the ecrecover path retained as a fallback. Note `compressor.verify()` and external verification via `external_verify_compressed_proof()`.
- [ ] **Gate**: P3 section accurately describes current compressor + verifier state

---

## Batch B — Fix claims-table.md (22 formal claims)

### B.1 — Add "Provenance" column to claims table
- [ ] **File**: `paper/claims-table.md`
- [ ] **Change**: Add a column indicating whether each theorem's proof is for:
  - **TARGET** (the target Architecture B: Lattice PVSS + LatticeFold+ + MicroNova + UltraHonk)
  - **SURROGATE** (the current implementation: Sonobe Nova, SHA-256 hash, ecrecover)
  - **BOTH** (proved for both target and surrogate)
- [ ] **Gate**: Every claim has a provenance column

### B.2 — Reclassify P2-T1, P2-T3, P2-T5 as SURROGATE
- [ ] **File**: `paper/claims-table.md` rows P2-T1, P2-T3, P2-T5
- [ ] **Change**: Status → add `(SURROGATE: Sonobe Nova SHA-256 hash accumulation)` qualifier. The existing PROVED status remains accurate for the surrogate path.
- [ ] **Gate**: Claims table is honest about what each PROVED status actually covers

### B.3 — Reclassify P3-T1, P3-T2, P3-T5 as SURROGATE
- [ ] **File**: `paper/claims-table.md` rows P3-T1, P3-T2, P3-T5
- [ ] **Change**: Status → add `(SURROGATE: ECDSA/ecrecover attestation)` qualifier. P3-T4 (Gas Bound) is empirically validated for both paths — mark as BOTH. P3-T3 (Trusted-Setup) keep as-is with note about KZG for target path.
- [ ] **Gate**: P3 claims are honest about surrogate vs target

### B.4 — Add P1 criticality footnote from SECURITY.md
- [ ] **File**: `paper/claims-table.md` P1 rows
- [ ] **Change**: Add footnote: "P1 soundness is conditional on Module-SIS + Cyclo Theorem 3. Formal joint-extractor proof (T2) is a skeleton per SECURITY.md §P1."
- [ ] **Gate**: Claims table reflects SECURITY.md open-problem status

---

## Batch C — Update benchmark figures

### C.1 — Regenerate P1 benchmark figures with current code
- [ ] **Action**: Run `bench/p1/run.sh` with current code (post Round 3, BFV sigma v4 active)
- [ ] **Output**: Update `paper/figures/p1-bench.tex` with current timing data
- [ ] **Gate**: P1 benchmark reflects BFV sigma proof overhead

### C.2 — Add P2 benchmark for two-track DKG
- [ ] **Action**: Run `bench/p2/` benchmarks with two-track sk/e_sm folding
- [ ] **Output**: Add two-track comparison to `paper/figures/p2-bench.tex`
- [ ] **Gate**: P2 benchmark captures two-track DKG overhead

### C.3 — Update P3 gas measurement with ultra-honk path
- [ ] **Action**: Run `just p3-bench` for both ecrecover path (current) and ultra-honk path (if available)
- [ ] **Output**: Report both gas figures in paper. ecrecover: 5,273 gas. UltraHonk: 39,687 gas.
- [ ] **Gate**: Paper shows dual P3 gas costs

---

## Batch D — Dual-track paper: describe BOTH Sonobe (achieved) and LatticeFold+ (target)

The paper should present two parallel architectures, not one:

1. **Concrete instantiation (achieved, benchmarked)**: Sonobe Nova IVC + CycloFoldStepCircuit + ecrecover attestation
2. **Theoretical target (aspirational, blocked on Lemma 9)**: LatticeFold+ over RLWE + MicroNova + UltraHonk

Each gets its own theorem statements, proof sketches, and benchmark results.

### D.1 — Restructure paper architecture section for dual-track
- [ ] **File**: `paper/main.tex` §4–§7
- [ ] **Change**: Refactor the P1→P2→P3 pipeline description into two parallel tracks:
  - **Track A (concrete)**: P4 (PVSS) → P1 (bfv_sigma + SLAP sigma) → P2-A (Sonobe Nova IVC with CycloFoldStepCircuit) → P3-A (ecrecover attestation + off-chain Sonobe verification)
  - **Track B (target)**: P4 (PVSS) → P1 (bfv_sigma + SLAP sigma) → P2-B (LatticeFold+ over RLWE) → P3-B (MicroNova + UltraHonk on-chain)
  - Note: Track A and Track B share P4 and P1 (implemented identically). They diverge at P2/P3.
- [ ] **Gate**: Architecture section clearly describes both tracks; the concrete track is the one with benchmarks

### D.2 — Write P2 Track A proof section (Sonobe — proved)
- [ ] **File**: `paper/main.tex` — new §6.A (Track A: Sonobe Nova IVC)
- [ ] **Change**: Describe the current Cyclo folding + Sonobe compression as a valid concrete instantiation:
  - **P2-A-T1** (Sonobe Folding Completeness): Honest Cyclo fold instances produce valid Sonobe Nova IVC step witnesses. Proved by `p2/T1.md` (VERDICT: APPROVE).
  - **P2-A-T2** (Sonobe Knowledge Soundness): The Sonobe Nova IVC verifier accepts only valid folded CCS instances. Proved via standard Nova IVC soundness (not LatticeFold+ Lemma 9).
  - **P2-A-T3** (Sonobe ZK Preservation): The CycloFoldStepCircuit operates on hashed accumulator state (3 Fr scalars), preserving ZK of the underlying witness. Proved by `p2/T3.md`.
  - **P2-A-T4** (Sonobe Accumulator Binding): SHA-256 hash commitment. Proved by `p2/T4.md` (CONDITIONAL).
  - **Benchmarks**: Reference `paper/figures/p2-bench.tex` for Sonobe IVC timing.
- [ ] **Gate**: §6.A clearly describes the working Sonobe path with proved theorems

### D.3 — Write P2 Track B theory section (LatticeFold+ — target)
- [ ] **File**: `paper/main.tex` — new §6.B (Track B: LatticeFold+ over RLWE)
- [ ] **Change**: Describe the LatticeFold+ architecture as the theoretical target:
  - **P2-B-T1** (LatticeFold+ Folding Completeness): ASPIRATIONAL. The proposed LatticeFold+ scheme accumulates RLWE instances. Proof sketch only.
  - **P2-B-T2** (LatticeFold+ Knowledge Soundness): CONTINGENT on Lemma 9 (CONJECTURE). Formal proof deferred.
  - **P2-B-T3** (LatticeFold+ ZK Preservation): ASPIRATIONAL. Projected SLAP core ZK view preserved under proposed folding.
  - **P2-B-T4** (LatticeFold+ Accumulator Binding): ASPIRATIONAL. Designed to be binding under RingSIS/M-SIS.
  - **Plan**: Reference `.sisyphus/plans/p2-latticefold-target.md` for planned implementation.
- [ ] **Gate**: §6.B clearly distinguishes LatticeFold+ as theoretical with explicit conjecture dependency

### D.4 — Write P3 Track A/B proof sections
- [ ] **File**: `paper/main.tex` — new §7.A (Track A: ecrecover + off-chain Sonobe), §7.B (Track B: UltraHonk on-chain)
- [ ] **Change**:
  - **Track A**: ecrecover-based ECDSA attestation (5,273 gas). Proved theorems P3-A-T1 through P3-A-T5 (all PROVED per `p3/adviser-verdict.md`). Off-chain Sonobe verification via `offchain-verifier`. Benchmarks: 5,273 gas (ecrecover), off-chain verification time in `paper/figures/p3-bench.tex`.
  - **Track B**: UltraHonk + MicroNova on-chain verification (39,687 gas). Proofs are skeletons. Deferred to `.sisyphus/plans/p3-micronova-target.md`.
- [ ] **Gate**: §7.A/B clearly distinguished both paths with track-specific theorem statuses

### D.5 — Update claims table for dual-track
- [ ] **File**: `paper/claims-table.md`
- [ ] **Change**: Add a second provenance column. Each claim now has:
  - **Track A status** (Sonobe — current code): PROVED / CONDITIONAL / etc.
  - **Track B status** (LatticeFold+ — target): ASPIRATIONAL / CONTINGENT / SKELETON
  - P2 and P3 claims are split: P2-A-T1 through P2-A-T5 (proved for Sonobe), P2-B-T1 through P2-B-T5 (target for LatticeFold+)
- [ ] **Gate**: Claims table is honest about both tracks

### D.6 — Create deferred implementation plans (track B)
- [ ] **Files**: `.sisyphus/plans/p2-latticefold-target.md`, `.sisyphus/plans/p3-micronova-target.md`, `.sisyphus/plans/p1-t2-joint-extractor.md`, `.sisyphus/plans/p1-t3-zk-full.md`
- [ ] **Change**: For each track B theorem marked ASPIRATIONAL or CONTINGENT, create a plan describing what would be needed to implement it: research milestones, cryptographic assumptions, engineering effort.
- [ ] **Gate**: 4 plans written, each mapping to specific paper theorems

---

## Batch E — Update paper conclusion and future work

### E.1 — Update conclusion (§11) with current remediation status
- [ ] **File**: `paper/main.tex` lines 271-273
- [ ] **Change**: Replace:
  ```
  P2 and P3 currently use cryptographic surrogates
  ```
  With:
  ```
  P2 uses a Sonobe Nova IVC surrogate (CycloFoldStepCircuit proving hash-state accumulation, not Ajtai fold).
  P3 uses the ecrecover/ECDSA attestation surrogate for on-chain acceptance.
  Post-remediation (3 audit rounds): BFV sigma v4, committed-smudge, two-track DKG enabled.
  P1 masking seeds upgraded to OsRng.
  ```
- [ ] **Gate**: Conclusion reflects actual remediation state

### E.2 — Add "Remediation Log" appendix
- [ ] **File**: `paper/main.tex` — new appendix §A
- [ ] **Change**: Add a brief appendix summarizing three rounds of remediation:
  - Round 1: Fixed masking seeds, logging hygiene, shamir safety, B_E naming
  - Round 2: Per-share NIZK verify, committed smudge wiring, dkg_root, BFVPublicKey
  - Round 3: CommittedSmudge demo activation, aggregator NIZK, C1 key components
- [ ] **Gate**: Appendix accurately reflects commits `aaacb9e` through `952a078`

---

## Execution order

| Batch | Priority | Depends on | Effort |
|-------|----------|------------|--------|
| **A** (paper header + architecture) | P0 | None | ~1h |
| **B** (claims-table fixes) | P0 | None | ~30min |
| **C** (benchmark regeneration) | P1 | A complete | ~1h |
| **D** (paper→code plans) | P1 | None | ~1h (planning only) |
| **E** (conclusion + appendix) | P1 | A-D complete | ~30min |

All batches are independent except C depends on A (benchmarks may need architecture context) and E depends on A-D (conclusion summarizes all changes).

---

## Acceptance criteria

- [ ] Paper header no longer claims "verifier accepts any proof bytes"
- [ ] Architecture section mentions bfv_sigma.rs, committed smudge, two-track DKG
- [ ] Claims table has provenance column (SURROGATE / TARGET / BOTH)
- [ ] P2-T1/T3/T5 and P3-T1/T2/T5 marked as SURROGATE
- [ ] P1 criticality footnote present in claims table
- [ ] P1 benchmark figures regenerated with current code
- [ ] P2 benchmark captures two-track DKG
- [ ] P3 gas measurement shows both ecrecover and ultra-honk paths
- [ ] 3 deferred plans created (p2-latticefold, p3-micronova, p1-t2-extractor)
- [ ] P1-T3 ZK full-cover plan created
- [ ] Conclusion updated with remediation status
- [ ] Remediation log appendix added
