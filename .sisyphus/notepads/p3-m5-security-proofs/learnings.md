# Learnings — P3-M5 Security Proofs

## 2026-05-14

### Document structure conventions

- Each P3 theorem document uses a consistent header format: Theorem ID, Status, Reduction target, and Replaces (when superseding a prior variant).
- The proof skeleton format from `docs/security-proofs/p3/proof-skeletons.md` was NOT reused directly because the P3-M5 documents target the UltraHonk/MicroNova stack (Option B), not the SP1 + Groth16 primary stack that the skeletons describe.
- The existing T1.md, T2.md, T4.md files in the directory are from an earlier ECDSA-based verifier era and should not be confused with the new documents. The new files use descriptive suffixes (`-ultrahonk-soundness`, `-micronova-preservation`, `-gas-bound`) to avoid collision.

### Key references used

- Aztec Protocol's UltraHonk security analysis is the primary reduction target for T1.
- MicroNova ePrint 2024/2099 (Zhao et al., IEEE S&P 2025) is the primary reference for T2.
- The 39,687 gas baseline comes from `docs/security-proofs/p3/ultrahonk-deploy.md` and `docs/security-proofs/p3/gas-optimization.md`, which cite Aztec's reference implementation.
- The P3 stack decision (`spec-real-p2p3.md` §6.4, Option B) is the canonical source for the two-layer compression chain: Cyclo → MicroNova → UltraHonk → HonkVerifier.sol.

### Single-step IVC simplification

The PVTHFHE Nova IVC chain has length 1 (one Cyclo accumulator verification step). This eliminates the linear loss factor `T` in the soundness budget and is documented in T2-micronova-preservation.md §Single-Step Chain Simplification. This is an important structural advantage over general MicroNova deployments.

### LatticeFold+ UltraHonk subset

LatticeFold+ proofs use a strict subset of UltraHonk: no lookup arguments (Plookup/LogUp), no RAM/ROM tables. This may tighten the knowledge-soundness bound by a factor of 2–4× compared to generic UltraHonk. Documented in T1 §LatticeFold+ Subset Note.

## 2026-05-16 — Status updated to DOCUMENTED

Updated all three P3-M5 theorem documents:
- `docs/security-proofs/p3/T1-ultrahonk-soundness.md`: changed status from DEFERRED to
  DOCUMENTED -- measurements deferred to post-p3-m3.
- `docs/security-proofs/p3/T2-micronova-preservation.md`: same status change.
- `docs/security-proofs/p3/T4-gas-bound.md`: same status change.

All three documents already contained the required content: T1 references Aztec's security
analysis for BN254 UltraHonk, T2 documents MicroNova's preservation of Nova knowledge
soundness, and T4 documents the projected gas (39,687) with measurement methodology.

Updated the meta-plan checkbox for `p3-m5-security-proofs` in
`.sisyphus/plans/meta-plan-all-deferred.md` from `- [ ]` to `[-]`.
