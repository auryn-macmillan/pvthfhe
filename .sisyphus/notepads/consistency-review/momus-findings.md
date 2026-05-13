# Momus 3-Dimensional Skeptical Review — Findings Summary

**Executed**: 2026-05-13
**Scope**: Paper soundness, codebase soundness, docs consistency

## Paper Findings

| ID | Severity | Theorem | Issue |
|----|----------|---------|-------|
| P1 | FAIL | P2-A-T2 (Sonobe Knowledge Soundness) | Paper claims PROVED via Nova IVC soundness reduction. Proof file `p2/T2.md` proves LatticeFold+ ternary extractor — different argument for different system |
| P2 | FAIL | P2-A-T5 (On-chain Compatibility) | Paper claims PROVED. Proof file shows 2/6 obligations discharged; 4 are Phase D design targets |
| P3 | MEDIUM | P4-T4 (Abort-with-Blame) | Missing `\begin{proof}` block in paper; proof file exists |
| P4 | MEDIUM | P1-T2/P1-T3 tension | Extraction and ZK proved for incompatible proof objects; never reconciled |

## Codebase Findings

| ID | Severity | File:Line | Issue |
|----|----------|-----------|-------|
| C1 | HIGH | bfv_sigma.rs:335-338 | Plaintext domain constraint not enforced; m values in [32768, B_Z_M] pass verification |
| C2 | HIGH | nizk_decrypt.rs:325-355 | No cross-check between committed esm_agg_share and actual esm_noise_poly_bytes |
| C3 | MEDIUM | sigma.rs:14 | 2^{-N} soundness claim inflated; actual soundness is conditional (P1) |
| C4 | MEDIUM | adapter.rs:161-163 | Proof-bytes session_id and participant_id read but never verified |

## Docs Findings

| ID | Severity | Documents | Issue |
|----|----------|-----------|-------|
| D1 | HIGH | SECURITY.md vs paper/claims-table.md | P1/P2/P3 OPEN vs Track A PROVED (14 theorems) |
| D2 | HIGH | ARCHITECTURE.md vs paper | "Sonobe substitutes" / "critical surrogates" vs Track A primary/PROVED |
| D3 | HIGH | WARNING.md vs paper | "No real security" vs "All 19 theorems proved" |
| D4 | HIGH | interfold-equivalence.md vs paper | C3 partial (D.1 blocker) vs P1-T2 PROVED |
| D5 | MEDIUM | SECURITY.md internal | Line 17 "Implemented" vs line 48 "deferred" |
| D6 | MEDIUM | ARCHITECTURE.md internal | "critical surrogates" vs "real UltraHonk verifier" in same paragraph |
| D7 | MEDIUM | ARCHITECTURE.md vs SECURITY.md | "no real security" vs "real UltraHonk verifier" |
| D8 | MEDIUM | paper/submission/README.md vs paper-claims.md | "All 19 proved" vs 28 overstated/contradicted |
| D9 | MEDIUM | Aggregate key assertion | No adversarial test; structurally weak against shared bugs |
