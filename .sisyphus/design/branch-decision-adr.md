# ADR-001: BRANCH-A vs BRANCH-B Folding Backend Decision

## Status
PENDING USER APPROVAL

## Context
The PVTHFHE project requires a folding scheme to compress per-share threshold decryption proofs into a single on-chain SNARK. We must decide between a fully lattice-native stack (Branch A: LatticeFold+) and a mature curves-based folding stack (Branch B: Nova/HyperNova via MicroNova Noir wrapping). 

The Phase 0 design freeze (`spec-real-p2p3.md §1.3` and §6.4) heavily signaled Branch B (Option B: Wrap MicroNova Proof in UltraHonk Noir Circuit) as the chosen P3 target. We must formalize this decision against the strict backend-lock (`gnosisguild/fhe.rs` + `fhe-math`) and the toolchain fit (canonical Barretenberg `bb` flows).

## Decision Rubric

| Axis | BRANCH-A (LatticeFold+) | BRANCH-B (Nova/HyperNova) | Notes |
|------|------------------------|--------------------------|-------|
| Soundness confidence (0–5) | 3 | 5 | Nova is battle-tested; LatticeFold+ is newer. |
| Implementation risk (0–5, lower=better) | 5 | 2 | No mature LatticeFold+ Rust crate exists. |
| Backend-lock compat (pass/fail) | Pass | Pass | Both can theoretically bind to `fhe-math` types. |
| Toolchain fit (0–5) | 2 | 5 | Branch B directly targets Noir + BB UltraHonk. |
| Calendar cost (weeks) | 12+ weeks | 4-6 weeks | Custom LatticeFold+ implies massive R&D. |
| **TOTAL** (excl. calendar) | **10/20** | **18/20** | (Assumes Pass=5, Risk is inverted) |

## Decision

**BRANCH-B: Nova/HyperNova via Noir + UltraHonk**

## Rationale
BRANCH-B overwhelmingly wins on implementation feasibility and toolchain fit. The Phase 0 `spec-real-p2p3.md` already designated MicroNova wrapped in a Noir UltraHonk circuit as the chosen path. Branch B allows us to leverage existing mature curve-based folding crates (`sonobe`, `microsoft/nova`) and fits perfectly into our canonical `nargo execute -> bb write_vk -> bb prove -> bb verify` pipeline.

## Branch-Specific Task Matrix

| Task | Branch-A Scope | Branch-B Scope |
|------|---------------|----------------|
| T1: Real folding | Custom LatticeFold+ Rust impl | Wire sonobe/nova crate to fhe-math types |
| T2: Noir circuits | Noir circuits for lattice acc relations | Noir circuits for Nova/HyperNova step fn |
| T3: NIZK Fiat-Shamir | Same | Same |
| T4: On-chain registry | Same | Same |
| T5: Forged-share rejection | Same | Same |
| T6: decrypt_share constraints | Lattice-native constraints | Nova-compatible R1CS/Plonkish constraints |
| T7: Hermine PVSS | Same | Same |
| T8: Norm-bound fix | Same | Same |
| T9: Lemma 9 | Same | Same |
| T10: Hash-family alignment | Same | Same |
| T11: DoS hardening | Same | Same |
| T13: Multi-review audit | Same | Same |
| T14: Final gate | Same | Same |
| T15: Threat model | Same | Same |

## Rejection Reasons (BRANCH-A)
LatticeFold+ lacks a production-ready Rust crate compatible with our strict locked dependencies (`fhe-math`). Building a custom lattice folding scheme from scratch introduces unacceptable calendar cost and implementation risk for Stage 1. It also lacks clear integration paths into our required Barretenberg / Noir toolchain.

## Decision Owner
Atlas (orchestrator)

## Timestamp
2026-05-04

APPROVED-BY-USER: APPROVED (explicit user approval 2026-05-04)
