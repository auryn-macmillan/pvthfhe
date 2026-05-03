# P2 Stack Decision Memo

This memo freezes **LatticeFold+** as the P2 primary stack, with **MicroNova** as the first pivot when the downstream on-chain envelope dominates and **Rust-in-zkVM** as the guaranteed-delivery fallback. The choice follows the frozen C.R.5 scorecard (`3.45 > 3.25 > 3.00`), the C.D.1 `FoldingScheme` boundary, and the P1→P2 bundle's requirement to preserve the exact frozen verifier equation rather than a surrogate relation.

## Primary Stack

**Primary:** LatticeFold+ (ePrint 2025/247).

LatticeFold+ stays primary because it is the only frozen candidate that matches the repo's current P2 goal on all three first-order constraints at once: it is RLWE-native enough to track the frozen P1 verifier equation, it improves materially on LatticeFold's prover/verifier constants, and it fits the backend-agnostic `FoldingScheme` trait from C.D.1 without leaking backend-specific gadgets into the public interface. For this repo, that matters because the P1 verifier is already mostly arithmetic and foldable; the only non-arithmetic pieces are SHA-256 recomputation and the bounded `z_e` checks called out in the P1→P2 bundle.

Concretely, the primary rationale is:

- **RLWE-native relation matching:** the frozen P1 verifier equation is still an RLWE-flavored relation with hash and range-check side conditions, so keeping folding in a lattice-native commitment world avoids an immediate commitment-model mismatch.
- **Faster prover / simpler verifier than LatticeFold baseline:** the prior-art freeze records LatticeFold+ as the materially improved follow-on to LatticeFold, with better prover constants and a simpler verifier/range-proof story.
- **Trait fit:** the C.D.1 trait keeps `acc_commitment` and `proof_bytes` opaque, so a real `latticefold-plus` adapter can satisfy the frozen public API without changing statement, witness, accumulator, or final-proof semantics.

**License posture:** paper is CC BY; any implementation reused from research code should be treated as review-required before vendoring.

## Fallback Stacks

### 1. MicroNova (ePrint 2024/2099)

MicroNova is the **first pivot** when the blocker is the P2-T5 envelope rather than RLWE-native semantics. It is not RLWE-native, but it has the clearest current story for a compressed final proof that can plausibly meet the downstream on-chain constraints, so it remains the right promotion candidate when `≤14KB` proof size or `≤5M` gas becomes the dominant decision variable.

**License posture:** paper is CC BY; implementation lineage is exposed through the MIT-licensed Nova ecosystem.

### 2. Rust-in-zkVM (SP1 / RISC0 wrapping the P1 Rust verifier)

Rust-in-zkVM is the **guaranteed delivery fallback**. It preserves semantic fidelity to the frozen P1 verifier, including exact proof-byte parsing, SHA-256 transcript recomputation, and the current witness-opening behavior, so it is the lowest research-risk path if native or circuitized folding stalls.

**License posture:** SP1 and RISC0 use Apache-2.0/MIT-style licensing, which is cleaner operationally than the current research-code lattice path.

Fallback order is frozen as:

1. stay on **LatticeFold+** while the RLWE-native route remains credible;
2. pivot to **MicroNova** when the P3 envelope is the blocking constraint;
3. pivot to **Rust-in-zkVM** when guaranteed delivery or exact semantic fidelity becomes the only credible path.

## Quantitative Comparison

The quantitative projections below are **projected / estimated**, not measured P2 implementation results. They are anchored to the checked-in repo baselines that exist today: `bench/results/folding-1024.json` (surrogate folding baseline: `167.1 ms` over `1024` folds, `280`-byte accumulator), `bench/results/scaling-n1024.json` (current recursive baseline: `21,856`-byte final proof and `8,131,800 KB` peak memory), `bench/results/kzg-batch-128.json` (`3.65M` gas batch verifier checkpoint), and `bench/results/backend-compare-2026-05-02.json` (`15.29 ms` median NTT-domain polynomial multiply at `N=4096`). They should be read as design-level order-of-magnitude guidance only.

### Projected prover time at `t=513`

| Candidate | Prover time @ fold-depth ≈10 for `t=513` | Note |
| --- | ---: | --- |
| LatticeFold+ | `~2-6 s` projected | Best native fit; assumes ~10 binary folds and better constants than LatticeFold |
| MicroNova | `~8-20 s` projected | Pays to re-express the frozen P1 verifier inside a non-lattice recursive circuit |
| Rust-in-zkVM (SP1 / RISC0) | `~30-120 s` projected | Slowest path; proves the exact Rust verifier rather than a native fold relation |

| Candidate | RLWE-native | Fold-depth@t=513 | Prover-mem-peak | Accum-size | Verifier-gas | PQ-posture | Audit-surface | Weighted-score |
| --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| LatticeFold+ | Yes | `~10` folds projected | `~1.5-3.0 GiB` estimated | `~1-4 KB` estimated | `~4.0-5.5M` via P3 wrap projected (borderline) | PQ-native (`RLWE` / `RingSIS`) | Medium-high: new lattice folding core plus adapter, no third-party audit | 3.45 |
| MicroNova | No | `~10` folds + compressed checkpoint projected | `~2.0-4.0 GiB` estimated | `~0.5-2 KB` compressed state estimated | `~2.2-3.7M` projected; strongest current envelope story | Not PQ | High: verifier circuit, KZG / pairing layer, outer wrapper | 3.25 |
| Rust-in-zkVM (SP1 / RISC0) | No | `~10` recursive checkpoints or one batched verification pass projected | `~4.0-8.0 GiB` estimated | `~16-64 KB` receipt / proof state estimated | `~2.5-4.5M` with EVM-friendly wrap projected | Depends on wrapped inner proof | High: zkVM runtime, guest verifier, outer proof, wrapper contract | 3.00 |

Interpretation: LatticeFold+ wins on relation fit and post-quantum posture, MicroNova wins on the on-chain envelope, and Rust-in-zkVM wins on delivery confidence. That ordering matches the frozen scorecard and is why the primary/fallback order remains unchanged.

## Recursion Fit

For `t=513` parties with binary folding, the required fold depth is about `d = 10` because `2^9 = 512 < 513` and `2^10 = 1024 > 513`. The extraction tree cost at depth `d` is explicitly `2^d`, so at the target depth the conservative rewinding budget is `2^10 = 1024` branches.

At `n=1024`, that recursion budget matters more than asymptotic notation alone:

- **LatticeFold+** is the best fit because it folds the RLWE-native verifier relation directly and preserves the frozen P2 trait boundary. It inherits the P1 ternary challenge semantics, so the baseline soundness product is still `(1/3)^d`; at `d≈10`, that is `(1/3)^10`, with the extractor paying the `1024`-branch rewind tree.
- **MicroNova** handles depth operationally, but the fit is weaker because the frozen P1 verifier must be circuitized into a non-lattice accumulator, including SHA-256 and exact proof-byte decoding.
- **Rust-in-zkVM** handles depth most comfortably from an implementation standpoint because recursion is delegated to the zkVM stack, but that is a delivery fit, not a research-native fit; prover latency and memory are the trade-off.

## PQ Posture

- **LatticeFold+** is the only PQ-native option in this shortlist because its security story remains in the lattice family (`RLWE` / `RingSIS`).
- **MicroNova** is **not PQ** because the compressed on-chain path relies on pairing / KZG-style machinery.
- **Rust-in-zkVM** is mixed: the wrapped inner proof can preserve the P1 post-quantum assumptions, but the outer recursion / EVM verification story depends on the chosen zkVM wrapper and is not automatically PQ-native.

That posture is the key reason the primary remains LatticeFold+ even though MicroNova has the better present-day verifier envelope.

## On-chain Verifier Cost

The downstream P2-T5 target remains: **final proof `≤14KB` and on-chain verification `≤5M` gas**. P2 does not get to ignore this just because the folding relation is primary-research work; the selected stack must leave P3 a plausible path to that envelope.

Candidate-by-candidate:

- **LatticeFold+** only remains acceptable as the primary if it is finalized through a P3 compression path; by itself it does not yet give a convincing direct-EVM verifier. Current projection is **borderline**, so gas / proof size are explicit pivot triggers rather than solved properties.
- **MicroNova** is the clearest candidate that can plausibly hit the envelope today. The prior-art freeze records an Ethereum-oriented verification target around `2.2M` gas, so this remains the first pivot when on-chain size or gas is the blocker.
- **Rust-in-zkVM** can also plausibly land inside the gas envelope once wrapped for EVM verification, but proof size, prover cost, and PQ posture are less attractive than MicroNova for the same role.

Decision consequence: **do not pivot away from LatticeFold+ unless the envelope is the blocker**; if it is, pivot first to **MicroNova**, not directly to zkVM.

## Kill Criteria / Pivot Triggers

Refined from `RG-P2-decision.md`:

- Pivot away from **LatticeFold+** if the folded design cannot faithfully encode the full frozen P1 verifier equation, including SHA-256 transcript recomputation, exact proof-byte parsing, bounded `z_e` checks, parameter/session binding, and accumulator binding, without underconstraining soundness.
- Pivot from **LatticeFold+** to **MicroNova** if, after one design iteration, there is still no credible path to the P2-T5 envelope (`≤14KB`, `≤5M gas`) or if the projected fold-depth-10 memory trend ceases to look materially better than the repo's current `~7.8 GiB` recursive baseline.
- Pivot from **LatticeFold+** or **MicroNova** to **Rust-in-zkVM** if implementation friction dominates and exact Rust-verifier wrapping becomes the only path that still preserves credible delivery for `t=513`, `n=1024`.
- Treat **Rust-in-zkVM** as the terminal fallback, not an intermediate optimization track.

## Reviewer Sign-off
VERDICT: APPROVE
