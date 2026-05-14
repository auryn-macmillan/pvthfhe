# Issues — P1-T2 Joint Extractor

## M1: Forking-Lemma Formalization

### 2026-05-14

| Issue | Severity | Status |
|-------|----------|--------|
| Forking-lemma bound is vacuous for ternary challenge space (\|C\|=3) with Q_total=12 | HIGH | OPEN — M2 clarifies that actual reduction goes to SHA-256 binding, not forking-lemma extraction. M-SIS enters through P2 folding. Vacuous forking bound does not block M2. |
| Formula discrepancy between task spec (ε_acc²) and standard forking lemma (ε_acc²/Q) | MEDIUM | OPEN — document notes both |
| Norm bound for Δ = ±2 extraction may be too large for M-SIS reduction | HIGH | OPEN — deferred to M3. M2 documents the Δ=±2 problem but does not resolve it. |
| Exact randomization of rewind point selection not specified | LOW | OPEN — implementer's choice |

## M2: M-SIS Reduction

### 2026-05-14

| Issue | Severity | Status |
|-------|----------|--------|
| M-SIS β = 2048 concrete security level not quantified | MEDIUM | OPEN — needs concrete lattice estimate for R_{q_commit} at φ=256, q≈2^50 |
| Case B (h ≠ pvss_commitment) in §4 has no reduction target | LOW | OPEN — Fiat-Shamir statement binding ambiguity; does not imply any known hardness break |
| Additive composition claim (ε_adversary ≤ Adv_SHA-256 + Adv_M-SIS) needs formal proof in M4 | MEDIUM | OPEN — stated in §5, formal proof deferred to M4 |

## M3: Challenge-Space Analysis

### 2026-05-14

| Issue | Severity | Status |
|-------|----------|--------|
| q_commit parity not definitively resolved (odd vs. power-of-two) | LOW | OPEN — Document covers both cases. Actual parity depends on Cyclo implementation parameter selection. |
| Norm blowup for Δ = ±2 (inverse norm ~2^49) makes extracted witness norm exceed q_commit | MEDIUM | OPEN — Documented in M3 §3.5. Extractors should reject Δ = ±2 forks. |
| The 3^256 challenge space figure is partially misleading for P1 (only applies to folding layer, not leaf NIZK) | LOW | RESOLVED — Document clarifies the distinction in §3.1. |
| No concrete bound on η_Lemma9 provided | MEDIUM | OPEN — Lemma 9 accepted as assumption; document treats η_Lemma9 as "negligible" without quantifying it. |

## M4: Joint Extractor Composition

### 2026-05-14

| Issue | Severity | Status |
|-------|----------|--------|
| Independence of leaf extractions not formally proved (assumed for product formula) | MEDIUM | OPEN — The document notes the independence justification (distinct FS challenges) but does not prove it. |
| Exponential decay in t makes extraction infeasible for large t | HIGH | OPEN — For t=4 with ε_leaf≈0.65, ε_joint≈0.18. For larger t, extraction becomes impractical. Protocol should be parameterized with minimal t. |
| M-SIS concrete security at φ=256, q≈2^50, β=2048 not independently verified | MEDIUM | OPEN — Carried forward from M2. |
| The joint extractor's "contradiction argument" (Step 4) is informal | LOW | OPEN — The logic is correct (extraction failure implies hardness break) but is stated in prose rather than as a formal reduction. |

## M5: Formal Write-Up

### 2026-05-14

| Issue | Severity | Status |
|-------|----------|--------|
| Numerical tightness table shows vacuous forking-lemma bound for all ε_acc ≤ 1 | HIGH | OPEN — This is accurate (not a mistake). The real guarantee comes from M-SIS/SHA-256 reduction, not the forking-lemma bound. M5 §4.3 explains this. |
| Pseudocode LeafExtractor has MAX_REWINDS as an unspecified constant | LOW | OPEN — The actual value should be derived from the extraction probability analysis. Left as a parameter to avoid over-specifying. |
| M5's assumption security levels are estimates, not formally derived | LOW | OPEN — SHA-256 (2^{-128}) is well-characterized. M-SIS (2^{-128}) is an estimate. Lemma 9 has no concrete bound. ROM is heuristic. |
