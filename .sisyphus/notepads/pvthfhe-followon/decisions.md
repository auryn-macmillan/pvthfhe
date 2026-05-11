# Decisions — pvthfhe-followon

## 2026-05-02 — Session Start

- Sequential order: P4 → P1 → P2 → P3 (strictly enforced by gates)
- Paper strategy: UNIFIED primary; split-paper decision at end of C.D.5
- Proving stack: anything goes; Noir not a blocker; Rust-in-zkVM acceptable fallback
- Novelty: unrestricted; aggressive bets encouraged
- Surrogates: feature-flagged, never deleted (stub protocol)

## 2026-05-03 — Task B.I.3
- Kept the adversarial integration tests isolated to a new `lattice_nizk_adversarial.rs` file and committed only that file plus the captured evidence log, leaving existing GREEN implementation files untouched per task scope.

## 2026-05-03 — Task C.R.4
- Registered P2-T1 through P2-T5 in `docs/security-proofs/p2/theorem-inventory.md` and `docs/security-proofs/obligations.md` before any full proof drafts, keeping P2 on the same registry-first workflow as P1/P4.
- Chose to state P2-T4 with the repository-grounded symbolic accumulator `norm_bound` and to state P2-T5's `G ≤ 5,000,000` / `S ≤ 14 KB` limits as explicit downstream obligations, because the current repo freezes those budgets but does not yet prove them for the real P2 construction.
- Added `docs/security-proofs/p2/proof-skeletons.md` as the canonical P2 skeleton artifact and changed the obligations registry from `stated` to `skeleton`, while leaving T4 `norm_bound` numeric details explicitly open because the repo has not frozen that value yet.

## 2026-05-07 — CLI NIZK params consistency fix
- Canonicalized the demo NIZK parameter tuple in a shared helper rather than leaving duplicate literals in each CLI binary.
- Kept the secret-share modulus `65_537` untouched; only the RLWE degree and error bound now flow from `pvthfhe_nizk::sigma::{RLWE_N, B_E}`.

- 2026-05-03: For C.D.4, froze a P2 benchmark matrix over `n ∈ {128, 512, 1024}`, fold-depth `{5, 10}`, and stacks `{LatticeFold+, MicroNova, Rust-in-zkVM}`, using the stack-decision memo as the quantitative anchor and the recursive/scalar baselines only as projection guardrails.
- 2026-05-03: For C.D.4 migration planning, staged the surrogate-to-real rollout around `folding-real` and `folding-surrogate` flags at the `FoldingScheme` boundary so rollback can flip backend defaults without changing the frozen interface.
