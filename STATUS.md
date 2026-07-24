# Status

> ⚠️ **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**

Snapshot as of 2026-07-24 (post-refactor). For the canonical ledger see [docs/OPEN-PROBLEM-BLOCKERS.md](docs/OPEN-PROBLEM-BLOCKERS.md); for design see [ARCHITECTURE.md](ARCHITECTURE.md).

## What works (verified by gates)

- **P4 DKG**: 3-round PVSS keygen with blame, commit-reveal rogue-key defense, session-bound transcripts. `just pvss-gate`, `just dkg-paper-gate`.
- **P1 NIZK**: Ajtai D2 + BFV sigma (90-round), LaZer (LaBRADOR) default, Greyhound PCS. `just phase1-gate`.
- **P2 folding**: LatticeFold+ lattice-native folding (sole backend; Track A Nova removed). `just compressor-gate`.
- **P3 on-chain**: UltraHonk Solidity verifier + IVC binding (fail-closed). `just ajtai-onchain-gate`, `just noir-onchain-gate`, `just verify-onchain`.
- **C7 threshold decryption**: Schwartz-Zippel Lagrange recombination proven in Noir (`aggregator_final`, 29 tests).
- **End-to-end demo**: `just demo-e2e` (DKG → encrypt → fold → decrypt → on-chain).
- **Test suites**: Rust workspace, Noir workspace, and `forge test` all green.

## What is open

| ID | Problem | State |
|----|---------|-------|
| P1 | Lattice NIZK well-formedness soundness (Greco M-SIS) | OPEN |
| P2 | LatticeFold+ linearity/soundness over RLWE | OPEN (contingent on Lemma 9, an accepted assumption) |
| P4 | On-chain IVC decider verification | OPEN (fail-closed today) |
| G-N8 | Noir circuit ring dimension N=256 vs production N=8192 | PARAMETERIZED (Noir beta.22 ACIR OOM at N=8192) |

Resolved: P3, C5, C6, C7, A1.

## Recent changes

- 2026-07-24: whole-repo refactor — 24 → 14 crates (Poulpy/enclave/offchain/keygen/keygen-spec/circuits-facade removed; micro-crates merged into `pvthfhe-foundations`; DKG consolidated into `pvthfhe-pvss`), duplicated primitives pinned by equivalence tests, broken baseline repaired (6 pre-existing failures), docs reconciled.
- 2026-07-14: security-audit remediation merged (44 files, +1659/−337).
- 2026-06: three MPC audits remediated; DKG paper (ePrint 2026/1159) integration landed (NonEquiv, AVID, key escrow, leader election).
