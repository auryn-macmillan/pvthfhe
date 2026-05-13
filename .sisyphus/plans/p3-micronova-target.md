# P3 MicroNova + UltraHonk Target Implementation Plan

**Created**: 2026-05-13
**Status**: ASPIRATIONAL (blocked on P2 Track B)
**Paper reference**: §7.B (Track B), theorems P3-B-T1 through P3-B-T5

## Goal

Replace the ecrecover trusted-signer surrogate (Track A) with full on-chain cryptographic verification of the LatticeFold+ terminal accumulator via MicroNova compression + UltraHonk EVM verifier.

## Blocked Dependencies

| Dependency | Status | Resolution |
|-----------|--------|------------|
| P2 Track B (LatticeFold+) | ASPIRATIONAL | `.sisyphus/plans/p2-latticefold-target.md` |
| MicroNova integration with LatticeFold+ | DESIGN | Cyclo CCS → MicroNova step circuit adapter needed |
| UltraHonk verifier Solidity contract | OPEN | HonkVerifier.sol from Aztec protocol; gas projection 39,687 |
| BN254/Grumpkin cycle compatibility | VERIFY | Sonobe uses BN254; LatticeFold+ must use same field |

## Research Milestones

1. **M1: MicroNova step circuit** — Design step circuit encoding the LatticeFold+ terminal verifier relation over BN254/Grumpkin. Requires the exact constraint system from P2-B.

2. **M2: MicroNova compression** — Implement recursive compression reducing depth-d LatticeFold+ tree to constant-size proof. Leverage existing Sonobe Nova infrastructure.

3. **M3: UltraHonk verifier deployment** — Deploy HonkVerifier.sol to EVM testnet. Measure actual gas consumption (target: ≤5,000,000; projection: 39,687).

4. **M4: Gas optimization** — Profile and optimize the EVM verifier for the specific LatticeFold+ proof structure. Target: under 100,000 gas for competitive positioning.

5. **M5: Security proofs** — Complete proof skeletons from `docs/security-proofs/p3/proof-skeletons.md`:
   - T1: UltraHonk knowledge soundness over BN254
   - T2: MicroNova → UltraHonk soundness preservation
   - T4: Measured gas bound (not just projection)

## Estimated Effort

~6–10 weeks of engineering (depends on P2 Track B completion). The gas optimization step (M4) may require additional EVM-level profiling.

## Cross-references

- `docs/security-proofs/p3/proof-skeletons.md` — P3 Track B proof skeletons
- `docs/security-proofs/p3/advisor-verdict.md` — P3 Track A advisor verdict (APPROVE)
- `.sisyphus/plans/p2-latticefold-target.md` — P2 Track B plan (prerequisite)
- `.sisyphus/research/p3/prior-art.md` — Gas estimates for prior-art EVM verifiers
- `.sisyphus/design/spec-real-p2p3.md` — P2/P3 real specification
