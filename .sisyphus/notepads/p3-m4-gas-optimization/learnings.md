# P3-M4 Learnings

## 2026-05-14 — Document Created

- Created `docs/security-proofs/p3/gas-optimization.md` from the plan at `.sisyphus/plans/p3-m4-gas-optimization.md`
- Baseline figure of 39,687 gas comes from the Aztec UltraHonk verifier reference (standard Honk without LatticeFold+ additions)
- Current `HonkVerifier.sol` is a keccak256 placeholder (~3M gas) — this is NOT the baseline; it's a stub awaiting BB Solidity verifier generator support
- T4 gas-bound theorem sets a hard ceiling of 5,000,000 gas; our M4 target of <100,000 is much more aggressive
- Three optimization categories identified: strip lookup logic, optimize pairings, inline scalarmul
- All actual profiling is blocked on P3-M3 completing the EVM deploy with a real verifier
- The `bb write_solidity_verifier` tool is blocked on BB version 5.0.0-nightly.20260324 producing wrong VK shapes
- Notepad directory pattern: `.sisyphus/notepads/{plan-name}/`
