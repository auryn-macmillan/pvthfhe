# RG-P3 Decision Memo

Date: 2026-05-03
Gate: RG-P3 — candidate scorecard + primary/fallback freeze

## Inputs Reviewed

- `.sisyphus/research/p3/prior-art.md`
- `.sisyphus/research/p3/novelty-memo.md`
- `.sisyphus/research/p3/threat-model.md`
- `docs/security-proofs/p3/theorem-inventory.md`
- `.sisyphus/research/p3/scorecard.md`

## VERDICT: APPROVE

## Primary: SP1 + Groth16 wrap

SP1 + Groth16 wrap is approved as the P3 primary because it satisfies the concrete envelope today: reported verifier gas is comfortably below 5M, proof plus the fixed 200-byte public-input blob stays far below 14 KB, and the path uses established BN254 pairing precompiles rather than an EIP we may not land in time. It is also the strongest current delivery balance between verifier maturity and implementation effort, which matters because the P3 threat model makes contract correctness and audit surface more important than theoretical elegance alone.

## Fallback: Rust-in-zkVM with EVM final wrap

Rust-in-zkVM with EVM final wrap is approved as the fallback because it is the cleanest non-EIP escape hatch if the primary circuit expression or wrapper integration slips. This path keeps the final on-chain verifier inside the same existing precompile envelope while preserving exact Rust semantics for the frozen upstream verifier relation, making it the most credible worst-case delivery route.

## Kill / Pivot Triggers

- Pivot away from the primary if the wrapped verifier relation cannot bind the frozen 200-byte public-input layout without adding unacceptable complexity or undercutting T1/T2.
- Pivot if the concrete SP1 wrap path loses its sub-5M gas or sub-14 KB proof advantage once the real lattice-facing verifier is encoded.
- Do not promote any EIP-dependent path to primary unless it ships with a non-EIP fallback that can be delivered on the current schedule.

## Sign-off

Signed: Prometheus
