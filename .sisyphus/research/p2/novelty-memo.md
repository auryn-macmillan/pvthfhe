# P2 Novelty Gap Memo

## Required Novelty
Identify what is MISSING in existing work for our specific setting:
- (a) Folding over RLWE relations consuming P1's specific SLAP sigma transcript as inner proof (P1 proof bytes layout: [2B version][4B t_len][t_bytes][8B z_s][z_e i64s][openings])
- (b) Accumulator structure compatible with on-chain P3 verification (EVM gas constraints, Solidity verifier)
- (c) FHE-parameter consistency across folded steps (same q=65537, same degree n)
- (d) Batched share aggregation up to t=513 with n=1024

## Aggressive Bets
1. **Novel folding-over-NTT**: exploit the NTT structure of RLWE arithmetic to make the folding verifier circuit much cheaper (NTT-friendly challenges)
2. **Lattice-native accumulator with constant-size verifier**: accumulate RLWE relations without blowing up proof size — compress accumulator to O(log n) via recursion
3. **Hybrid lattice→Plonk projection**: prove the lattice folding in Plonk after 1 round of folding, so the on-chain verifier is just a standard Honk verifier — trades lattice purity for on-chain efficiency

## Risk Register
- **Novel folding-over-NTT**
  - **Risk:** NTT-friendly challenges might weaken soundness or require larger fields that break EVM compatibility.
  - **Likelihood:** Medium
  - **Impact:** High
  - **Mitigation:** Fallback to standard arithmetic checks inside the folding circuit (non-NTT) at the cost of higher prover overhead.
- **Lattice-native accumulator with constant-size verifier**
  - **Risk:** The recursion depth required to compress to O(log n) might cause prover time to exceed our O(n) threshold.
  - **Likelihood:** High
  - **Impact:** High
  - **Mitigation:** Rely on flat batch verification instead of deep recursion, or pivot to MicroNova for out-of-the-box constant-size verification.
- **Hybrid lattice→Plonk projection**
  - **Risk:** Plonk/Honk circuit might be too large to prove the first lattice folding round efficiently.
  - **Likelihood:** Medium
  - **Impact:** Medium
  - **Mitigation:** Optimize the first-round folding verifier or use Rust-in-zkVM for the final projection step.

## Pivot Triggers
- If LatticeFold+ prover time at t=513 exceeds 10× P1 prove time → pivot to MicroNova
- If on-chain verifier gas exceeds 5M gas → pivot to Hybrid lattice→Plonk
- If Rust-in-zkVM proves viable within 30s end-to-end → accept as delivery path
