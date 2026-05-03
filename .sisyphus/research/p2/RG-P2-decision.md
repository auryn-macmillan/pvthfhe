# RG-P2 Decision Memo

## Primary: LatticeFold+

LatticeFold+ is approved as the P2 primary because it is the best fit for the frozen P1→P2 handoff: the relation is already mostly arithmetic, the program wants an RLWE-native fold path, and LatticeFold+ is the strongest known lattice-native candidate in the current survey. It improves materially over LatticeFold on prover and verifier simplicity, which matters because the downstream obligations are not only theoretical soundness but also a viable wrapped verifier path for P3. The choice is still research-grade rather than production-grade, so approval is conditioned on preserving an explicit fallback and on exiting quickly if the verifier budget or fold relation fidelity breaks.

## Fallback: MicroNova and Rust-in-zkVM

MicroNova is frozen as the first pivot when P2-T5 dominates the decision: it has the clearest on-chain verifier story and therefore is the right fallback if the lattice-native route cannot plausibly compress to the required proof-size and gas envelope. Rust-in-zkVM is frozen as the guaranteed delivery fallback because it can prove the existing Rust P1 verifier with the least semantic translation risk, especially around exact byte parsing, SHA-256 transcript recomputation, and witness-opening behavior. The pivot order is therefore: stay on LatticeFold+ while the RLWE-native path remains credible, move to MicroNova if the blocker is verifier envelope, and move to Rust-in-zkVM if the blocker is implementation deliverability or semantic mismatch.

## Kill Criteria

- Abandon LatticeFold+ if the fold relation cannot faithfully encode the frozen P1 verifier equation, including SHA-256 transcript recomputation, bounded `z_e` checks, and accumulator binding, without underconstraining soundness.
- Abandon LatticeFold+ in favor of MicroNova if the best credible wrapped-proof path still misses the P2-T5 target of ≤14KB final proof size or ≤5M gas.
- Abandon both native and non-native folding candidates in favor of Rust-in-zkVM if exact Rust-verifier wrapping becomes the only path with credible delivery inside the current research program.

## Advisor Sign-off
VERDICT: APPROVE
