# P1 Stack Review Memo

Date: 2026-05-03
Task: B.D.2 — P1 stack decision memo

VERDICT: APPROVE

## Summary

- The stack decision memo compares the four required stacks against quantitative metrics that matter for PVTHFHE P1: prover time, proof size, verifier time, recursion fit, PQ posture, license, and audit surface.
- The memo freezes SLAP as primary, Greyhound as research fallback, and Rust-in-zkVM as delivery fallback, consistent with the scorecard and novelty memo.
- The design stays compatible with the frozen `LatticeNizk` trait by keeping all choices behind the same statement/witness/proof adapter boundary.

## Primary Justification

- SLAP remains the highest-confidence primary because it is the best direct fit to the bounded decrypt-share relation while preserving a lattice-native and post-quantum proof story.
- Its projected verifier cost is not as low as Greyhound's, but it remains within a plausible recursion-consumption budget for P2 without forcing the project into a more immature transparent-proof stack immediately.

## Fallback Justification

- Greyhound is the right first fallback because its verifier profile is the strongest native-lattice hedge if recursion pressure dominates and SLAP's verifier object lands too heavy.
- Rust-in-zkVM is the right delivery fallback because it preserves a concrete path to an implementation even if native lattice constants miss expectations; this matches the explicit project instruction not to let proving efficiency become a blocker.

## Recursion Compatibility

- The memo properly centers P2 folding as the key downstream constraint rather than treating prover time as the only metric.
- SLAP, Greyhound, and wrapper fallbacks are all described in terms of the same deterministic `NizkProof` metadata contract (`constraint_estimate`, `proof_size_bytes`), which is the correct boundary for P2 consumption.

## Risks

- The largest unresolved risk remains the joint Fiat-Shamir binding between the inherited SHA-256 PVSS commitment and the lattice relation.
- Quantitative projections are still order-of-magnitude estimates from prior art plus local baselines, so implementation work must validate constants before P1 implementation freeze.
- License clarity for native lattice research code remains weaker than for zkVM fallbacks, increasing audit and packaging risk if external code is adopted.
