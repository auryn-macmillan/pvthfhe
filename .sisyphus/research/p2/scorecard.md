# P2 Candidate Scorecard

This scorecard freezes the P2 folding-scheme selection against the frozen P1 verifier equation, the P2 theorem obligations, and the delivery constraints inherited from P3. Scores use a 1–5 scale per criterion, then apply the required weights.

## Weighted Criteria

| Criterion | Weight | Description |
| --- | --- | --- |
| RLWE-native | 25% | Can absorb the frozen P1 RLWE verifier equation natively |
| Folding depth scalability | 20% | Handles depth d at t=513, n=1024 without exponential prover blowup |
| Prover memory per fold step | 15% | Memory footprint at n=1024 |
| On-chain verifier cost (P3) | 20% | Final proof size ≤14KB, gas ≤5M (P2-T5 obligation) |
| Maturity/auditability | 10% | Peer-reviewed or independently vetted |
| Implementation deliverability | 10% | Can be delivered in this research program with available tooling |

## Weighted Scores

| Candidate | RLWE-native 25% | Folding depth scalability 20% | Prover memory per fold step 15% | On-chain verifier cost (P3) 20% | Maturity/auditability 10% | Implementation deliverability 10% | Weighted total | Rank |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| LatticeFold+ (ePrint 2025/247) | 5 | 4 | 3 | 2 | 2 | 3 | 3.45 | 1 |
| MicroNova (ePrint 2024/2099) | 1 | 4 | 3 | 5 | 4 | 4 | 3.25 | 2 |
| Rust-in-zkVM (SP1 / RISC0 wrapping the P1 Rust verifier) | 1 | 4 | 2 | 4 | 4 | 5 | 3.00 | 3 |
| LatticeFold (2024) | 4 | 3 | 2 | 2 | 3 | 2 | 2.85 | 4 |
| HyperNova | 1 | 4 | 3 | 3 | 4 | 3 | 2.75 | 5 |

## Freeze Decision

Primary: LatticeFold+
Fallback: MicroNova
Fallback: Rust-in-zkVM

## Primary Rationale

LatticeFold+ is the best research fit because it is the only surveyed candidate that is both lattice-native and explicitly aimed at simplifying the folding verifier for succinct proof systems. That matters directly for the frozen P1 verifier equation, which is already mostly arithmetic except for SHA-256 recomputation and bounded `z_e` checks, so the primary value is preserving an RLWE-native path instead of immediately paying a commitment-model mismatch. It also improves materially over LatticeFold on prover and proof-shape constants, which is important because P2 must still leave room for the downstream P3 verifier budget.

## Fallback Rationale

MicroNova is the delivery fallback when the main blocker is the P2-T5 envelope rather than lattice purity. It gives the strongest known on-chain story among the realistic non-lattice candidates and therefore stays frozen as the first pivot when proof size or gas becomes dominant.

Rust-in-zkVM remains the guaranteed delivery fallback because it can wrap the frozen Rust P1 verifier directly, including byte parsing and SHA-256 transcript logic, with the least research risk. It is not the desired end-state, but it preserves a credible exit if the lattice-native line stalls or the non-lattice recursive route still needs too much circuit adaptation.

## Kill Criteria / Pivot Triggers

### LatticeFold+ kill criteria

- Pivot away from LatticeFold+ if the folded design cannot preserve the frozen P1 verifier relation without introducing an unsound or underconstrained treatment of SHA-256 transcript recomputation, `z_e` range checks, or accumulator binding.
- Pivot to MicroNova if credible projections for the wrapped final proof miss P2-T5 by a wide margin, i.e. no plausible path to ≤14KB proof size or ≤5M gas remains after one design iteration.
- Pivot to Rust-in-zkVM if implementation friction dominates and a native lattice prototype cannot demonstrate a believable path for t=513, n=1024 within the research program's available tooling.

### MicroNova pivot triggers

- Use MicroNova only if the bottleneck is verifier size/gas rather than RLWE-native folding semantics.
- Abandon MicroNova for Rust-in-zkVM if the verifier circuit for the frozen P1 relation becomes too awkward because of SHA-256, exact byte decoding, or witness-opening semantics from the current proof payload.

### Rust-in-zkVM pivot triggers

- Use Rust-in-zkVM when guaranteed delivery and semantic fidelity to the frozen P1 verifier outweigh research purity.
- Treat it as the terminal fallback, not an intermediate optimization track.
