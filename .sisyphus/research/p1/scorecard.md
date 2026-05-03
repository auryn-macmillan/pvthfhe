# P1 Candidate Scorecard

This scorecard ranks the viable B.R.1 candidates against the frozen P1 constraints from the prior-art matrix, novelty memo, threat model, theorem inventory, and P4→P1 bundle. Scores use a 1–5 scale where 5 is best. Weighted totals are on a 5.00-point scale.

## Weighted Criteria

- **Scale at n=1024 (20%)**: expected prover time and memory under the batch sizes targeted by PVTHFHE.
- **Verifier cost for downstream P2 folding consumption (25%)**: recursion-friendliness and verifier work dominate because P2/P3 need a cheap verification object.
- **FHE-parameter compatibility (20%)**: ability to bind the intended RLWE parameter tuple `(q, N, error bound)` from the theorem inventory and downstream bundle, without treating the current P4 Shamir/SHA-256 surrogate as the final witness shape.
- **Novelty cost (15%)**: inverse score for how much new technique is needed beyond the cited line of work.
- **PQ posture (10%)**: whether the candidate remains lattice-native / PQ-aligned under the frozen ROM baseline, while acknowledging that QROM-level claims are deferred.
- **Implementation feasibility / zkVM fallback viability (10%)**: practical path to a working verifier, including whether a zkVM fallback remains clean if the primary path misses constants.

## Weighted Scores

| Candidate | Scale 20% | Verifier 25% | FHE compat 20% | Novelty cost 15% | PQ posture 10% | Feasibility 10% | Weighted total | Rank |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SLAP | 4.00 | 3.75 | 4.50 | 3.25 | 4.50 | 3.00 | 3.88 | 1 |
| Greyhound | 3.50 | 4.75 | 4.00 | 2.50 | 4.50 | 2.50 | 3.76 | 2 |
| LANES / LNS21 | 3.50 | 2.75 | 4.50 | 4.00 | 4.50 | 3.25 | 3.66 | 3 |
| Beullens one-shot lattice ZK | 3.75 | 3.50 | 4.00 | 3.25 | 4.50 | 2.75 | 3.64 | 4 |
| SNARK-friendly hash-of-RLWE-witness | 2.50 | 5.00 | 3.25 | 3.75 | 2.00 | 4.00 | 3.56 | 5 |
| Rust-in-zkVM (SP1 / RISC0 / Jolt) | 2.00 | 4.25 | 3.25 | 4.50 | 2.00 | 5.00 | 3.49 | 6 |

## Scoring Notes

### SLAP
- Best direct fit to the intended decrypt-share/plaintext-consistency relation once the public statement binds the inherited SHA-256 transcript plus the RLWE tuple from T1–T5.
- Verifier is not as recursion-friendly as Greyhound or a conventional outer SNARK, but it stays closer to the native lattice proof target than those wrappers.
- Novelty cost is moderate rather than low because the bridge from plaintext consistency to the exact P1 share relation still needs adaptation work.

### Greyhound
- Strongest verifier/folding profile among the lattice-native candidates, which matters because P2 folding consumption is weighted above prover speed in this program.
- Takes a novelty/feasibility hit because transparent-lattice engineering maturity and concrete constants remain thin for the exact P1 relation.

### LANES / LNS21
- Mature direct-lattice fallback with a good fit to linear relations and boundedness, especially if the system needs a less novel native proof story.
- Loses mainly on verifier cost; the verifier is workable off-chain but still heavier than the recursion-first paths.

### Beullens one-shot lattice ZK
- Attractive direct-lattice option with flatter transcripts than classic Σ-proofs and a credible path to expressing bounded linear relations.
- Falls behind SLAP because the exact ciphertext/share/plaintext consistency fit is weaker and practical implementation data are thinner.

### SNARK-friendly hash-of-RLWE-witness
- Wins decisively on verifier cost, but gives up too much on PQ alignment and direct RLWE-parameter fit because the outer SNARK becomes the dominant soundness object under the frozen ROM baseline.
- Remains a useful engineering pattern if recursion dominates every other concern, but it is not the cleanest frozen P1 research choice.

### Rust-in-zkVM (SP1 / RISC0 / Jolt)
- Operationally strongest fallback because it can ship a real verifier even if the native lattice candidates miss constants.
- Scores lower overall due to prover cost and mixed post-quantum posture, but the program explicitly accepts it as the worst-case path.

## Freeze Decision

- **Primary: SLAP**
- **Fallback: Greyhound**
- **Fallback: Rust-in-zkVM (SP1 / RISC0 / Jolt)**

## Frozen Rationale

### Primary freeze — SLAP
SLAP wins the weighted scorecard because it is the best-balanced option across the two hardest P1 constraints: (1) direct expression of the intended lattice decrypt-share relation and (2) a verifier story that is still plausible for downstream P2 folding. It preserves a lattice-native, PQ-aligned proof direction under the frozen ROM baseline without paying Greyhound's extra engineering immaturity penalty.

### Fallback freeze — Greyhound
Greyhound is the research fallback because its verifier profile is the best native-lattice hedge if SLAP's concrete verifier or transcript costs prove too high. If the program must optimize for recursion-friendliness over near-term engineering tractability, Greyhound is the next candidate to promote.

### Fallback freeze — Rust-in-zkVM
Rust-in-zkVM is the delivery fallback because it keeps the project moving even if every native lattice path misses constants or extractor complexity targets. This freeze is explicit so efficient proving cannot become a blocker for RG-P1.

## Pivot Triggers For The Freeze

- Pivot from **SLAP → Greyhound** if SLAP adaptation to the exact P1 share relation introduces a verifier object that is too heavy for P2 folding or requires an unacceptably bespoke joint extractor.
- Pivot from **SLAP/Greyhound → Rust-in-zkVM** if native-lattice proving cannot produce acceptable constants or implementation confidence on the RG-P1 schedule.
- Do **not** use the current surrogate witness shape from `circuits/decrypt_share/src/main.nr` as a selection input; the freeze is based on the intended RLWE-plus-transcript relation from the threat model and theorem inventory instead.
