# Labrador Norm Proofs — Recommended Upgrade Path

> **Paper**: "Labrador: Efficient Lattice Zero-Knowledge Proofs for Linear Relations with Short Secrets" (Fenzi et al. 2023, ePrint).
> **Date documented**: 2026-05-21
> **Status**: NOT IMPLEMENTED — documented as research reference for future upgrade.

## 1. Current Approach (R1CS L2 Accumulation)

The current in-circuit norm enforcement (G7b) tracks witness norm growth via L2 accumulators
(`z_s_sq_acc`, `z_e_sq_acc`) inside the CycloFoldStepCircuit with `state_len=7`. Each fold
step squares and accumulates coefficients into the state, and the verifier checks the
accumulated L2 norm against the accepted bound.

This approach **works** but is **expensive** in R1CS constraints:
- Each coefficient requires field multiplication and addition in the constraint system.
- For N=1024 ring elements, this adds Ω(N) constraints per fold step.
- The constraint cost scales linearly with ring degree, making large-N circuits unwieldy.

## 2. Labrador Approach (Recommended)

Labrador (Fenzi et al. 2023) gives ZK lattice proofs optimized for **norm-bound relations**:

### Core Idea
Instead of accumulating raw squared coefficients in R1CS, Labrador uses a **rejection-sampling
proof** that a polynomial has small norm without encoding every coefficient. The prover
commits to the witness and uses a hash-based challenge to prove the norm bound in sub-linear
communication.

### Key Innovations
1. **Norm-preserving linear maps**: Encode the norm condition into a compressed linear relation,
   reducing the number of constraints from O(N) to O(log N) per fold step.
2. **Rejection-sampling soundness**: The protocol achieves soundness via computational binding
   under the MSIS assumption with a slack factor (typically constant multiplicative overhead).
3. **One-shot norm proof**: Instead of per-coefficient constraint accumulation, a single
   compressed proof attests that all coefficients lie within the bound.
4. **Amortized efficiency**: When chained with folding, the Labrador proof composes naturally
   with Nova-style accumulation — the norm proof folds alongside the main statement.

### Circuit Impact (Estimated)
| Metric | Current (R1CS L2) | Labrador (Projected) |
|--------|-------------------|----------------------|
| Constraints per fold step | Ω(N) | O(log N) |
| Communication overhead | O(N) accumulated state | O(log N) sub-linear proof |
| Soundness slack | Exact (L2 bound) | Multiplicative slack (Labrador η factor) |

## 3. Upgrade Path

### Prerequisites
- P2 (lattice folding) must be resolved with a real lattice-native folding scheme (Cyclo
  Lemma 9 or successor), since Labrador norm proofs compose with the folding accumulator.
- The BFV/RLWE ring structure must be compatible with Labrador's norm map (power-of-two
  cyclotomic X^N+1 is the standard case).

### Integration Plan (T4+)
1. Replace the `norm.rs` per-coefficient check with a Labrador-style compressed norm gadget.
2. The gadget produces a single challenge-response proof that the witness satisfies
   `‖w‖_∞ ≤ B` without individual coefficient constraints.
3. The NormProof folds into the main accumulator alongside the SHA-256 commitment opening
   and algebraic relation checks — no separate verification step needed.
4. Verifier cost drops from O(N) to O(log N) per fold step, enabling practical scaling
   to N=8192 and beyond.

### Risk / Open Questions
- **Slack factor**: Labrador admits a multiplicative slack (prover can cheat up to η·B).
  Whether this slack is acceptable under PVTHFHE's soundness budget needs formal analysis.
- **Module compatibility**: Labrador is stated for module lattices; adapting to the specific
  Cyclo commitment ring X^256+1 with q≈2^50 requires verification.
- **Implementation complexity**: Labrador requires new cryptographic primitives (norm map,
  compressed proofs) that don't currently exist in the Nova/R1CS toolchain.

## 4. References

- **Primary**: Fenzi, G., Hesse, J., Krenn, S., Nguyen, N.K. "Labrador: Efficient Lattice
  Zero-Knowledge Proofs for Linear Relations with Short Secrets." ePrint 2023.
- **Survey**: Bootle, J., Cerulli, A., Chaidos, P., Groth, J. "Lattice-based Zero-Knowledge
  Proofs: New Techniques and Applications." (Related group signature ZKPs.)
- **In-code**: `crates/pvthfhe-aggregator/src/folding/norm.rs` (current G7b R1CS approach)
- **Notepads**: `.sisyphus/notepads/p2-m3-norm-enforcement/` (G7b implementation details)

## 5. Decision Log

- **2026-05-21**: Documented Labrador as recommended upgrade path per `.sisyphus/plans/claude-dkg-improvements.md` Task 2. No implementation at this stage — deferred to T4 (post P2 resolution).

- **2026-06-03**: Verified `bench/results/aggregate_1024.json` exists after running the aggregate smoke test command, but the test target now errors because `legacy-fold` has been removed in R4.3 and the crate expects `real-folding` instead.
