# RG-P1 Decision Record

Date: 2026-05-03
Gate: RG-P1 — P1 candidate scorecard + primary/fallback freeze

## Inputs Reviewed

- `.sisyphus/research/p1/prior-art.md`
- `.sisyphus/research/p1/novelty-memo.md`
- `.sisyphus/research/p1/threat-model.md`
- `docs/security-proofs/p1/theorem-inventory.md`
- `.sisyphus/contracts/p4-to-p1-bundle.md`
- `.sisyphus/research/p1/scorecard.md`

## Decision

- **Primary frozen for P1:** SLAP
- **Fallback frozen for P1:** Greyhound
- **Fallback frozen for P1:** Rust-in-zkVM (SP1 / RISC0 / Jolt)

## Rationale

The weighted scorecard ranks **SLAP** first because it best balances direct fit to the intended decrypt-share relation, acceptable scaling at `n=1024`, and a verifier object that is still plausible for downstream P2 folding. This is the best current compromise between preserving a lattice-native, PQ-aligned P1 proof story under the frozen ROM baseline and respecting the program-wide requirement that verifier cost matters more than raw prover speed.

**Greyhound** is frozen as the primary research fallback because it offers the strongest recursion-friendly verifier path among the lattice-native candidates. It is not selected as primary only because the engineering/constant risk is materially higher than SLAP today.

**Rust-in-zkVM** is frozen as the operational fallback because the user constraint explicitly permits it as the worst case. This keeps P1 moving even if native-lattice proving misses concrete constants, and prevents efficient proving from becoming a hard blocker.

## Constraints Preserved

- The freeze is based on the intended P1 relation from the threat model and theorem inventory, not on the current Noir surrogate witness shape.
- The baseline security target remains ROM knowledge soundness with rewinding extraction; simulation-soundness is not treated as a gating requirement for this freeze.
- The public statement must bind the concrete RLWE parameter tuple `(q, N, error bound)` together with the inherited SHA-256 transcript semantics exported by P4.

## Advisory Notes / Future Revisit Conditions

- Revisit the primary choice if SLAP cannot express the joint SHA-256-plus-RLWE binding without a qualitatively new extractor argument.
- Revisit the native-lattice path entirely if Greyhound and SLAP both miss acceptable verifier or prover constants for the P2 folding target.
- If the program chooses a fully transparent PQ outer proof stack later, the SNARK-friendly hash-of-RLWE-witness row may deserve a fresh score update.

## Sign-off

**Prometheus:** APPROVE — primary/fallback freeze accepted for RG-P1.

**External Advisor:** [PENDING HUMAN REVIEW]
Note: human advisory review remains open; this placeholder records the dependency without blocking the mechanical RG-P1 gate.
