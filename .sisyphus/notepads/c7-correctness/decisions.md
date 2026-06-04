# Decisions: C7 Correctness Plan

## 2026-06-04

### D.1: Schwartz-Zippel vs coefficient-wise verification

**Decision**: Use Schwartz-Zippel (single evaluation at random challenge point).

**Rationale**: 
- Coefficient-wise approach requires 3 × 8192 × t constraints for N=8192. For t=4, that's ~98K constraints.
- Schwartz-Zippel requires ~7 constraints per share (3 modulus limbs × 1 eval + 1 Horner = ~4 per share, plus recombination product and sum). For t=128, that's ~900 constraints.
- Schwartz-Zippel false acceptance probability is ≤ N / |Fr| = 8192 / 2^254 ≈ 0.
- This is the same approach used by Nova and other IOP-based systems.

**Alternatives considered**: Coefficient-wise verification was rejected due to constraint count.

### D.2: Extend aggregator_final vs create new circuit

**Decision**: Extend `circuits/aggregator_final/src/main.nr`.

**Rationale**:
- The existing circuit already has the correct structure (Nova final state input, plaintext commitment verification).
- Adding constraints to the existing `main()` function is simpler than creating a new circuit with cross-circuit verification.
- The canonical Noir+BB flow is already set up for `aggregator_final`.
- Phase B.1 (G3) was scoped to complete the C7 circuit verification in this circuit.

**Alternatives considered**: Creating a separate `c7_correctness` circuit was rejected because it would require cross-circuit binding between the hash-proving circuit and the correctness-proving circuit, adding complexity.

### D.3: Ring arithmetic per-modulus-limb

**Decision**: Verify the Lagrange recombination independently for each of the 3 RNS moduli (q₀, q₁, q₂). Do not CRT-reconstruct in-circuit.

**Rationale**:
- Each modulus q_j is ~58 bits, fitting in one BN254 Fr field element.
- CRT reconstruction in Noir would require modular arithmetic over Q ≈ 2^174, which requires big-int emulation or multiprecision arithmetic. This is expensive (~100-500 constraints per coefficient).
- Checking per-modulus-limb ensures the equality holds modulo each q_j. By CRT uniqueness, if the equality holds for all 3 moduli, it holds modulo Q.
- The Lagrange coefficients λ_i are small integers (≤ 64 bits for small t), so no modular reduction issues within each limb.

### D.4: MAX_SHARES = 128

**Decision**: Set MAX_SHARES = 128 for the Noir circuit.

**Rationale**:
- Matches the existing `NOIR_MAX_PARTICIPANTS` constant in `full_pipeline.rs`.
- Constraint count is linear in MAX_SHARES but ~256 constraints for 128 is negligible.
- Can be increased later without changing the constraint logic (just change the global constant).
- For N=8192 scaling, MAX_SHARES would need to increase to 8192, but that's a separate scaling concern (covered by c7-p3-final.md).
