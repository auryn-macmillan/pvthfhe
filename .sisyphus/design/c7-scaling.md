# Design: C7 Scaling — aggregator_final N=128 and Beyond

**Status**: DESIGN (Phase 5)
**Depends on**: Phase 1-4 completion

## Current State

`circuits/aggregator_final/src/main.nr` operates with `MAX_PARTICIPANTS = 128`
and N (ring dimension) = 8. The Lagrange recombination computes O(MAX_PARTICIPANTS^2)
per coefficient using nested loops.

## N=128 Scaling Plan

1. **Precompute Lagrange coefficients**: Lagrange coefficients `L_i(0)` are
   deterministic given the committee party IDs. Precompute them as a circuit
   constant array `lagrange_coeffs: [Field; MAX_PARTICIPANTS]` and replace the
   O(n^2) nested loop with a single O(n) weighted sum:
   ```
   let mut plaintext = 0;
   for i in 0..n {
       plaintext += shares[i] * lagrange_coeffs[i];
   }
   ```

2. **Constraint measurement**: Run `nargo info` at N=128 to measure constraint
   count. Expectation: <2M constraints (UltraHonk budget). Actual: TBD.

3. **Incremental scaling**: Test at N=128, then N=256, then N=512. Monitor
   constraint growth. If constraints grow polynomially with N, parametrize
   `MAX_PARTICIPANTS` as a compile-time configurable constant.

4. **N=8192 path**: If N=8192 exceeds 2M constraints, consider:
   - Merkle-tree batched Lagrange (O(log n) amortized per coefficient)
   - Offload Lagrange precomputation to the client (pass as public input)
   - Use Poseidon sponge accumulators over batched coefficient groups

## Success Criteria

- N=128 passes `nargo test` and `nargo execute`
- Constraint count measured and documented
- N=8192 path documented in `spec-real-p2p3.md`
- C7 status: "N=128 functional in research prototype, N=8192 deferred to Phase 5"
