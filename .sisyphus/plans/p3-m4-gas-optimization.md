# Plan: P3 M4 — Gas Optimization

**Plan**: `p3-m4-gas-optimization`
**Status**: DRAFT
**Created**: 2026-05-14
**Depends on**: P3-M3 (EVM deploy)
**Goal**: Profile and optimize the UltraHonk EVM verifier for the specific LatticeFold+ proof structure. Target: under 100,000 gas.

---

## Implementation

### P3-M4.1 — Profile current gas

Use Foundry's `forge test --gas-report` to identify hot paths in HonkVerifier.sol.

### P3-M4.2 — Optimize

- Remove unused UltraHonk features (no lookup arguments in LatticeFold+ proofs)
- Optimize pairing checks (BN254 pairings are ~45K gas each)
- Inline scalar multiplication in G1/G2 field operations

### P3-M4.3 — Re-measure

| Metric | Before | After | Target |
|--------|--------|-------|--------|
| Gas | ~40K | TBD | <100K |

### P3-M4.4 — Documentation

- Update `p3-micronova-target.md` — mark M4 complete

## Acceptance Criteria

- [ ] Gas optimized and re-measured
- [ ] Under 100K target achieved or documented why not

## Estimated Effort

~1-2 weeks. EVM gas golfing.
