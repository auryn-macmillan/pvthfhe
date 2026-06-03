# P2 — Greyhound: Lattice Polynomial Commitments

**Status**: PLAN
**Date**: 2026-05-31
**Parent**: `.sisyphus/plans/lattice-meta-plan.md`

## Goal

Replace KZG-based commitments used in the Nova IVC accumulator with Greyhound lattice polynomial commitments. This removes the elliptic curve / pairing assumption from the accumulation layer.

## Why Greyhound

- 53KB evaluation proofs for N=2^30 — 10^4× smaller than SLAP
- Standard lattice assumptions (Module-SIS/Module-LWE), not pairings
- O(√N) verifier time (sublinear)
- Composable with LaBRADOR for full succinctness
- Eliminates need for Aztec SRS (KZG ceremony) — transparent setup

## Integration Architecture

```
pvthfhe-compressor/src/nova/
├── greyhound_pcs.rs          ← Greyhound polynomial commitment implementation
├── greyhound_accumulator.rs  ← Accumulator using Greyhound instead of KZG
├── monomial_range.rs         ← Replaced by LatticeFold+ algebraic range proof (P3)
├── nova_gadgets.rs           ← Updated to use Greyhound opening proofs
└── mod.rs                    ← GreyhoundPCS replaces KZG commitment scheme
```

## Phases

### Phase 1 — Greyhound Implementation (~6 hrs)
- [ ] Implement `GreyhoundPCS` struct: `commit(poly) -> Commitment`, `open(poly, eval_pt) -> OpeningProof`, `verify(commit, eval_pt, value, proof) -> bool`
- [ ] Implement Module-SIS commitment operation (A · s = t mod q)
- [ ] Implement O(√N) evaluation protocol: commit to polynomial, prove evaluation at random point
- [ ] Implement verifier: check commitment + evaluation proof
- [ ] Add `enable-greyhound` feature flag
- [ ] Verify: `cargo test -- greyhound` — commit/open/verify roundtrip passes

### Phase 2 — Replace KZG in Nova Accumulator (~4 hrs)
- [ ] Replace `Pedersen<G2>` commitment with `GreyhoundPCS` in `NovaCompressor`
- [ ] Replace `KZG<Bn254>` with `GreyhoundPCS` in `public_params::setup`
- [ ] Update `RecursiveSNARK` proof format to include Greyhound opening proofs
- [ ] Update `CompressedProof` serialization for Greyhound proof bytes
- [ ] Verify: Nova IVC prove/verify works with Greyhound (identity circuit test)

### Phase 3 — Integration Testing (~2 hrs)
- [ ] Test BFV DKG with Greyhound accumulator (n=3, t=1)
- [ ] Test CKKS DKG with Greyhound accumulator (n=3, t=1)
- [ ] Benchmark: Greyhound proof size vs KZG proof size
- [ ] Benchmark: Greyhound verifier time vs KZG verifier time

## Success Criteria
- [ ] Greyhound commit/open/verify roundtrip passes
- [ ] Nova IVC prove/verify with Greyhound passes (identity circuit)
- [ ] `just demo-e2e` ACCEPT with Greyhound backend
- [ ] Greyhound proof size < 100KB (target: 53KB at N=2^30)
- [ ] No KZG/pairing dependencies in the commitment layer
