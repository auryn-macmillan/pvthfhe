# Plan: Per-Node Performance — KZG SRS + Batched Parity + Skip Precomp

**Status**: PLAN
**Target**: Reduce per-node distributed E2E from ~72s to ~17s at n=64

## Option 1: Reduce KZG SRS Size (2¹⁷ → 2¹⁴)

The KZG trusted setup in `snark_bridge.rs` uses `DECIDER_N = 1 << 17` (131k).
The `DealerParityStepCircuit` has 2 + n multiplications — for n=64, ~66 constraints.
A KZG SRS of 2¹⁴ (16k) covers all practical party sizes up to n=4096.

### Change
1. `/home/dev/pvthfhe/crates/pvthfhe-compressor/src/sonobe/snark_bridge.rs`
   Change `DECIDER_N = 1 << 17` to `1 << 14` (still powers entries up to 16384).
   The KZG::setup runtime is ~proportional to SRS size.

### Verification
- `dealer_parity_works` passes
- KZG `setup` time reduced from ~20s to ~2s
- No circuit constraint count increase

## Option 2: Batch Parity Proofs (One KZG Setup for All Dealers)

Currently: `for each dealer: new SonobeCompressor → KZG::setup → prove_step → ivc_proof`
The KZG setup runs n times. The Nova prover/verifier key is RECREATED per dealer.

Fix: create ONE `SonobeCompressor` before the dealer loop, reuse it.
`SonobeCompressor::prove` reads `DEALER_PARITY_DATA` from thread-locals, so
one compressor can handle multiple dealers with different share data.

### Changes
1. `/home/dev/pvthfhe/crates/pvthfhe-cli/src/full_pipeline.rs`
   Move `SonobeCompressor::<DealerParityStepCircuit<Fr>>::new(...)` from inside
   the dealer loop (~line 380) to before the loop.
   Inside the loop: just call `compressor.prove(&acc, &pi)` for each dealer.

### Verification
- `demo-e2e 5 2 1` ACCEPT — all parity checks pass
- KZG setup logged once not n times
- Prove per dealer still works (thread-local data correctly updated)

## Option 3: Skip `setup_threshold` Precomputation

`compute_party_sk_sums` in `fhers.rs` regenerates Shamir shares from
`party_state.sk_poly_sum`, which were already computed during DKG deal.
The 20.5s (756MB) at n=64 is redundant.

### Change
Make `setup_threshold` / `compute_party_sk_sums` a no-op when the data
is already available from the DKG deal phase.

## Rollout (Options 1+2 first, 3 after)

1. Apply Option 1 (SRS size) — one-line change
2. Apply Option 2 (batched parity) — restructure dealer loop
3. Build + test: `dealer_parity_works` + `demo-e2e 5 2 1`
4. Apply Option 3 (skip precomp)
5. Build + test: `demo-e2e 5 2 1` + `demo-e2e 64 31 1`

## Success Criteria

- [x] Option 1: KZG SRS capped at `1 << 14` (kzg.rs:106 `max_srs = 1 << 14`)
- [x] Option 2: One compressor instance reused across dealers (full_pipeline.rs)
- [ ] Option 3: `setup_threshold` wall clock → near-zero at n=64 — DEFERRED
- [x] `demo-e2e 5 2 1` ACCEPT throughout (verified 2026-05-23)
- [ ] `demo-e2e 64 31 1` shows measurable per-node speedup — NOT RUN (calculable: KZG SRS ~8× faster + batched parity ~n× fewer setups)
