# P2 Benchmark Plan

This plan freezes the P2 design-stage benchmark matrix for the LatticeFold+ primary stack against the two already-frozen pivots, using the current repo baselines as anchors and treating every number below as **projected / estimated** rather than measured. The fixed parameter tuple for these projections is `(q=65537, N=1024, B_e=17, k=ternary_challenge_set={-1,0,1})`, and the target operating point remains `t=513` with binary fold depth near `10`.

## Benchmark Matrix

All rows below are projected. They extrapolate from `.sisyphus/design/p2/stack-decision.md` and the checked-in baselines in `bench/results/`, especially the surrogate folding accumulator (`280` bytes at 1024 folds), the current recursive baseline (`21,856`-byte final proof, `~7.8 GiB` peak memory), and the KZG verifier checkpoint (`3.65M` gas at batch size `128`).

| n | fold-depth | stack | projected-prover-time | projected-mem-peak | projected-accum-size | projected-verifier-gas | note |
| --- | ---: | --- | --- | --- | --- | --- | --- |
| 128 | 5 | LatticeFold+ | ~0.6-1.4 s projected | ~0.6-1.0 GiB projected | ~1-2 KB projected | ~4.0-4.4M projected | Smallest planned sweep; accumulator stays close to the current surrogate order of magnitude but with real-folding overhead. |
| 128 | 5 | MicroNova | ~2-5 s projected | ~0.9-1.4 GiB projected | ~0.5-1.0 KB projected | ~2.2-2.8M projected | Pays circuitization cost early but keeps the strongest projected verifier envelope. |
| 128 | 5 | Rust-in-zkVM | ~8-20 s projected | ~1.8-3.0 GiB projected | ~16-24 KB projected | ~2.5-3.2M projected | Delivery-first baseline; proof object remains much larger than the lattice-native paths. |
| 128 | 10 | LatticeFold+ | ~1.2-2.6 s projected | ~0.9-1.5 GiB projected | ~1-3 KB projected | ~4.1-4.8M projected | Deeper recursion pressure without the full `t=513` witness width. |
| 128 | 10 | MicroNova | ~4-9 s projected | ~1.2-2.0 GiB projected | ~0.6-1.2 KB projected | ~2.4-3.1M projected | Compression advantage should remain visible even when prover time scales worse than LatticeFold+. |
| 128 | 10 | Rust-in-zkVM | ~14-35 s projected | ~2.5-4.0 GiB projected | ~20-32 KB projected | ~2.8-3.6M projected | Tracks the exact Rust verifier shape; latency becomes the main trade-off. |
| 512 | 5 | LatticeFold+ | ~1.0-2.5 s projected | ~0.9-1.6 GiB projected | ~1-3 KB projected | ~4.0-4.7M projected | Mid-scale point before the full `t=513` target; expected to stay clearly below the recursive memory baseline. |
| 512 | 5 | MicroNova | ~3-8 s projected | ~1.2-2.3 GiB projected | ~0.5-1.5 KB projected | ~2.2-3.1M projected | Useful pivot checkpoint when verifier gas dominates the decision. |
| 512 | 5 | Rust-in-zkVM | ~12-40 s projected | ~2.5-4.8 GiB projected | ~16-40 KB projected | ~2.5-3.8M projected | Likely acceptable only if native folding stalls. |
| 512 | 10 | LatticeFold+ | ~2-5 s projected | ~1.3-2.4 GiB projected | ~1-4 KB projected | ~4.0-5.2M projected | Direct anchor to the stack-decision `t=513`, fold-depth≈10 band. |
| 512 | 10 | MicroNova | ~7-16 s projected | ~1.8-3.2 GiB projected | ~0.5-2 KB projected | ~2.2-3.5M projected | Best current projected path to the `≤5M` gas target if the primary stack stalls. |
| 512 | 10 | Rust-in-zkVM | ~24-80 s projected | ~3.5-6.5 GiB projected | ~16-56 KB projected | ~2.5-4.2M projected | Delivery fallback only; latency cost is already steep at this depth. |
| 1024 | 5 | LatticeFold+ | ~1.5-3.5 s projected | ~1.1-2.0 GiB projected | ~1-3 KB projected | ~4.1-4.9M projected | Full statement width with shallower recursion; should still preserve a credible path to the P2-T5 envelope. |
| 1024 | 5 | MicroNova | ~5-12 s projected | ~1.6-2.8 GiB projected | ~0.5-1.5 KB projected | ~2.3-3.3M projected | Pivot candidate if on-chain envelope pressure dominates before depth-10 measurements land. |
| 1024 | 5 | Rust-in-zkVM | ~18-60 s projected | ~3.0-5.5 GiB projected | ~16-40 KB projected | ~2.6-4.0M projected | Likely still under the recursive memory baseline, but only with a much larger final proof object. |
| 1024 | 10 | LatticeFold+ | ~2-6 s projected | ~1.5-3.0 GiB projected | ~1-4 KB projected | ~4.0-5.5M projected | Primary decision row from the stack memo; borderline on gas but strongest RLWE-native fit. |
| 1024 | 10 | MicroNova | ~8-20 s projected | ~2.0-4.0 GiB projected | ~0.5-2 KB projected | ~2.2-3.7M projected | First pivot if proof-size or gas becomes the blocking constraint. |
| 1024 | 10 | Rust-in-zkVM | ~30-120 s projected | ~4.0-8.0 GiB projected | ~16-64 KB projected | ~2.5-4.5M projected | Terminal fallback; preserves exact verifier semantics but risks missing latency and proof-size expectations. |

## Projected Timings

The timing projections are intentionally anchored to the current repository evidence rather than to unpublished assumptions. The checked-in surrogate folding benchmark shows roughly `167.1 ms` over `1024` folds with a `280`-byte accumulator, which is useful only as a lower-bound shape signal: a real LatticeFold+ implementation will be slower and somewhat larger because it must bind the frozen RLWE-with-noise verifier relation instead of a permissive surrogate. The stack-decision memo therefore remains the main anchor for the design-stage numbers, and this matrix interpolates around its `fold-depth≈10`, `t=513` rows by assuming shallower fold trees and smaller party counts reduce prover time and memory sublinearly while preserving the same ordering across stacks.

The verifier-gas projections are also design-level estimates. They use the existing `3.65M` gas KZG batch-verifier checkpoint as a reality check for the envelope and then preserve the relative ranking already frozen in `stack-decision.md`: LatticeFold+ stays borderline because it still depends on a credible P3 compression path, MicroNova keeps the cleanest path to `≤5M` gas, and Rust-in-zkVM remains plausible on gas only by accepting a much larger proof object and materially slower proving. None of these figures should be treated as measured implementation commitments; they exist to define what the implementation-wave benchmark harness must confirm or falsify.

A practical reading of the time bands is that LatticeFold+ only needs to beat the current recursive baseline decisively enough to preserve its research justification. The recursive baseline at `n=1024` already peaks around `~7.8 GiB` memory with a `21,856`-byte final proof, so a projected LatticeFold+ row in the low-single-digit seconds, low-single-digit GiB, and low-kilobyte accumulator range is enough to justify staying on the primary path until the real adapter lands. MicroNova and Rust-in-zkVM are retained in the matrix not because they are equally likely, but because the migration plan needs explicit numerical checkpoints for pivot and rollback decisions.

## Interpretation

The primary success condition is simple: keep LatticeFold+ as the default stack if real measurements preserve a credible path to the P2-T5 envelope of `≤14KB` final proof bytes and `≤5M` verifier gas while staying materially below the repo's current recursive memory baseline of `~7.8 GiB` at fold-depth `10`. In practice, that means the `n=1024`, `fold-depth=10` LatticeFold+ row is the decisive benchmark cell, with the `n=512` and `fold-depth=5` cells serving as trend checks rather than independent ship criteria.

The pivot triggers follow the already-frozen kill criteria in `.sisyphus/design/p2/stack-decision.md`. Pivot from LatticeFold+ to MicroNova if there is still no credible path to the `≤14KB` / `≤5M gas` envelope after one implementation iteration, or if the fold-depth-10 memory trend approaches or exceeds the current recursive `~7.8 GiB` baseline instead of staying materially better. Pivot from either native option to Rust-in-zkVM only if implementation friction dominates and exact Rust-verifier wrapping becomes the last credible delivery path.
