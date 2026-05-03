# P1 Benchmark Plan

## Benchmark Matrix

The P1 benchmark sweep freezes the matrix required for the Design Gate: network size `n ∈ {128, 256, 512, 1024}` crossed with the P1 statement parameter tuple `(q bits, N, B_e)` and the prover stack choice (**SLAP** primary, **Greyhound** fallback). The matrix is advisory for design validation and will be materialized as JSON benchmark outputs during Implementation Wave.

| n | q bits | N | B_e | prover stack | statement profile | expected output artifact |
| --- | ---: | ---: | ---: | --- | --- | --- |
| 128 | 109 | 2048 | 32 | SLAP primary | small decrypt-share witness with P4 SHA-256 binding | `.sisyphus/evidence/benchmarks/p1/slap-n128.json` |
| 128 | 109 | 2048 | 32 | Greyhound fallback | same statement encoding, fallback verifier object | `.sisyphus/evidence/benchmarks/p1/greyhound-n128.json` |
| 256 | 109 | 4096 | 32 | SLAP primary | medium witness / first recursion-pressure point | `.sisyphus/evidence/benchmarks/p1/slap-n256.json` |
| 256 | 109 | 4096 | 32 | Greyhound fallback | same public input layout under fallback stack | `.sisyphus/evidence/benchmarks/p1/greyhound-n256.json` |
| 512 | 218 | 4096 | 48 | SLAP primary | deployment-relevant medium-large instance | `.sisyphus/evidence/benchmarks/p1/slap-n512.json` |
| 512 | 218 | 4096 | 48 | Greyhound fallback | verifier-shape comparison point for P2 planning | `.sisyphus/evidence/benchmarks/p1/greyhound-n512.json` |
| 1024 | 218 | 8192 | 64 | SLAP primary | design-limit instance for DG/IG claims | `.sisyphus/evidence/benchmarks/p1/slap-n1024.json` |
| 1024 | 218 | 8192 | 64 | Greyhound fallback | pivot benchmark if SLAP misses verifier budget | `.sisyphus/evidence/benchmarks/p1/greyhound-n1024.json` |

Matrix rationale:

- `n=128/256` anchor the low-end and first scale-up regime against the checked-in `bench/results/scaling-n{128,256}.json` conventions.
- `n=512/1024` match the repo's existing scaling and recursive-proof baselines and the P1 stack memo's projection checkpoints.
- `q bits`, `N`, and `B_e` are frozen as benchmark-plan inputs so prover/verifier results cannot silently drift across incompatible RLWE parameter regimes.
- Both stacks must consume the identical `NizkStatement` public-input layout from `.sisyphus/design/p1/interface-spec.md`.

## Advisory Thresholds

Threshold format follows the existing `bench/` pattern: per-run JSON output plus human-readable advisory limits that flag stack-pivot conditions without pretending to be final theorem claims.

| Metric | n=128 advisory | n=256 advisory | n=512 advisory | n=1024 advisory | Source / rationale |
| --- | ---: | ---: | ---: | ---: | --- |
| Prover time (ms) | ≤ 400 | ≤ 900 | ≤ 2,000 | ≤ 4,000 | Matches the SLAP projection band in `stack-decision.md`; values above this trigger fallback review |
| Proof size (bytes) | ≤ 64,000 | ≤ 96,000 | ≤ 160,000 | ≤ 240,000 | Keeps P1 proofs in the same order-of-magnitude envelope promised to downstream P2 folding |
| Verifier time (ms) | ≤ 12 | ≤ 18 | ≤ 25 | ≤ 40 | Uses the stack memo's explicit `~40 ms` SLAP pivot trigger at `n=1024` |
| Peak memory (MiB) | ≤ 512 | ≤ 1024 | ≤ 2048 | ≤ 4096 | Bounded to stay materially below the repo's ~7.8 GiB recursive aggregator baseline in `bench/results/scaling-n1024.json` |

Advisory interpretation:

- **Primary acceptance band:** SLAP results at or below all thresholds proceed to Implementation Gate evidence without stack escalation.
- **Fallback comparison band:** Greyhound may exceed the prover-time threshold modestly if it materially improves verifier time or verifier-object shape for P2.
- **Design pivot band:** any `n=1024` run with verifier time `> 40 ms`, proof size `> 240,000 bytes`, or peak memory `> 4096 MiB` requires an explicit rollback review under the migration plan.
- **Delivery fallback band:** if both native stacks exceed thresholds by `> 2×` at `n=1024`, freeze a Rust-in-zkVM contingency benchmark before claiming P1 implementation readiness.

## Measurement Protocol

The benchmark procedure is fixed now so Implementation Wave evidence is comparable across stacks and reruns.

1. Run from repo root via `just p1-bench` once the harness lands; emit one JSON artifact per `(n, stack)` tuple.
2. Record machine metadata alongside each run, consistent with `bench/results/hardware-fingerprint.txt` and the existing `bench/results/*.json` schema style.
3. Measure at least these fields in every JSON record: `n`, `q_bits`, `ring_degree_n`, `error_bound_b_e`, `stack`, `prover_ms`, `proof_size_bytes`, `verifier_ms`, `peak_mem_mib`, `sample_count`, `warmup_count`.
4. Use fixed seeds and deterministic statement fixtures so SLAP vs Greyhound compares the same witness family and P4 commitment-binding inputs.
5. Report medians and means separately; advisory-threshold evaluation uses the median for prover/verifier time and the maximum observed proof size / peak memory.
6. Preserve raw JSON in `.sisyphus/evidence/benchmarks/p1/` and only derive human-readable summaries from those records.
7. If a run fails or times out, keep the failed JSON/log output and mark the tuple as blocked rather than dropping it from the matrix.
