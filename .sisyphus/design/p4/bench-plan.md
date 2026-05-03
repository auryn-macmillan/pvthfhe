# P4 Benchmark Plan

## Overview

This document specifies the benchmark suite for the Hermine-adapted PVSS keygen protocol in PVTHFHE. The suite measures end-to-end performance across three network sizes and provides the evidence required to validate the O(n) per-party work claim.

## Benchmark Sizes

| Size   | Participants (n) | Threshold (t = ⌊n/2⌋+1) |
|--------|-----------------|--------------------------|
| Small  | 128             | 65                       |
| Medium | 512             | 257                      |
| Large  | 1024            | 513                      |

## Metrics

| Metric                          | Unit    | Description                                                                 |
|---------------------------------|---------|-----------------------------------------------------------------------------|
| Dealer keygen time              | ms      | Wall-clock time for one dealer to generate their PVSS share set, commitments, and NIZKs |
| Participant verification time   | ms      | Wall-clock time for one participant to verify all dealer transcripts        |
| Proof generation time           | ms      | Wall-clock time for one dealer's lattice NIZK proof generation (subset of dealer keygen) |
| Proof size                      | bytes   | Serialized size of one dealer's NIZK proof blob                             |
| BFV key reconstruction time     | ms      | Wall-clock time for the coordinator to reconstruct the BFV public key from t valid shares |

## Target Thresholds

| Metric                        | n=128  | n=512   | n=1024  |
|-------------------------------|--------|---------|---------|
| Dealer keygen time            | ≤ 200 ms | ≤ 800 ms | ≤ 1600 ms |
| Participant verification time | ≤ 50 ms  | ≤ 200 ms | ≤ 400 ms  |
| Proof generation time         | ≤ 150 ms | ≤ 600 ms | ≤ 1200 ms |
| Proof size                    | ≤ 64 KB  | ≤ 64 KB  | ≤ 64 KB   |
| BFV key reconstruction time   | ≤ 100 ms | ≤ 400 ms | ≤ 800 ms  |

*Thresholds assume a single-core reference machine (AMD Zen 3, 3 GHz). Wall-clock times are p50 over 50 iterations with a 5-iteration warm-up.*

## Benchmark Infrastructure

- **Harness**: Criterion.rs within `crates/pvthfhe-bench`
- **Entry point**: `just bench-scaling` (see `justfile`)
- **Parameters**: passed as Criterion `BenchmarkId` with parameter = n value
- **Output**: JSON + HTML reports under `bench/results/`
- **CI gate**: `cargo bench -p pvthfhe-bench --features p4-keygen` is allowed to exceed thresholds on CI but must compile and emit valid JSON (perf gates are advisory until T4)

## Benchmark Groups

### `keygen/dealer`
Measures: share generation + commitment + NIZK proof for a single dealer.

```rust
group.bench_with_input(BenchmarkId::new("dealer_keygen", n), &n, |b, &n| {
    b.iter(|| dealer.generate_shares(n, threshold));
});
```

### `keygen/participant_verify`
Measures: one participant verifying all n dealer transcripts.

```rust
group.bench_with_input(BenchmarkId::new("participant_verify", n), &n, |b, &n| {
    b.iter(|| participant.verify_all_transcripts(&transcripts));
});
```

### `keygen/bfv_reconstruct`
Measures: BFV public key reconstruction from t shares.

```rust
group.bench_with_input(BenchmarkId::new("bfv_reconstruct", n), &n, |b, &n| {
    b.iter(|| reconstruct_bfv_key(&shares[..threshold]));
});
```

## Reproducibility

- Benchmarks run with `PVTHFHE_BENCH_SEED=42` for deterministic parameter generation.
- Hardware spec and OS version are written to `bench/results/metadata.json` at run time.
- Full reproduction steps will be pinned in `REPRODUCING.md` at T4.

## Kill Criteria

If at T4 any threshold is exceeded by more than 3× at n=1024, the benchmark plan triggers a stack re-evaluation against the fallback candidates listed in `.sisyphus/design/p4/stack-decision.md`.
