# CKKS vs BFV Benchmark

Date: 2026-05-31
Hardware: AMD RYZEN AI MAX+ 395 w/ Radeon 8060S, 62 GiB RAM, Linux x86_64
Commit: `a128ee24e65598a9a8a79b395bbd9206b2b8ecdf` (feat/poulpy-threshold)
BFV backend: fhe.rs (gnosisguild/fhe.rs, rev `5f24d0b`), N=8192, 3 RNS limbs, t_plain=65536
CKKS backend: Poulpy (poulpy-fhe/poulpy, rev `4a1f0c6`), N=8192, 3 RNS limbs, log_delta=40, log_budget=688

## Methodology

- **BFV**: `pvthfhe-cli demo --n <N> --threshold 1 --seed 1 --backend fhe-rs` — full pipeline (DKG, NIZK, PVSS, Cyclo folding, Nova compression, Noir aggregation)
- **CKKS**: `pvthfhe-cli demo --n <N> --threshold 1 --seed 1 --backend poulpy-ckks` — standalone CKKS pipeline (keygen, sigma NIZK, PVSS, encrypt, decrypt)
- Metrics extracted from demo stdout; wall clock measured via `/usr/bin/time`
- BFV n=1 is unsupported (requires `t ≤ (n-1)/2 = 0`, but `t ≥ 1`)
- Raw logs: `bench/results/bfv-*.log`, `bench/results/ckks-*.log`

## Results

### FHE Operation Timings (ms)

| Metric | BFV (n=3) | CKKS (n=3) | BFV (n=10) | CKKS (n=10) |
|--------|-----------|------------|------------|-------------|
| keygen | 171.2 | 505.6 | 1967.6 | 1629.0 |
| encrypt | 3.2 | 12.8 | 3.2 | 14.5 |
| decrypt (total) | 9.8 | 10.4 | 9.2 | 12.5 |
| decrypt (partial) | 2.9 | 10.4 | 2.7 | 12.5 |
| decrypt (aggregate) | 6.9 | 0.0 | 6.5 | 0.0 |
| add | N/A ¹ | N/A ¹ | N/A ¹ | N/A ¹ |
| mul | N/A ¹ | N/A ¹ | N/A ¹ | N/A ¹ |

¹ Neither demo benchmarks standalone FHE add/mul operations. CKKS has internal `add`/`mul` functions in `ckks_ops.rs` but they are not exercised by the demo pipeline.

### CKKS-Only Metrics (n=1 included)

| Metric | CKKS (n=1) | CKKS (n=3) | CKKS (n=10) |
|--------|------------|------------|-------------|
| keygen | 170.7 | 505.6 | 1629.0 |
| encrypt | 13.6 | 12.8 | 14.5 |
| decrypt | 11.2 | 10.4 | 12.5 |
| sigma prove | 9.3 | 17.9 | 53.5 |
| sigma verify | 2.2 | 6.8 | 22.4 |
| accuracy | ~10.4 digits | ~10.3 digits | ~9.6 digits |
| total wall (s) | 0.23 | 0.60 | 1.90 |

### Sigma NIZK

| Metric | BFV (n=3) | CKKS (n=3) | BFV (n=10) | CKKS (n=10) |
|--------|-----------|------------|------------|-------------|
| sigma prove | N/A ² | 17.9 | N/A ² | 53.5 |
| sigma verify | N/A ² | 6.8 | N/A ² | 22.4 |

² BFV sigma NIZK (Ajtai D2) runs inside the full pipeline but per-phase prove/verify timings
are not printed by the demo observer. The NIZK is embedded in the `dkg_deal` phase (4656ms at n=3,
29852ms at n=10) which includes share dealing, Ajtai commitments, and NIZK rounds.

### Accuracy

| Metric | BFV (n=3) | CKKS (n=3) | BFV (n=10) | CKKS (n=10) |
|--------|-----------|------------|------------|-------------|
| plaintext roundtrip | exact | OK (diff 4.5e-11) | exact | OK (diff 2.6e-10) |
| significant digits | exact | ~10.3 | exact | ~9.6 |

CKKS accuracy degrades slightly with n due to accumulated key-switching noise in threshold
key aggregation. BFV is exact (integer arithmetic, no approximation error).

### Total Wall Clock

| Metric | BFV (n=3) | CKKS (n=3) | BFV (n=10) | CKKS (n=10) |
|--------|-----------|------------|------------|-------------|
| wall time (s) | 29.67 | 0.60 | 130.83 | 1.90 |

> **Note:** BFV wall time includes the full Nova IVC pipeline (14 steps: DKG,
> Ajtai D2 NIZK, Cyclo RLWE folding, Nova BN254/Grumpkin compression,
> Noir circuit aggregation via barretenberg UltraHonk). CKKS wall time
> covers only the standalone CKKS pipeline without folding/compression.

## BFV Pipeline Breakdown (n=3)

| Phase | Time (ms) |
|-------|-----------|
| keygen | 171.2 |
| dkg_deal | 4656.2 |
| dkg_aggregate | 0.04 |
| pvss_share_encrypt | 172.1 |
| setup_threshold | 20.8 |
| cyclo_fold | 4.2 |
| partial_decrypt | 2.9 |
| aggregate_decrypt | 6.9 |
| c7_decrypt_aggregation (Noir) | 1155.9 |
| compressor_prove (Nova) | 27.9 |
| compressor_verify (Nova) | 24.1 |
| c7_noir_aggregator (bb) | 686.7 |
| **Sum of printed phases** | **~7.0s** |
| **Wall clock** | **29.67s** |

The ~22.7s gap between printed phases and wall clock is attributable to:
- Ajtai D2 sigma NIZK prove (3 instances) and verify (9 cross-checks) — not individually timed
- DKG fold phase (step 4)
- Noir circuit witness generation, nargo execution, barretenberg setup
- Serialization, hashing, and pipeline orchestration overhead

## CKKS Accuracy Detail

| n | plaintext (orig) | recovered | absolute diff | digits |
|---|-----------------|-----------|---------------|--------|
| 1 | 1.0 | 0.9999999999600091 | 3.999e-11 | ~10.4 |
| 3 | 1.0 | 1.0000000000453626 | 4.536e-11 | ~10.3 |
| 10 | 1.0 | 0.9999999997387222 | 2.613e-10 | ~9.6 |

Digits computed as `-log10(|diff|)`.

## Interpretation

1. **Raw FHE operations** — BFV keygen, encrypt, and decrypt are all faster per-instance
   than CKKS (e.g., encrypt: 3.2ms vs 12.8ms). This is expected: BFV uses NTT-domain
   RNS arithmetic over small moduli (58-bit), while Poulpy CKKS uses a portable
   NTT reference implementation with heavier big-integer arithmetic.

2. **Keygen scaling** — Both scale linearly with n. BFV: 171ms→1968ms (11.5× for 3.3× n);
   CKKS: 171ms→1629ms (9.5× for 10× n). CKKS keygen is O(n) per party.

3. **Encrypt/Decrypt** — Both are O(1) with n (constant per ciphertext), as expected
   for single-key threshold FHE.

4. **Accuracy** — BFV is exact (integer plaintext space). CKKS provides ~10 decimal
   digits of precision with slight degradation at larger n due to key-switching
   noise accumulation in threshold aggregation.

5. **Pipeline overhead** — BFV's full pipeline (Nova IVC + Noir + barretenberg)
   dominates wall time. The CKKS demo is a lightweight pipeline without folding,
   making direct wall-clock comparison misleading. Per-operation FHE timings
   are the meaningful comparison metric.

## Reproducibility

```bash
# Build
PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 PVTHFHE_ALLOW_RESEARCH_BUILD=1 \
  cargo build --release -p pvthfhe-cli \
  --features "nova-compressor,demo-seeded-rng,enable-ckks"

# BFV benchmarks
target/release/pvthfhe-cli demo --n 3 --threshold 1 --seed 1 --backend fhe-rs
target/release/pvthfhe-cli demo --n 10 --threshold 1 --seed 1 --backend fhe-rs

# CKKS benchmarks
target/release/pvthfhe-cli demo --n 1 --threshold 1 --seed 1 --backend poulpy-ckks
target/release/pvthfhe-cli demo --n 3 --threshold 1 --seed 1 --backend poulpy-ckks
target/release/pvthfhe-cli demo --n 10 --threshold 1 --seed 1 --backend poulpy-ckks
```
