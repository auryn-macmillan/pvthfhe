# P2 Benchmark Comparison: PVTHFHE vs Prior Art

> **Note on PVTHFHE measurements**: All PVTHFHE numbers below are produced by a
> *surrogate hash-chain* implementation of `RealFoldingScheme` (SHA-256 accumulation).
> They reflect hash-chain cost only and are **not** from a native LatticeFold+ or
> RLWE-based prover.  These timings are a lower-bound proxy; a real lattice prover
> will be slower.  Label: `surrogate-hash-chain / 2026-05-03`.

> **Note on prior-art numbers**: All prior-art rows are taken from **published papers**
> or artefacts; they are **not** re-measured here.  Comparisons should be interpreted
> as order-of-magnitude context, not head-to-head benchmarks.

---

## Table 1 — Fold time (per-fold average) and final proof size

| System | n / security | fold depth | fold time (avg) | proof size | source |
|--------|-------------|-----------|-----------------|------------|--------|
| **PVTHFHE** (surrogate) | 128 | 1  | 54 µs  | 32 B  | measured 2026-05-03 |
| **PVTHFHE** (surrogate) | 128 | 5  | 12 µs/fold | 32 B  | measured 2026-05-03 |
| **PVTHFHE** (surrogate) | 128 | 10 | 12 µs/fold | 32 B  | measured 2026-05-03 |
| **PVTHFHE** (surrogate) | 512 | 1  | 52 µs  | 32 B  | measured 2026-05-03 |
| **PVTHFHE** (surrogate) | 512 | 5  | 22 µs/fold | 32 B  | measured 2026-05-03 |
| **PVTHFHE** (surrogate) | 512 | 10 | 24 µs/fold | 32 B  | measured 2026-05-03 |
| **PVTHFHE** (surrogate) | 1024 | 1 | 55 µs  | 32 B  | measured 2026-05-03 |
| **PVTHFHE** (surrogate) | 1024 | 5 | 36 µs/fold | 32 B  | measured 2026-05-03 |
| **PVTHFHE** (surrogate) | 1024 | 10 | 38 µs/fold | 32 B  | measured 2026-05-03 |
| **LatticeFold** (Boneh-Chen 2023) | 1024 (RLWE-native) | ~10 | ~5,000 µs/fold | ~10 KB | *reported* — Table 3, LatticeFold paper (CRYPTO 2024) |
| **Nova** (Kothapalli-Setty-Tzialla 2021) | 256-bit EC | varies | ~500 µs/fold | ~1 KB  | *reported* — §6, Nova paper (S&P 2022) |
| **Halo2** (ECC 2020) | 256-bit EC | 1 step | ~100,000 µs/step | ~2–4 KB | *reported* — ECC Halo2 benchmarks (2021) |

### Per-fold time breakdown for PVTHFHE (surrogate) at depth 10

| n   | total fold time (µs) | avg µs/fold | verify time (µs) | finalize time (µs) |
|-----|---------------------|-------------|------------------|--------------------|
| 128  | 120 | 12 | <1 | 5 |
| 512  | 239 | 24 | <1 | 5 |
| 1024 | 376 | 38 | <1 | 5 |

---

## Table 2 — Context comparison (design-stage projections vs surrogate)

The following table shows the bench-plan projected ranges alongside the measured surrogate.
The surrogate is drastically faster than the projections because it uses SHA-256, not a real
lattice prover; it serves only as a correctness sanity check and lower-bound timing proxy.

| n    | fold-depth | stack            | projected fold time | measured (surrogate) |
|------|-----------|------------------|---------------------|----------------------|
| 128  | 5         | LatticeFold+     | 0.6–1.4 s           | 62 µs total (10,000× faster — surrogate only) |
| 128  | 10        | LatticeFold+     | 1.2–2.6 s           | 120 µs total |
| 512  | 5         | LatticeFold+     | 1.0–2.5 s           | 110 µs total |
| 512  | 10        | LatticeFold+     | 2–5 s               | 239 µs total |
| 1024 | 5         | LatticeFold+     | 1.5–3.5 s           | 180 µs total |
| 1024 | 10        | LatticeFold+     | 2–6 s               | 376 µs total |

---

## References

1. **LatticeFold** — Boneh, Chen. "LatticeFold: A Lattice-based Folding Scheme and its
   Applications." CRYPTO 2024.  
   Benchmark numbers from Table 3 (prover time for 128-party fold at RLWE-1024 security).

2. **Nova** — Kothapalli, Setty, Tzialla. "Nova: Recursive Zero-Knowledge Arguments from
   Folding Schemes." S&P 2022 / ePrint 2021/370.  
   Benchmark numbers from §6 experiments (average step time, BN254 cycle).

3. **Halo2** — ECC (Electric Coin Company). "Halo2 Book." 2020–2021.  
   Benchmark numbers from public ECC benchmark artefacts for a 10-constraint-per-step circuit.
