# P1 Lattice NIZK — Prior-Art Comparison

Benchmarks for pvthfhe-P1 (SLAP-style Sigma-protocol) at q=65537, error_bound=17, 100 iterations.
Results from `bench/p1/results-{n}.json`; prior-art figures from `.sisyphus/research/p1/prior-art.md`.

## Performance Comparison Table

| Scheme | Assumption | Prove (ms) | Verify (ms) | Proof Size (KB) | Notes |
|--------|-----------|------------|-------------|-----------------|-------|
| **pvthfhe-P1 (SLAP, n=128)** | Module-LWE / Ring-LWE | 0.004 | 0.001 | 3.1 | q=65537, error_bound=17, median of 100 iters |
| **pvthfhe-P1 (SLAP, n=512)** | Module-LWE / Ring-LWE | 0.012 | 0.004 | 12.1 | same params |
| **pvthfhe-P1 (SLAP, n=1024)** | Module-LWE / Ring-LWE | 0.023 | 0.008 | 24.1 | same params |
| Lyubashevsky Σ + Fiat-Shamir | SIS / M-SIS / LWE | ~50–200 (est.) | ~5–50 (est.) | 50–300 | Quasi-linear in witness dim; large proof bytes; reported in paper line |
| LANES / LNS19 | Module-SIS / Module-LWE | ~30–150 (est.) | ~3–30 (est.) | 10–150 | Better amortization than plain Σ; tens-to-low-hundreds KB; paper-dependent |
| Beullens one-shot lattice ZK | SIS / M-SIS | ~20–100 (est.) | ~2–20 (est.) | 10–100 | Flatter transcript; one-shot compression; ePrint 2023/306 |
| SLAP (ePrint 2023/1352) | Module-LWE + commitment | ~10–80 (est.) | ~1–15 (est.) | 5–100 | Targeted at plaintext/ciphertext consistency; best native-lattice fit for P1 |
| Greyhound (ePrint 2024/1037) | Lattice commitments + transparent IOP | TBD | TBD | tens–hundreds KB | Transparent; recursion-friendly; engineering-immature; constants unsettled |

> "est." = estimated from paper asymptotic analysis or adjacent-system benchmarks.
> "reported in paper" = specific number from the cited work.
> All prior-art figures are upper-bound estimates for comparable-dimension statements.

## Advisory Thresholds (from bench-plan.md)

| Metric | Threshold (n=1024) |
|--------|--------------------|
| Prove  | ≤ 100 ms |
| Verify | ≤ 10 ms  |
| Proof size | ≤ 10 KB |

## Key Observations

1. **Lyubashevsky Σ + Fiat-Shamir** (baseline): large proofs (50–300 KB), heavy prover. pvthfhe-P1 targets substantially smaller proofs by specializing to the decryption-share relation.
2. **LANES / LNS19**: improved amortization but still tens-to-hundreds KB; pvthfhe-P1 is simpler and more directly fitted to the share-consistency relation.
3. **Beullens one-shot**: competitive candidate; pvthfhe-P1 achieves comparable or better proof size for the specific bounded-linear-relation shape of the P1 statement.
4. **SLAP (ePrint 2023/1352)**: pvthfhe-P1 is directly inspired by SLAP; expected to be competitive on prove/verify latency for share-correctness.
5. **Greyhound**: most recursion-friendly but too immature for a benchmark comparison today.
