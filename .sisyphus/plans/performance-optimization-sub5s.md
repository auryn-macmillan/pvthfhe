# Plan: E2E Demo Performance Optimization — Sub-5s Target

**Plan**: `performance-optimization-sub5s`
**Status**: DRAFT
**Created**: 2026-05-15
**Target**: Sub-5 second E2E decryption at t=114 by optimizing aggregate_decrypt and C7 IVC folding.

---

## Current Performance (n=230, t=114)

| Step | Current | Target | Reduction |
|------|---------|--------|-----------|
| `aggregate_decrypt` | 7.2s | 0.5s | 14× |
| `c7_decrypt_aggregation` | 18.3s | 4.0s | 4.5× |
| **Total decryption** | **25.5s** | **4.5s** |

Non-decryption steps (keygen, NIZK, PVSS, compressor) excluded — they're either parallelized across nodes or already optimized.

---

## Batch A: C7 IVC Optimization (18.3s → 4.0s)

### A.1 — Batch C7 steps (per-participant → per-group)

Instead of one Nova step per participant (t=114 steps), batch k participants per step at 1/k the step count.

At k=8: 114 → 15 steps. Each step folds 8 Lagrange contributions: `acc += λ₁·d₁(r) + ... + λ₈·d₈(r)`. The state equation becomes 8 multiply-adds instead of 1 — linear increase per step, 8× fewer steps, net ~2-3× speedup.

| Task | Files | Effort |
|------|-------|--------|
| A.1a | Modify `run_c7_verification` to group share_evals into batches of k=8 | `full_pipeline.rs:1174-1192` | 1 day |
| A.1b | Update `C7DecryptAggregationCircuit::generate_step_constraints` to accept batched inputs — state transition: `acc_eval += Σ λ_i·d_i(r)` for batch | `c7_circuit.rs:53-69` | 1 day |
| A.1c | RED test: batch-of-8 produces identical accumulator to sequential | Tests | 0.5 day |

### A.2 — Precompute share evaluations

Share polynomial evaluation `d_i(r) = Σ coeff[j] · r^j` is computed sequentially for each of t=114 shares — 114 × 8192 Horner iterations = 933K Fr multiplications. These are performed inside `run_c7_verification` before Nova folding begins.

| Task | Files | Effort |
|------|-------|--------|
| A.2a | Precompute powers of r once: `r_pow = [r^0, r^1, ..., r^8191]` | `poly_eval.rs` | 0.5 day |
| A.2b | Use precomputed powers for O(N) dot product instead of O(N) Horner | `full_pipeline.rs:1174` | 0.5 day |
| A.2c | Move evaluation into rayon parallel iterator (already wired in L3) | Already done | — |

### A.3 — Profile Nova hot path

Nova's `prove_step` cycle iterates IVC step by step over the hashed state. Each step performs Fiat-Shamir challenge, R1CS witness generation, and NIFS update. 

| Task | Files | Effort |
|------|-------|--------|
| A.3a | Add micro-benchmark: `cargo bench --bench nova_prove_step` | `benches/nova_bench.rs` | 1 day |
| A.3b | Profile hot spots with `perf` or `cargo flamegraph` | Manual | 0.5 day |
| A.3c | Address any single-function bottleneck (e.g., reduce field inversion count, cache Poseidon config) | `sonobe/mod.rs` | 1 day |

### A.4 — MicroNova tree folding (O(log n) steps)

Replace flat sequential folding with tree-structured MicroNova folding. At t=114: 114 flat steps → 7 tree levels × O(log n). Requires L2 (real MicroNova circuits) to be complete first.

| Task | Files | Effort |
|------|-------|--------|
| A.4a | Wire `LatticeFoldTreeCircuitFamily` as C7 compressor (post-L2) | `full_pipeline.rs` | 1 day |
| A.4b | Bench: tree folding at t=128 produces 7-level tree | Manual | 0.5 day |

## Batch B: aggregate_decrypt Optimization (7.2s → 0.5s)

### B.1 — Profile aggregate_decrypt

The function calls `decrypt_from_shares` (NTT-based BFV plaintext extraction) and `compute_lagrange_coeffs_integer`. Profile to find the exact hotspot.

| Task | Files | Effort |
|------|-------|--------|
| B.1a | Add timing instrumentation to `aggregate_decrypt` — log per-substep | `fhers.rs:1390-1430` | 0.5 day |
| B.1b | Identify dominant term: NTT vs Lagrange coeff computation vs CRT decoding | Manual | 0.5 day |

### B.2 — Fast NTT via fhe.rs backend

The `decrypt_from_shares` call uses `gnosisguild/fhe.rs` NTT implementation which is already optimized (iterative Cooley-Tukey, power-of-two length). No further optimization possible on our side without modifying the upstream dependency.

| Option | Impact | Complexity |
|--------|--------|------------|
| Profile and confirm NTT is bottleneck | — | Done in B.1 |
| If not NTT: optimize Lagrange/CRT paths | Varies | After B.1 |

### B.3 — Reduce effective t for decrypt

`aggregate_decrypt_with_poly` processes all submitted shares. At t=114, this is 114 parties × NTT depth ≈ 6.7M operations. For a smaller threshold (t=60, still majority-honest at n=230), this drops to ~3.5M operations.

| Task | Files | Effort |
|------|-------|--------|
| B.3a | Document performance vs security tradeoff at different t | `ARCHITECTURE.md` | 0.5 day |
| B.3b | Offer `--threshold-override` for demo runs wanting speed | `main.rs` | 0.5 day |

---

## Batch C: GPU Acceleration (FUTURE — not in scope)

GPU NTT acceleration requires integrating a GPU-accelerated NTT library. Candidates:

- **Ingonyama icicle**: CUDA-accelerated NTT for BN254/BLS12-381. Mature, used in production ZK prover pipelines.
- **SP1 GPU backend**: Succinct Labs' SP1 uses GPU-accelerated field ops for recursive proving.

Integration would require:
1. Adding icicle Rust bindings (`icicle-cuda-runtime`, `icicle-hash`, `icicle-core`)
2. Porting `decrypt_from_shares` to use icicle NTT
3. ~2-3 weeks for integration + testing

Not planned for this research prototype. Documented as future production path.

---

## Acceptance Criteria

- [ ] C7 at t=114: ≤ 4.0s (currently 18.3s)
- [ ] aggregate_decrypt at t=114: ≤ 2.0s (currently 7.2s)
- [ ] Total decryption (aggregate + C7): ≤ 6.0s
- [ ] With t=60: sub-5s
- [ ] Demo ACCEPT — both tracks
- [ ] All C7 Nova tests pass
- [ ] All aggregator tests pass

## Estimated Effort

Batch A: ~1 week (A.1-A.3). Batch B: ~0.5 week (B.1-B.2). Total: ~1.5 weeks.

## Execution Order

A.2 (precompute) → A.1 (batch steps) → A.3 (profile) → A.4 (tree) → B.1 (profile decrypt) → B.2 (optimize)

A.2 and B.1 can run in parallel.
