# Plan: Round 8 — Remediation + Scaling Roadmap

**Plan**: `round8-remediation-plus-scaling`
**Status**: DRAFT
**Created**: 2026-05-15
**Audits**: MicroNova safety, pipeline/demo/timing, NIZK/ciphertext/DKG + scaling research

---

## Findings Summary (16 findings, 3 audits)

### Critical (1)

| ID | Finding |
|----|---------|
| **F1** | MicroNova `verify_tree` per-variant hash check is logging-only — no enforcement. NovaNova::verify has no per-step circuit identity check. |

### High (1)

| ID | Finding |
|----|---------|
| **F2** | C7 Merkle double verification gap — native and in-circuit ordering differ. Nova folding over unsatisfied constraints → silent acceptance possible. |

### Medium (7)

| ID | Finding |
|----|---------|
| **F3** | `NizkWitness` lacks Zeroize — secret key coefficients persist in freed memory |
| **F4** | `setup_threshold` completely silent between steps 4-5 — 10-60s gap with zero output |
| **F5** | C7 Merkle circuit never tested with real data |
| **F6** | `num_circuits()` returns 1 for depth=1 (should be 2) |
| **F7** | SmudgeSlotRegistry per-run only, dual implementations |
| **F8** | Track B AjtaiMatrix deferred — `_track` parameter dead code |
| **F9** | C7 per-step Horner evaluation sequential (no parallelism) |

### Low (7)

| ID | Finding |
|----|---------|
| F10-F16 | BFV sigma binding contract, dual timing tracking, Nova OsRng non-determinism, usize→u32 truncation, poly_eval not wired, compressor hash-compression semantic, RefCell thread safety |

---

## Batch A: Critical + High Fixes (F1-F2)

| ID | Task | Files | Effort |
|----|------|-------|--------|
| A.1 | Replace debug-logging with actual per-variant rejection in `verify_tree` — compute `family.circuit_hash(family.circuit_index(i))` and compare against expected hash | `micronova/compressor.rs:108-125` | 1 day |
| A.2 | Fix Merkle circuit ordering gap — implement position-aware hashing matching native `verify_merkle_proof` (leaf_index at correct position per level) | `c7_merkle_circuit.rs:129-162` | 2 days |
| A.3 | RED test: native Merkle tree proof → R1CS circuit passes for arbitrary leaf_index | `c7_merkle_circuit` tests | 1 day |
| A.4 | RED test: verify_tree rejects wrong circuit variant per step | `micronova_heterogeneous` tests | 0.5 day |

## Batch B: Medium Fixes (F3-F9)

| ID | Task | Files | Effort |
|----|------|-------|--------|
| B.1 | Add `Zeroize` derive to `NizkWitness` in both crates | `real_nizk.rs`, `nizk/lib.rs` | 0.5 day |
| B.2 | Add `setup_threshold` to DemoObserver phase_start and phase_end handlers | `main.rs:416-478` | 0.5 day |
| B.3 | Add `setup_threshold` timing record to BenchObserver phase_end | `pvthfhe_e2e.rs:279` | 0.5 day |
| B.4 | Write integration test: C7 Merkle with real decryption share data | `c7_merkle` integration test | 1 day |
| B.5 | Fix `num_circuits()` bug — change `2.min(depth.max(1))` to account for depth=1 trees | `latticefold_circuit_family.rs:66` | 0.5 day |
| B.6 | Consolidate SmudgeSlotRegistry — use keygen-spec version (Serde support) in pipeline or document dual-impl | `full_pipeline.rs:515` | 1 day |
| B.7 | Remove unused `_track` parameter from `compute_ajtai_commitment_for_track` or wire it | `full_pipeline.rs:852` | 0.5 day |
| B.8 | Add `rayon` parallel Horner evaluation for C7 share polynomials | `full_pipeline.rs:1174` | 1 day |

## Batch C: Low Fixes (F10-F16)

| ID | Task | Files | Effort |
|----|------|-------|--------|
| C.1 | Add internal protocol identifier hash to `bfv_sigma::derive_challenge` as defense-in-depth | `bfv_sigma.rs:384` | 0.5 day |
| C.2 | Replace `u32::try_from(dealer_index).unwrap_or(u32::MAX)` with proper error | `nizk_share.rs:1547` | 0.5 day |
| C.3 | Wire `poly_eval::eval_poly_bn254` into C7 pipeline (deduplicate inline Horner) | `full_pipeline.rs:1174` | 0.5 day |
| C.4 | Replace `OsRng` with `ChaCha20Rng::from_seed(seed)` for deterministic Nova benchmarks | `mod.rs:376,549,680` | 0.5 day |
| C.5 | Add SAEFTY comment documenting `RefCell` non-reentrant invariant | `heterogeneous.rs:100` | 0.5 day |
| C.6 | Consolidate dual timing tracking (report.timings vs observer.timings) | `full_pipeline.rs + pvthfhe_e2e.rs` | 1 day |

## Batch D: Scaling — Parallel NIZK Verify

**Goal**: Replace sequential `for` loop with `rayon` parallel iterator.

**Files**: `crates/pvthfhe-cli/src/full_pipeline.rs:~208-232`

**Design**: The per-pair NIZK verification loop is embarrassingly parallel — each (dealer, recipient) pair is independent. Using `rayon::par_iter()`:

```rust
use rayon::prelude::*;
let (nizk_verify_total_ms, nizk_verify_per_instance_ms) = nizk_pairs
    .par_iter()
    .map(|(dealer, recipient)| {
        let start = Instant::now();
        // verify proof for this pair
        elapsed_ms(start)
    })
    .collect();
```

**Impact**: O(n²)/cores. For 8-core machine: 52,670 verifications → ~6,600 per core. Expected speedup: 6-8×.

**Effort**: 1 day. Requires adding `rayon` to Cargo.toml.

**RED test**: Verify timing data for n=32 with 4+ cores shows speedup vs baseline.

## Batch E: Scaling — Pre-Computed DKG

**Goal**: Defer O(n²) Shamir share generation to a one-time setup phase, reusing across demo runs.

**Design**: The `compute_party_sk_sums` in `fhers.rs:331-460` generates Shamir shares for n×n pairs. This is deterministic given the seed. Cache the generated shares to disk:

```rust
let cache_path = format!("dkg-cache-n{n}-t{t}-seed{seed}.bin");
if let Ok(cached) = std::fs::read(&cache_path) {
    return deserialize_dkg_shares(&cached);
}
let shares = compute_party_sk_sums(n, t)?;
std::fs::write(&cache_path, serialize_dkg_shares(&shares))?;
```

**Impact**: First run unchanged. Subsequent runs skip O(n²) setup entirely — step 4→5 gap drops to zero.

**Effort**: 2 days. Serialization + checksum validation + cache invalidation on parameter change.

**RED test**: Verify cache hit produces identical results to cache miss for same params.

## Batch F: Scaling — Batch NIZK Verification (Research)

**Goal**: Replace pairwise NIZK verification with batched multiscalar verification. Research-grade implementation suitable for the prototype.

**Design**: For sigma protocol proofs with the same challenge derivation structure, batch verification works by:
1. Summing the responses weighted by random coefficients
2. Verifying the combined equation once

This reduces O(n²) verifications to O(n) prover work + O(1) verifier work.

```rust
pub fn batch_verify_sigma_proofs(
    proofs: &[(ShareNizkStatement, ShareNizkOpenedProof)],
) -> Result<(), BatchVerifyError> {
    // Generate random coefficients via Fiat-Shamir on proof set
    let coeffs: Vec<Fr> = derive_batch_coeffs(proofs);
    // Weighted sum of z_s, z_e, t, d for all proofs
    let combined = proofs.iter().zip(&coeffs).fold(
        CombinedProof::zero(), |acc, ((stmt, pf), &c)| acc.add(c, stmt, pf)
    );
    // Single sigma equation check on combined proof
    verify_combined_sigma(&combined)?;
    Ok(())
}
```

**Impact**: NIZK verify goes from O(n²) to O(n log n). For n=230: 52,670 verifications → 230 proofs combined into 1. For n=1000: ~1M verifications → 1000 combined into 1.

**Effort**: 1-2 weeks. This is a novel research contribution — batch verification of lattice sigma proofs with ternary challenges requires careful analysis of the extraction bound under random coefficient weighting.

**Blocks**: Requires Lemma 9 (accepted as assumption) and M-SIS reduction (M2 from P1-T2 joint extractor).

## Batch G: Scaling — MicroNova Tree Folding (Complete Plan)

**Goal**: Replace flat sequential Nova folding with tree-structured MicroNova folding via the existing `LatticeFoldTreeCircuitFamily` + `HeterogeneousStepCircuit`.

**Prerequisite**: F1 must be fixed first (per-variant verifier key check).

**Design**: The existing infrastructure (`LatticeFoldTreeCircuitFamily`, `HeterogeneousStepCircuit`, `MicroNovaCompressor`) already supports tree folding but is gated behind `PVTHFHE_COMPRESSOR=micronova` and has F1 soundness gap.

After F1 fix:
1. Enable MicroNova path by default for the compressor
2. The tree depth is `ceil(log2(n))` — for n=230, depth=8
3. Total Nova steps: 2^d - 1 = 255 → but each step is O(1) circuit work
4. The flat Nova approach uses n steps (230), tree uses 255 — comparable at small n
5. At large n, tree wins: n=1000: flat=1000 steps vs tree=1023 steps (similar), but tree uses heterogeneous circuits (per-level optimization)

**Actual benefit**: Not faster at current scale (n≈200). The benefit is asymptotic: the tree structure enables recursive proof composition (each internal node proves its two children), which is a building block for full recursive SNARK compression.

**Effort**: Already built. Only F1 fix + enabling by default needed.

## Acceptance Criteria

- [ ] A.1-A.4: MicroNova verifier per-variant check enforces rejection
- [ ] B.1-B.8: All 8 medium fixes applied
- [ ] C.1-C.6: All 6 low fixes applied  
- [ ] D.1: Parallel NIZK verify gives 4+× speedup on 8-core machine
- [ ] E.1: Cached DKG eliminates setup_threshold gap on second run
- [ ] All 16 findings resolved
- [ ] Demo ACCEPT — both tracks
- [ ] All existing tests pass

## Execution Order

Batch A (critical, 3 days) → Batch B+F1 checkpoint (verify works) → Batch F (research, 1-2 weeks) → Batch D+E (scaling, 3 days) → Batch C (polish) → Batch G (enable MicroNova default)

Batches B and C can run in parallel. Batch D and E are independent and can run any time.
