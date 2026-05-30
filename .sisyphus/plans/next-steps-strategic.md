# Next Steps — Strategic Plan

**Status**: PLAN
**Date**: 2026-05-30
**Branch**: main

## Immediate (next 1-2 weeks)

### S1 — Fix CI (Red Pipeline)
**Current**: 9 failing jobs from earlier run (fmt, clippy, test, forge, markdown-lint, etc.)
**Fix**: The last run `26597659109` failed with compilation errors that were fixed on `feat/greco-e3-compute-provider`. Those fixes are now on main via merge. Re-run CI and fix any remaining failures.
**Verify**: GitHub Actions — all jobs green
**Effort**: ~1 hr (mostly waiting for CI)

### S2 — Benchmark n=64,128 with Nova backend
**Current**: n=64 run timed out. No hard numbers for Nova IVC scaling.
**Fix**: Run `just demo-e2e n=64 t=31 seed=1` and `just demo-e2e n=128 t=63 seed=1`. Compare against old Sonobe benchmarks in `.pre-symphony-logs/`. Publish comparison table.
**Verify**: Both runs complete. Per-node and distributed estimates included.
**Effort**: ~4 hrs (mostly wall-clock waiting)

### S3 — Un-gate test files behind `legacy-nova`
**Current**: 14 test files gated behind `#[cfg(feature = "legacy-nova")]`. Some test actual Nova functionality (`cyclo_fold_ring_constraints.rs`, `typed_step_circuit.rs`).
**Fix**: Re-audit each file. If it tests Nova-snark functionality, un-gate. If Sonobe-specific, delete.
**Verify**: `cargo test --workspace` passes
**Effort**: ~2 hrs

### S4 — Update ARCHITECTURE.md
**Current**: References "Sonobe Nova Nova", "Cyclo CCS", "DealerParityStepCircuit (Sonobe FCircuit)". Outdated since Sonobe→Nova migration.
**Fix**: Rewrite §2 (Folding/Pipeline), §3 (Compression), §4 (Step Circuits) to reflect nova-snark backend. Add Greco/Symphony sections.
**Verify**: All references accurate against current code
**Effort**: ~1 hr

## Medium-term (next 2-4 weeks)

### S5 — FheComputeStepCircuit: Mul + Relinearize
**Current**: `FheOp::Add` is in-circuit. `Mul` and `Relin` are native-only stubs declaring `"🚧 Not implemented"`.
**Fix**: Implement RNS modular multiplication in bellpepper. For each degree d in the polynomial: `ct_out[d] = Σ ct0[i] * ct1[j] * ω^{i·j} mod q_l` where i+j ≡ d or i+j ≡ d+N (negacyclic wrap). Requires →/N² constraints per limb. Defer Relinearize (requires key-switching matrix).
**Verify**: `just compute n=3` — Mul operations work
**Effort**: ~8 hrs

### S6 — On-chain RecursiveSNARK verification (P4)
**Current**: `IvcBinding` provides hash-based binding. The Noir circuit checks 6 fields are non-zero. It doesn't verify the actual Nova proof.
**Fix**: Port the RecursiveSNARK verifier to Noir. Or generate a Groth16/PLONK proof that wraps RecursiveSNARK success using nova-snark's native prove, then verify that in Noir via `std::verify_proof`. Option B is more practical: have nova-snark produce a slim proof of IVC verification, pass it as calldata.
**Verify**: `forge test --match-contract PvtFheVerifier` — adversarial test rejects tampered Nova state
**Effort**: ~12 hrs

### S7 — CRISP comparison
**Current**: Plan to compare Nova IVC vs Risc Zero zkVM was never executed.
**Fix**: Run both systems on identical workloads (3 self-adds, 5 self-adds, 10 self-adds). Measure: worker prove time, proof size, verifier time, on-chain gas cost. Publish comparison.
**Verify**: Both systems produce verifiable results, Nova < 1s/op, Risc Zero ~30-90s/op
**Effort**: ~4 hrs

### S8 — Enable Symphony T1/T2 by default
**Current**: `symphony-t1` and `symphony-t2` are feature-gated in `symphony-all`.
**Fix**: Run benchmarks at n=16,32,64,128 with and without Symphony features. If there's a measurable gain, enable by default. Remove feature gates.
**Verify**: Demo-e2e runs with ACCEPT, no regression in timing
**Effort**: ~2 hrs (mostly benchmarking)

## Far-out (1-3 months)

### S9 — Distributed network layer
**Fix**: Create `coordinator` and `node` binaries. Coordinator orchestrates DKG ceremony across n nodes via gRPC. Nodes run sigma proving and PVSS share generation locally. Verifier collects proofs and runs on-chain.
**Verify**: 3-node DKG + decryption over local network
**Effort**: ~40 hrs

### S10 — External audit preparation
**Fix**: Fuzzing harness for sigma, BFV, PVSS, Nova inputs. Formal verification of protocol invariants (session binding, commitment length, share uniformity). Complete adversarial test suite (every known attack vector with PoC tests).
**Verify**: All fuzz targets pass 1M+ iterations. All adversarial tests pass.
**Effort**: ~80 hrs

### S11 — zkVM comparison paper
**Fix**: Write paper comparing Nova IVC vs Risc Zero for FHE compute. Include formal analysis of soundness, concrete benchmarks, and on-chain integration.
**Verify**: Draft accepted by co-authors
**Effort**: ~40 hrs

## Execution Order

```
S1 (CI) → S3 (tests) → S4 (docs) → S2 (benchmarks)
                                    → S5 (Mul) → S8 (Symphony) → S6 (P4)
                                    → S7 (CRISP)
                                                                    → S9 → S10 → S11
```

S1/S3/S4 are independent quick wins. S2 and S5-S8 can run in parallel after S1.
