# pvthfhe-benchmark-loop-closure — Close the Loop for a Legitimate trBFV Comparison

> **Status**: CLOSED — 2026-05-07 — F2 user acceptance signed off
> **Predecessors**: `pvthfhe-real-fhe-demo.md` (CLOSED 19/19), `pvthfhe-real-p2p3.md` (Phase-3 components landed but not wired into demo/bench)
> **Companion** (long-haul): `pvthfhe-followon.md`
> **Spec freeze**: `.sisyphus/design/spec-real-p2p3.md` (joint freeze, 740 L) + new addendum on Sonobe substitution (Task S0)
> **Baseline source of truth**: <https://github.com/gnosisguild/enclave/tree/main/circuits/benchmarks/results_secure> — `report.md` and `integration_summary.json` (Apple M4 Pro, 14c/48GB, Nargo 1.0.0-beta.16, BB 3.0.0-nightly.20260102, H=N=3, T=1)
> **Time budget**: 8–12 weeks pragmatic, **conditional on the two feasibility spikes (N3a, P0a) coming back green**. If either spike fails, the schedule re-baselines per the fallback task graphs (§7 N3a outcome table, §8 P0a outcome table) before any downstream task in that phase starts.
> **Decisions (user-confirmed 2026-05-06)**: (1) Sonobe substitutes for MicroNova for now, behind a **bounded migration surface** (S0/S4) — not a "no-tech-debt" claim; (2) Path A — real lattice PVSS for share encryption, gated on the P0a feasibility spike; (3) full-dim Noir + real BB-generated UltraHonk verifier in scope, gated on the N3a feasibility spike.
> **Momus review (2026-05-06)**: REJECT addressed by adding Phase X (spec reconciliation), Task N0 (circuit-test harness), Task N3a (Sonobe-in-UltraHonk feasibility spike with explicit fallback graph), Task P0a (PVSS feasibility spike), tightening S0/S4, and per-row split/merge notes in §3.

---

## 0. Mission

Today the demo and `bench-scaling` paths skip the cost-relevant proofs (NIZK, Cyclo, MicroNova/Sonobe wrap, on-chain UltraHonk verifier) and use `MockBackend` + integer-Shamir + a `revert`-everything verifier. As a result, any wall-clock comparison against Interfold trBFV is meaningless — trBFV's headline 8056 s for n=3 is dominated by 12 ZK circuits (notably `ZkShareEncryption` at ~75% of DKG cost) that have **no analogue exercised** in our pipeline.

This plan closes the loop end-to-end:

1. **Wire** the already-real components (P1 Sigma+Ajtai NIZK, P2 Cyclo folding, FhersBackend) into `run_demo` and `bench-scaling` so their costs are measured.
2. **Substitute** Sonobe (PSE Nova/HyperNova) for the MicroNova SHA-256 scaffold behind a `ProofCompressor` trait whose surface is MicroNova-shaped. The substitution is governed by a **bounded migration surface** (S0): step-circuit shape, accumulator-state encoding, setup artifacts, and verifier-key semantics are frozen as MicroNova-compatible invariants in the spec addendum, so a future swap back is bounded — not zero-cost.
3. **Bring the Noir circuits and on-chain verifier to real**: full-dim `decrypt_share`, `aggregator_final`, and `sonobe_wrap`; BB-generated `UltraHonkVerifier.sol`; remove the `revert` killswitch from `PvtFheVerifier.sol`.
4. **Upgrade Hermine PVSS** from integer-Shamir+SHA-256 to a real lattice PVSS that encrypts each share under the recipient's public key and reuses the P1 Sigma+Ajtai NIZK at share-encryption time — the analogue of trBFV's dominant `ZkShareEncryption + ZkVerifyShareProofs + ZkDkgShareDecryption` proofs.
5. **Produce** `just bench-comparison`: a single command that runs PVTHFHE under the same H=N=3, T=1 configuration as the Interfold report and emits a side-by-side circuit-level table (ours vs. their published numbers).

P1 joint-extractor formalisation, QROM proofs, and PQ-secure on-chain verification remain out of scope (`pvthfhe-followon.md`).

---

## 1. Out of Scope

- P1 joint-extractor T2 formalisation (still tabled; conditional-soundness banner remains).
- Production audits, CVE-class review, formal security proofs of the Sonobe wiring.
- Re-running Interfold's benchmarks ourselves — we use their published `report.md`/`integration_summary.json` verbatim. **No comparison hardware match attempted**: we report our hardware and theirs side-by-side and let the reader normalise. (See §12 for honest-comparison policy.)
- MicroNova production deployment (deferred; Sonobe is the substitute; trait surface is MicroNova-shaped to keep the swap cheap — see Task S0).
- Switching FHE backends (locked to `gnosisguild/fhe.rs` per F1, AGENTS.md).

---

## 2. Non-negotiable Policies

- **TDD strict**: RED test committed and CI-visible before every implementation change.
- **ZERO** new `#[allow(...)]` attributes anywhere in this plan's diffs.
- Cargo: `cargo ... -p <crate>` from repo root. Never `--workspace` for tests.
- Foundry: `forge ... --root contracts` from repo root.
- Noir: `(cd circuits && nargo ...)` from repo root.
- **Forbidden**: `nargo prove`, `nargo verify`. Use canonical BB flow (AGENTS.md §"Canonical Noir + BB flow").
- **Stub protocol**: replace stubs in place; never delete-and-recreate.
- **No silent fallback**: every backend swap surfaces in a `backend_id` field and SECURITY.md banner within the same PR.
- **Stage 0 tripwires SURVIVE**: build.rs banner and `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` opt-in guard remain in place until P1 joint-extractor is formalised — independent of this plan.
- **Plan files are read-only for sub-agents**; only the orchestrator marks checkboxes.
- **Honest comparison**: any benchmark output that compares against trBFV must include a hardware-and-parameter disclosure block (see §12).

---

## 3. Vocabulary & Mapping (trBFV ↔ PVTHFHE)

| trBFV proof (Interfold) | PVTHFHE analogue | Mapping cardinality | Owner crate / file | Phase here |
|---|---|---|---|---|
| ZkPkBfv (PK-share well-formedness) | P1 Sigma+Ajtai NIZK at keygen | **1:N** — one trBFV proof maps to N parties' Sigma+Ajtai instances; report sum (and per-party mean) and label `aggregate-of-N` in §12 disclosure | `crates/pvthfhe-nizk` | W |
| ZkShareComputation | `fhers::keygen_share_with_session` | 1:1 | `crates/pvthfhe-fhe` | (already real & wired) |
| **ZkShareEncryption** (~75% of DKG) | Lattice PVSS share-encryption proof (Path A) | **1:N(N-1)** — trBFV's circuit covers all encrypted shares per dealer; ours runs once per (dealer, recipient) pair. Report sum and per-pair mean. | `crates/pvthfhe-pvss` (new) | P |
| ZkVerifyShareProofs | NIZK verify on encrypted shares | 1:N(N-1) (verifier-side counterpart of above) | `crates/pvthfhe-pvss` | P |
| ZkNodeDkgFold + ZkPkAggregation | Cyclo first-fold + agg fold | **2:2 split-merge** — trBFV splits node-fold from PK-aggregation; we fold both into Cyclo. Report Cyclo total alongside the trBFV sum and disclose the merge. | `crates/pvthfhe-cyclo`, `crates/pvthfhe-aggregator` | W |
| ZkDkgAggregation (final SNARK) | Sonobe wrap (substituting MicroNova) | 1:1, **but proof system differs** (UltraHonk-wrapped Nova vs trBFV's UltraHonk over BFV-encrypted state). Disclose proof-system asymmetry per row. | `crates/pvthfhe-compressor` (new), `circuits/sonobe_wrap` | S, N |
| ZkThresholdShareDecryption | Same Sigma+Ajtai NIZK, decrypt-time statement | 1:N (one per decrypting party) | `crates/pvthfhe-nizk` (reused) | W |
| ZkDkgShareDecryption | Lattice PVSS decrypt-side proof | 1:N (one per recipient) | `crates/pvthfhe-pvss` | P |
| ZkDecryptedSharesAggregation + ZkDecryptionAggregation | Cyclo + Sonobe at decrypt | **2:2 split-merge** (same caveat as DKG fold/agg row) | existing | W, S |
| on-chain UltraHonk verify | BB-generated `UltraHonkVerifier.sol` + `PvtFheVerifier.sol` pass-through | 1:1 | `contracts/` | N |

**Per-row disclosure obligations (enforced by E2 renderer)**: every row whose cardinality is not `1:1` MUST render with (a) the cardinality tag, (b) the aggregation rule (sum / mean / pair-mean), (c) the per-instance count actually executed, and (d) a one-line "why this is comparable" or "why this is asymmetric" note. Rows whose proof systems differ MUST flag the asymmetry in the rendered table even when cardinality is 1:1.

The "ProofCompressor" trait (S0) is intentionally shaped after MicroNova (BN254/Grumpkin half-cycle, HAC RoK boundary, public-input layout from `spec-real-p2p3.md` §3.7) so the Sonobe backend implements that surface. **The substitution is bounded, not free**: S0 freezes the migration surface (step-circuit shape, accumulator state encoding, setup artifacts, VK semantics) so a future MicroNova swap is scoped to enumerated touch points rather than a backend-only no-op.

---

## 4. Phase X — Cross-cutting Prerequisites (BLOCKS everything else)

Gate: `just prereq-gate`. **No task in W/S/N/P/E may start until X1 and X2 are green.**

### Task X1 — Reconcile spec-real-p2p3.md parameter inconsistency ✅ DONE

| Field | Value |
|---|---|
| **ID** | X1 |
| **Owner** | `.sisyphus/design/spec-real-p2p3.md` |
| **Depends on** | — |
| **Gate** | prereq-gate |

**Problem**: spec asserts `N=8192` at line 75 but mentions `RLWE_N=1024` at lines 200-204; sub-agents implementing against the spec will diverge.

**RED test** (`tests/integration/spec_consistency.rs`): grep `spec-real-p2p3.md` for both `N=8192` and `RLWE_N=1024`; assert that exactly one ring degree is named as the **production** parameter and any other appearance is explicitly tagged `(legacy|illustrative|deprecated)`. Initially fails.

**GREEN criteria**: spec carries a single canonical parameter table at the top; all other appearances reference it. Decision-record paragraph notes which value is canonical and why. `parameters.toml` matches. `cargo test --test spec_consistency` passes.

---

### Task X2 — Add cross-plan AGENTS-policy assertion test ✅ DONE

| Field | Value |
|---|---|
| **ID** | X2 |
| **Owner** | `tests/integration/policy_invariants.rs` (new) |
| **Depends on** | — |
| **Gate** | prereq-gate |

**RED test**: a single Rust integration test asserts: (i) build.rs banner present and emits Stage 0 warning; (ii) `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK` env-var guard present in `pvthfhe-bench` and `pvthfhe-cli`; (iii) zero `#[allow(...)]` attributes added under any path touched by this plan since the predecessor plan's CLOSED commit; (iv) `nargo prove`/`nargo verify` strings absent from all scripts under `bench/scripts/` and `Justfile`. Initially fails (test does not exist).

**GREEN criteria**: test exists and is wired into `prereq-gate`, `wire-gate`, `compressor-gate`, `noir-onchain-gate`, `pvss-gate`, and `bench-comparison-gate`. Any later task that violates these invariants fails its own gate, not just this one.

---

### Task X3 — `just prereq-gate` ✅ DONE

| Field | Value |
|---|---|
| **ID** | X3 |
| **Owner** | `Justfile` |
| **Depends on** | X1, X2 |
| **Gate** | itself |

**GREEN criteria**: recipe runs `cargo test --test spec_consistency` and `cargo test --test policy_invariants`. Required green before any phase-specific gate.

---

## 5. Phase W — Wire Real Components into Demo & Bench

Gate: `just wire-gate` (new — see Task W6).

### Task W1 — Wire P1 Sigma+Ajtai NIZK into `run_demo` keygen path ✅ DONE

| Field | Value |
|---|---|
| **ID** | W1 |
| **Owner** | `crates/pvthfhe-cli/src/main.rs` (run_demo, lines 151–295), `crates/pvthfhe-fhe/src/real_nizk.rs` |
| **Depends on** | — |
| **Gate** | wire-gate |

**RED test** (`crates/pvthfhe-cli/tests/run_demo_invokes_nizk.rs`): run `run_demo --seed 1 --n 3 --t 2`; assert via tracing-subscriber capture that `pvthfhe_nizk::prove` is called exactly `n` times and `pvthfhe_nizk::verify` is called exactly `n*(n-1)` times. Initially fails because run_demo never invokes the NIZK adapter.

**GREEN criteria**: keygen branch in `run_demo` constructs a `RealNizkAdapter`, calls `prove` per dealer, and verifies all peer shares; failure to verify aborts the demo with non-zero exit. `backend_id == "cyclo-ajtai-d2-conditional"` printed to stdout. `cargo test -p pvthfhe-cli run_demo_invokes_nizk` passes.

---

### Task W2 — Make Cyclo the default folding backend in `run_demo` and `bench-scaling` ✅ DONE

| Field | Value |
|---|---|
| **ID** | W2 |
| **Owner** | `crates/pvthfhe-aggregator/src/folding/mod.rs`, `Cargo.toml` (default features) |
| **Depends on** | — |
| **Gate** | wire-gate |

**RED test** (`crates/pvthfhe-aggregator/tests/default_folding_is_cyclo.rs`): `Aggregator::default()` reports `folding_backend_id == "cyclo-rlwe-t10-lemma9-heuristic"`. Initially fails because default uses hash-chain surrogate.

**GREEN criteria**: `real-folding` becomes a default feature; hash-chain path remains gated behind explicit `--no-default-features --features hash-chain-surrogate` and fails closed with `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` if invoked. `just demo-e2e --seed 1` exercises real folding. `cargo test -p pvthfhe-aggregator default_folding_is_cyclo` passes.

---

### Task W3 — Replace `MockBackend` with `FhersBackend` in `bench_scaling.rs` ✅ DONE

| Field | Value |
|---|---|
| **ID** | W3 |
| **Owner** | `crates/pvthfhe-bench/src/bin/bench_scaling.rs`, `crates/pvthfhe-bench/src/backends/fhe_rs.rs` |
| **Depends on** | W1, W2 |
| **Gate** | wire-gate |

**RED test** (`crates/pvthfhe-bench/tests/bench_scaling_uses_real_backend.rs`): spawn the bench bin with `--n 4 --dry-run`; capture stderr; assert `backend_id` line contains `fhers-bfv` and not `mock-xor`. Fails initially.

**GREEN criteria**: bench binary parameterised on `--backend {fhers,mock}` with `fhers` default; `mock` requires the env-var tripwire. JSON output includes `backend_id`, `nizk_backend_id`, `folding_backend_id`, `compressor_backend_id`, `n`, `t`, `seed`, hardware fingerprint (CPU model, core count, RAM).

---

### Task W4 — End-to-end binary `pvthfhe-e2e` exercising every phase ✅ DONE

| Field | Value |
|---|---|
| **ID** | W4 |
| **Owner** | `crates/pvthfhe-cli/src/bin/pvthfhe_e2e.rs` (new) |
| **Depends on** | W1, W2, W3 |
| **Gate** | wire-gate |

**RED test** (`crates/pvthfhe-cli/tests/e2e_invokes_all_phases.rs`): run `pvthfhe-e2e --n 3 --t 2 --seed 1` and assert tracing spans for each of: `keygen`, `nizk_prove`, `nizk_verify`, `pvss_share_encrypt` (skipped behind feature flag until Phase P lands), `cyclo_fold`, `compressor_prove`, `compressor_verify`, `noir_decrypt_share`, `noir_aggregator_final`, `noir_sonobe_wrap`, `onchain_verify`. Initially fails (binary doesn't exist).

**GREEN criteria**: `pvthfhe-e2e` runs the full pipeline. **Cargo feature selection** at build time: `--features surrogate-compressor` builds the SHA-256 scaffold (today's default; emits a stderr warning at startup) and `--features sonobe-compressor` builds against real Sonobe (becomes default after S3). Features are mutually exclusive (compile error if both selected). Exit 0 only if all phases succeed.

---

### Task W5 — `bench-comparison` JSON shape matches Interfold's `integration_summary.json` ✅ DONE

| Field | Value |
|---|---|
| **ID** | W5 |
| **Owner** | `crates/pvthfhe-bench/src/bin/bench_comparison.rs` (new), `Justfile` (`bench-comparison` recipe) |
| **Depends on** | W4 |
| **Gate** | wire-gate |

**RED test** (`crates/pvthfhe-bench/tests/comparison_json_shape.rs`): invoke `just bench-comparison-dryrun 3 1 1` (recipe accepts positional args `n t seed`; defined in W5 GREEN); parse the emitted JSON at `bench/results/comparison-dryrun.json`; assert keys `circuit_timings`, `phase_totals`, `hardware`, `backend_ids`, `commit_sha`, `comparison_target` exist and `circuit_timings` lists the 12 circuit names from Interfold's report (those without an analogue report `null` and a `gap_reason`).

**GREEN criteria**: `Justfile` defines `bench-comparison n t seed` and `bench-comparison-dryrun n t seed` recipes that invoke `cargo run -p pvthfhe-bench --bin bench_comparison -- --n {{n}} --t {{t}} --seed {{seed}} [--dry-run]`. Bench binary emits a JSON file under `bench/results/` with the schema above. Each circuit row carries `{name, prove_ms, verify_ms, witness_ms, vk_kb, proof_kb, status, cardinality_tag, instances_run, comparability_note}` where `status ∈ {"real", "real-fallback", "surrogate", "skipped", "n/a"}` (the `"real-fallback"` value is reserved for the on-chain row when N3a verdict == NoGo activates the N3'/N4'/N5' branch; see §7 N3a outcome table and §12). After Phase F there are no `"surrogate"` rows.

---

### Task W6 — `just wire-gate` ✅ DONE

| Field | Value |
|---|---|
| **ID** | W6 |
| **Owner** | `Justfile` |
| **Depends on** | W1–W5 |
| **Gate** | itself |

**RED test**: invoke `just wire-gate` on a fresh checkout; recipe missing.

**GREEN criteria**: recipe runs `cargo test -p pvthfhe-cli`, `cargo test -p pvthfhe-aggregator`, `cargo test -p pvthfhe-bench`, executes `pvthfhe-e2e --n 3 --t 2 --seed 1` end-to-end (with `surrogate-compressor` until S3), and validates the JSON schema from W5. Exit 0 required.

---

## 6. Phase S — Sonobe Substitute Behind MicroNova-Shaped `ProofCompressor`

Gate: `just compressor-gate`.

### Task S0 — Spec addendum: ProofCompressor trait + Sonobe→MicroNova migration contract ✅ DONE

| Field | Value |
|---|---|
| **ID** | S0 |
| **Owner** | `.sisyphus/design/spec-real-p2p3.md` (addendum §4.2), `.sisyphus/design/sonobe-migration.md` (new) |
| **Depends on** | — |
| **Gate** | compressor-gate |

**RED test** (`crates/pvthfhe-compressor/tests/spec_addendum_present.rs`): assert that `spec-real-p2p3.md` contains the strings `### 4.2 Sonobe substitute`, `ProofCompressor`, `migration: sonobe → micronova`, `bounded migration surface`, and section anchors for each of the five frozen invariants below. Initially fails.

**GREEN criteria**: addendum freezes the **bounded migration surface** — namely the five invariants any compressor backend (Sonobe today, MicroNova later) MUST honour:

1. **Trait surface**: `prove(acc, public_inputs) -> CompressedProof`, `verify(vk, proof, public_inputs) -> bool`, `backend_id`, `vk_bytes()`, `compressed_proof_bytes()`. No backend-specific types in the signature.
2. **Step-circuit shape**: input/output state width, public-input layout, and the per-step relation are expressed in a backend-agnostic R1CS `StepCircuit` description that is checked into `crates/pvthfhe-compressor/src/step_circuit.rs` and is identical for both backends.
3. **Accumulator-state encoding**: byte layout, field choice (BN254 scalar), and Poseidon parameterisation (Construction 1 bridge per `micronova-digest.md`) are MicroNova-compatible. Sonobe-specific accumulator wrappers convert at the trait boundary.
4. **Setup artifacts**: SRS / structured reference string acquisition is delegated to a `CompressorSetup` trait whose Sonobe impl uses Sonobe's setup but exposes only `(prover_key_bytes, verifier_key_bytes, srs_id)` — same surface MicroNova will satisfy.
5. **Verifier-key semantics**: `vk_bytes` carries an `srs_id`, `step_circuit_hash`, `backend_id`, and `version`. A future MicroNova backend producing the same `step_circuit_hash` over the same `srs_id` MUST be byte-compatible at the `public_inputs` boundary (proofs themselves differ).

**Bounded migration target** (replaces "no tech debt" claim): `sonobe-migration.md` enumerates every file a future MicroNova swap would touch and asserts the count is ≤ 8 (target 3-5). The doc lists each touch point with a one-line rationale. S4's invariant test enforces this bound.

---

### Task S1 — New crate `crates/pvthfhe-compressor` + `ProofCompressor` trait ✅ DONE

| Field | Value |
|---|---|
| **ID** | S1 |
| **Owner** | `crates/pvthfhe-compressor/src/lib.rs` |
| **Depends on** | S0 |
| **Gate** | compressor-gate |

**RED test** (`crates/pvthfhe-compressor/tests/trait_object.rs`): `ProofCompressor` object-safety compile test.

**GREEN criteria**: trait defined per S0; `cargo test -p pvthfhe-compressor` passes; trait is re-exported from `pvthfhe`.

---

### Task S2 — Sonobe Nova backend `pvthfhe_compressor::sonobe` ✅ DONE

| Field | Value |
|---|---|
| **ID** | S2 |
| **Owner** | `crates/pvthfhe-compressor/src/sonobe/mod.rs` |
| **Depends on** | S1 |
| **Gate** | compressor-gate |

**RED test** (`crates/pvthfhe-compressor/tests/sonobe_roundtrip.rs`): build a 4-step toy IVC over an R1CS instance representing one Cyclo fold step; `prove` then `verify`; expect roundtrip true. Initially fails (backend stub).

**GREEN criteria**: `SonobeCompressor` implements `ProofCompressor` using `folding-schemes` crate (PSE Sonobe) Nova variant over BN254/Grumpkin; `backend_id == "sonobe-nova-bn254-grumpkin"`; vk and proof are byte-deterministic for a fixed seed; cheating-witness test rejects.

---

### Task S3 — Wire `SonobeCompressor` into `pvthfhe-e2e` and `bench-comparison` ✅ DONE

| Field | Value |
|---|---|
| **ID** | S3 |
| **Owner** | `crates/pvthfhe-cli/src/bin/pvthfhe_e2e.rs`, `crates/pvthfhe-bench/src/bin/bench_comparison.rs` |
| **Depends on** | S2, W4, W5 |
| **Gate** | compressor-gate |

**RED test** (`crates/pvthfhe-cli/tests/e2e_uses_sonobe.rs`): build `pvthfhe-e2e` with `--features sonobe-compressor`; run with `--n 3 --t 2 --seed 1`; assert `compressor_backend_id == "sonobe-nova-bn254-grumpkin"`. Fails before this task lands (default still surrogate; sonobe feature missing).

**GREEN criteria**: `sonobe-compressor` becomes the default Cargo feature (in `Cargo.toml`'s `[features] default = ["sonobe-compressor"]`) for `pvthfhe-cli` and `pvthfhe-bench`. `surrogate-compressor` requires explicit `--no-default-features --features surrogate-compressor` plus the `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` env-var tripwire to start. The SHA-256 path is removed from the default build graph (verified by `cargo tree`).

---

### Task S4 — `crates/pvthfhe-micronova` deprecation note + invariant test ✅ DONE

| Field | Value |
|---|---|
| **ID** | S4 |
| **Owner** | `crates/pvthfhe-micronova/README.md`, `crates/pvthfhe-micronova/tests/no_consumers.rs` |
| **Depends on** | S3 |
| **Gate** | compressor-gate |

**RED test** (`crates/pvthfhe-micronova/tests/no_consumers.rs`): walk `cargo metadata` dependents of `pvthfhe-micronova`; assert `dependents == []` (no crate in the default build graph depends on it). Independently, parse `sonobe-migration.md` and assert the enumerated touch-point list has length ≤ 8. Initially fails because `pvthfhe-cli`/`pvthfhe-bench` still reference it via the surrogate path.

**GREEN criteria**: README states "Held in tree as the future MicroNova backend target; not in the build path of `pvthfhe-e2e`." Both assertions pass. No deletion (per stub protocol).

---

### Task S5 — `just compressor-gate` ✅ DONE

| Field | Value |
|---|---|
| **ID** | S5 |
| **Owner** | `Justfile` |
| **Depends on** | S0–S4 |
| **Gate** | itself |

**GREEN criteria**: runs `cargo test -p pvthfhe-compressor`, the e2e integration test under `--features sonobe-compressor`, and `cargo test -p pvthfhe-micronova no_consumers`.

---

## 7. Phase N — Real Noir Circuits + BB-Generated UltraHonk Verifier

Gate: `just noir-onchain-gate` (replaces the existing `phase3-gate` once green).

### Task N0 — Circuit-test harness `crates/pvthfhe-circuit-tests` ✅ DONE

| Field | Value |
|---|---|
| **ID** | N0 |
| **Owner** | `crates/pvthfhe-circuit-tests/{Cargo.toml,src/lib.rs,src/bb.rs,src/nargo.rs}` (new), `Cargo.toml` (workspace member add) |
| **Depends on** | X3 |
| **Gate** | noir-onchain-gate |

**Rationale**: Momus correctly flagged that N1/N2/N3 RED tests as previously written referenced a `cargo test -p pvthfhe-circuit-tests` harness that did not exist. This task creates it before any circuit task runs.

**RED test** (`crates/pvthfhe-circuit-tests/tests/harness_smoke.rs`): invoke `pvthfhe_circuit_tests::nargo::execute(package="aggregator_final", prover_toml=...)` and `pvthfhe_circuit_tests::bb::write_vk_prove_verify(package="aggregator_final", scheme="ultra_honk")` against the existing reduced-dim `aggregator_final` circuit; expect both to succeed and return populated `(vk_path, proof_path, public_inputs_path)` triples. Initially fails (crate doesn't exist).

**GREEN criteria**:
- New crate `pvthfhe-circuit-tests` added as workspace member.
- `src/nargo.rs` exposes `execute(package: &str, prover_toml: &Path) -> Result<NargoArtifacts>` that shells `(cd circuits && nargo execute --package <pkg> --prover-name <Prover>)`.
- `src/bb.rs` exposes `write_vk_prove_verify(package, scheme)` that runs the full canonical BB flow (`bb write_vk → bb prove → bb verify`); **never** `nargo prove` or `nargo verify`.
- `cargo test -p pvthfhe-circuit-tests` exits 0 on the smoke test.
- `tests/integration/policy_invariants.rs` (X2) extended to assert harness sources contain no `nargo prove`/`nargo verify` calls.

---

### Task N1 — `circuits/decrypt_share` full RLWE dimension ✅ DONE

| Field | Value |
|---|---|
| **ID** | N1 |
| **Owner** | `circuits/decrypt_share/src/main.nr`, `circuits/decrypt_share/Prover.toml`, `crates/pvthfhe-circuit-tests/tests/decrypt_share_full_dim.rs` |
| **Depends on** | N0, X3 |
| **Gate** | noir-onchain-gate |

**RED test** (`crates/pvthfhe-circuit-tests/tests/decrypt_share_full_dim.rs`): use the N0 harness to (a) `nargo::execute(package="decrypt_share", prover_toml=fixtures/decrypt_share_full_dim.toml)` against a Prover.toml generated for the canonical RLWE parameters (per the X1-frozen ring degree); (b) `bb::write_vk_prove_verify(package="decrypt_share", scheme="ultra_honk")`; (c) assert `bb verify` exits 0; (d) assert public-input vector length matches spec §3.4 (parsed from `target/public_inputs`). Initially fails because the circuit asserts only `c1[0]==42`.

**GREEN criteria**: circuit constrains the full RLWE share-decryption relation per `spec-real-p2p3.md` §3.4 (s_i ⋆ c1 + e_dec = m_i with norm bounds) at the X1-canonical ring degree; harness test passes end-to-end via canonical BB flow. Reduced-dim assertions removed in place (stub protocol).

---

### Task N2 — `circuits/aggregator_final` full dimension ✅ DONE

| Field | Value |
|---|---|
| **ID** | N2 |
| **Owner** | `circuits/aggregator_final/src/main.nr`, `crates/pvthfhe-circuit-tests/tests/aggregator_final_full_dim.rs` |
| **Depends on** | N0, N1 |
| **Gate** | noir-onchain-gate |

**RED test** (`crates/pvthfhe-circuit-tests/tests/aggregator_final_full_dim.rs`): use the N0 harness to generate a Prover.toml that aggregates `n=3` real decrypt-shares produced from N1's witness fixtures; run `nargo::execute` then `bb::write_vk_prove_verify`; assert `bb verify` exits 0; assert public-input layout matches spec §3.5. Initially fails because the circuit is a reduced-dim surrogate.

**GREEN criteria**: circuit performs full-dimension Lagrange aggregation over R_q with the threshold-T reconstruction relation at the X1-canonical ring degree; harness test passes via canonical BB flow.

---

### Task N3a — Sonobe-in-UltraHonk feasibility spike (timeboxed; gates N3-N5) ✅ DONE — verdict: NoGo → N3'/N4'/N5' activated

| Field | Value |
|---|---|
| **ID** | N3a |
| **Owner** | `crates/pvthfhe-circuit-tests/tests/sonobe_wrap_feasibility.rs`, `.sisyphus/research/sonobe-wrap-feasibility.md` (new) |
| **Depends on** | N0, S2 |
| **Gate** | noir-onchain-gate (must complete before N3) |
| **Timebox** | 5 working days hard cap |

**Rationale**: Momus correctly flagged that R4 was a hand-wave. This spike commits to a single binary outcome before anything downstream is built.

**Spike question**: Does a Noir/UltraHonk circuit that verifies a Sonobe Nova final IVC proof (BN254/Grumpkin half-cycle) compile, witness-generate, and `bb prove` within the available host memory and within ≤ 4 h wall time at the X1-canonical ring degree?

**RED test**: spike-feasibility test exists and asserts a recorded outcome `{Go|NoGo}` in `sonobe-wrap-feasibility.md` front-matter; initially fails (file doesn't exist).

**GREEN criteria**: feasibility doc records:
- (a) Sonobe final-proof byte size and verifier-circuit estimated gate count (from a minimal one-step IVC);
- (b) actual `nargo execute` + `bb write_vk` + `bb prove` wall time and peak RSS for that minimal wrap;
- (c) extrapolation to the full-protocol IVC step count;
- (d) a single binary verdict `{Go|NoGo}` written to the doc's front matter and asserted by the test.

**Outcome routing**:

| N3a verdict | Activates | Tasks that proceed | Tasks that activate instead |
|---|---|---|---|
| **Go** | "real on-chain Sonobe wrap" path | N3, N4, N5 (as written) | — |
| **NoGo** | "off-chain Sonobe + on-chain commitment" fallback path | — | N3', N4', N5' (defined below) |

**Fallback tasks (activate only on NoGo)**: defined as full task entries N3', N4', N5' immediately following N3a below. Under NoGo, N3/N4/N5 are skipped and N3'/N4'/N5' execute in their place.

**Comparison policy under NoGo (binds §12)**: the rendered comparison table flags the on-chain row as `status="real-fallback"` (not `"real"`) and includes a `comparability_note` describing the proof-vs-attestation asymmetry. `bench-comparison-gate` (E5) is amended to allow `real-fallback` on the on-chain row only.

---

### Task N3' — Off-chain Sonobe verification + Noir state-commitment circuit (NoGo branch) ✅ DONE

| Field | Value |
|---|---|
| **ID** | N3' |
| **Owner** | `circuits/sonobe_state_commitment/src/main.nr` (in-place rewrite of `circuits/micronova_wrap` per stub protocol; tracked via `git mv`), `crates/pvthfhe-offchain-verifier/` (new crate), `crates/pvthfhe-circuit-tests/tests/sonobe_state_commitment_full.rs` |
| **Depends on** | N3a (verdict == NoGo), S2, N1, N2 |
| **Gate** | noir-onchain-gate |
| **Activated only if** | N3a verdict == NoGo |

**RED test** (`crates/pvthfhe-circuit-tests/tests/sonobe_state_commitment_full.rs`): (a) take a real `SonobeCompressor` proof from S2; (b) run the new `cargo run -p pvthfhe-offchain-verifier -- --proof <path> --emit-attestation <path>` binary, which performs Sonobe IVC verification off-chain and emits an EIP-712 attestation bundle `{sonobe_final_state_commitment, cyclo_aggregate_commitment, session_id, signer, signature}`; (c) via the N0 harness build a Prover.toml binding the state commitments and run `nargo::execute` then `bb::write_vk_prove_verify`; (d) assert `bb verify` exits 0; (e) assert the attestation bundle bytes match the public inputs the Noir circuit committed to. Also a negative test: tampered attestation must cause Noir witness generation to fail. Initially fails (neither the new binary nor the new circuit exists; existing `micronova_wrap` is a reduced-dim surrogate).

**GREEN criteria**: (a) `pvthfhe-offchain-verifier` binary verifies a Sonobe Nova final IVC proof via the Sonobe Rust API and emits the attestation bundle described above (EIP-712 typed-data hashing, signer key configurable; default = ephemeral test key for local runs, production-key plumbing flagged for follow-on); (b) Noir circuit `sonobe_state_commitment` constrains a Poseidon commitment to the Sonobe final state plus the Cyclo aggregate, with public inputs `(commit_pk, commit_ct_in, commit_ct_out, session_id, sonobe_final_state_commitment, cyclo_aggregate_commitment)`; (c) test passes end-to-end via canonical BB flow; (d) SECURITY-ADVISORY-001 amended (in N5') to call out the trust-assumption shift from cryptographic-only verification to attestation-augmented verification.

---

### Task N4' — Generate `UltraHonkVerifier.sol` for `sonobe_state_commitment` (NoGo branch) ✅ DONE

| Field | Value |
|---|---|
| **ID** | N4' |
| **Owner** | `contracts/src/generated/UltraHonkVerifier.sol`, `bench/scripts/gen_verifier.sh`, `contracts/test/UltraHonkVerifier.t.sol` |
| **Depends on** | N3' |
| **Gate** | noir-onchain-gate |
| **Activated only if** | N3a verdict == NoGo |

**RED test** (`contracts/test/UltraHonkVerifier.t.sol`, run via `forge test --root contracts --match-contract UltraHonkVerifierTest`): (a) submit a valid `sonobe_state_commitment` UltraHonk proof + public inputs; expect `verify` returns true; (b) submit the same proof with a tampered public input (e.g., flipped bit in `sonobe_final_state_commitment`), expect false; (c) assert proof byte-size and verify gas are within the budget recorded in `sonobe-wrap-feasibility.md` (smaller than the Go-branch wrap budget). Initially fails because `HonkVerifier.sol` is the keccak prototype.

**GREEN criteria**: `bench/scripts/gen_verifier.sh` runs `bb write_solidity_verifier` against the `sonobe_state_commitment` vk and writes `contracts/src/generated/UltraHonkVerifier.sol`; the file is committed; the keccak prototype `HonkVerifier.sol` is replaced in place (stub protocol, not deleted-and-recreated); foundry tests pass under `forge test --root contracts`; verifier ABI documents commitment-binding semantics (rather than direct proof verification).

---

### Task N5' — Remove killswitch + thread off-chain attestation (NoGo branch) ✅ DONE

| Field | Value |
|---|---|
| **ID** | N5' |
| **Owner** | `contracts/src/PvtFheVerifier.sol`, `contracts/src/IPvthfheVerifier.sol`, `contracts/test/PvtFheVerifier.t.sol`, `SECURITY-ADVISORY-001.md` |
| **Depends on** | N4' |
| **Gate** | noir-onchain-gate |
| **Activated only if** | N3a verdict == NoGo |

**RED test** (`contracts/test/PvtFheVerifier.t.sol`): (a) submit a valid `sonobe_state_commitment` proof + matching off-chain attestation bundle from N3'; expect `PvtFheVerifier.verifyWithAttestation(...)` returns true; (b) submit valid proof but attestation signed by a non-designated key; expect `verifyWithAttestation` to revert with `InvalidAttestor`; (c) submit valid attestation but mismatched proof public inputs; expect `verifyWithAttestation` to revert with `CommitmentMismatch`; (d) submit the legacy "everything reverts" payload to the original `verify`; expect the unconditional `revert` block at lines 96–107 to be gone (the call now reaches the proof-verification path, which fails cleanly with `InvalidProof` rather than the killswitch `revert`). Initially fails because the killswitch is still present and `verifyWithAttestation` doesn't exist.

**GREEN criteria**: (a) `revert` block at `PvtFheVerifier.sol:96-107` removed in place (stub protocol); (b) **new** method `verifyWithAttestation(bytes proof, uint256[] publicInputs, AttestationBundle attestation)` is the success path under NoGo deployment — it delegates to `UltraHonkVerifier.verify` for the proof and validates the EIP-712 attestation bundle against a designated verifier set stored in contract state (set at construction; rotation flagged for follow-on); (c) the original `verify(bytes, uint256[])` signature is preserved (no breaking change to `IPvthfheVerifier`) and now delegates to `UltraHonkVerifier.verify` with no attestation check — under NoGo deployment this method is **not** the intended entrypoint and integration code uses `verifyWithAttestation`, but `verify` does not revert: it returns whatever `UltraHonkVerifier.verify` returns. The trust-assumption shift (NoGo callers must use `verifyWithAttestation`) is documented in SECURITY-ADVISORY-001 and the contract NatSpec; (d) `IPvthfheVerifier.sol` is extended additively with the new method (existing consumers unaffected); (e) SECURITY-ADVISORY-001 updated to (i) remove killswitch language and (ii) add a "Trust assumption: NoGo branch" subsection documenting the verifier-set trust model and citing the N3a feasibility doc; (f) E4 docs sweep covers ARCHITECTURE.md and README per its own checklist.

---

---

### Task N3 — `circuits/sonobe_wrap` (rename from `micronova_wrap`, in-place per stub protocol)

| Field | Value |
|---|---|
| **ID** | N3 |
| **Owner** | `circuits/sonobe_wrap/src/main.nr` (stub-replace existing `micronova_wrap`), `circuits/Nargo.toml`, `crates/pvthfhe-circuit-tests/tests/sonobe_wrap_full.rs` |
| **Depends on** | N3a (verdict=Go), S2, N1, N2 |
| **Gate** | noir-onchain-gate |
| **Activated only if** | N3a verdict == Go |

**RED test** (`crates/pvthfhe-circuit-tests/tests/sonobe_wrap_full.rs`): take a real `SonobeCompressor` proof from S2; via the N0 harness build a Prover.toml that wraps it; run `nargo::execute` then `bb::write_vk_prove_verify`; assert `bb verify` exits 0. Initially fails (existing wrap circuit is reduced-dim MicroNova surrogate).

**GREEN criteria**: Noir circuit verifies the Sonobe Nova final IVC proof (BN254/Grumpkin half-cycle handled; Poseidon↔Keccak Construction 1 bridge from `micronova-digest.md` re-used). Public inputs encode `(commit_pk, commit_ct_in, commit_ct_out, session_id)` per spec §3.7. **In-place rewrite**: keep the directory name update tracked via `git mv`; do not delete and recreate.

---

### Task N4 — Generate `UltraHonkVerifier.sol` via BB

| Field | Value |
|---|---|
| **ID** | N4 |
| **Owner** | `contracts/src/generated/UltraHonkVerifier.sol`, `bench/scripts/gen_verifier.sh`, `contracts/test/UltraHonkVerifier.t.sol` |
| **Depends on** | N3 (or N3' under N3a NoGo) |
| **Gate** | noir-onchain-gate |

**RED test** (`contracts/test/UltraHonkVerifier.t.sol`, run via `forge test --root contracts --match-contract UltraHonkVerifierTest`): submit a valid wrap proof; expect `verify` returns true; submit a tampered proof, expect false. Initially fails because `HonkVerifier.sol` does `keccak256(proof) == publicInputs[0]`.

**GREEN criteria**: `bench/scripts/gen_verifier.sh` runs `bb write_solidity_verifier` against the sonobe_wrap (or sonobe_state_commitment under NoGo) vk and writes to `contracts/src/generated/UltraHonkVerifier.sol`; the file is committed; the keccak prototype `HonkVerifier.sol` is replaced in place (stub protocol); foundry tests pass under `forge test --root contracts`.

---

### Task N5 — Remove the killswitch from `PvtFheVerifier.sol`

| Field | Value |
|---|---|
| **ID** | N5 |
| **Owner** | `contracts/src/PvtFheVerifier.sol` |
| **Depends on** | N4 (or N4' under N3a NoGo) |
| **Gate** | noir-onchain-gate |

**RED test** (`contracts/test/PvtFheVerifier.t.sol`): submit a valid wrap proof + public inputs; expect `verifyPvtFhe(...)` returns true. Initially fails because lines 96–107 unconditionally `revert`.

**GREEN criteria**: `revert` block deleted; verifier delegates to `UltraHonkVerifier.verify` and threads public inputs per `IPvthfheVerifier.sol` ABI (preserved). SECURITY-ADVISORY-001 updated to remove the killswitch language; README's status block updated under `pvthfhe-followon` note.

---

### Task N6 — `just noir-onchain-gate` ✅ DONE

| Field | Value |
|---|---|
| **ID** | N6 |
| **Owner** | `Justfile` |
| **Depends on** | N0, N1, N2, N3a, (N3+N4+N5) ∨ (N3'+N4'+N5') |
| **Gate** | itself |

**GREEN criteria**: recipe runs the canonical BB flow per circuit, `forge test --root contracts`, and the e2e `verify-onchain` recipe end-to-end.

---

## 8. Phase P — Real Lattice PVSS (Path A)

Gate: `just pvss-gate`.

> Replaces the integer-Shamir+SHA-256 `HermineAdapter` with a lattice PVSS that encrypts each share under the recipient's public key and proves well-formedness using the existing P1 Sigma+Ajtai NIZK adapted to the share-encryption statement. This is the analogue of trBFV's `ZkShareEncryption + ZkVerifyShareProofs + ZkDkgShareDecryption` cluster — together ~85% of trBFV's DKG cost.

### Task P0a — Lattice PVSS feasibility spike (timeboxed; gates P0-P5) ✅ DONE

| Field | Value |
|---|---|
| **ID** | P0a |
| **Owner** | `.sisyphus/research/lattice-pvss-feasibility.md` (new), `crates/pvthfhe-pvss/tests/feasibility.rs` (new, ignored by default) |
| **Depends on** | X3 |
| **Gate** | pvss-gate (must complete before P0) |
| **Timebox** | 5 working days hard cap |

**Spike question**: Can the existing Sigma+Ajtai NIZK from `pvthfhe-nizk` be composed with a per-recipient BFV encryption statement (`(u_i, v_i) = BFV.Enc(pk_j, s_i; r_{ij})`) such that (a) the joint statement remains a single Σ-protocol amenable to the existing Fiat-Shamir transcript, (b) per-instance prove time at H=N=3 is within ≤ 30× the existing keygen-time NIZK cost, and (c) no fresh extractor argument is required beyond what the conditional-soundness banner already covers?

**RED test**: feasibility doc exists with a single `verdict: {Go|NoGo|GoWithCaveat}` field in front matter; initially fails (file doesn't exist).

**GREEN criteria**: feasibility doc records (a) joint statement specification with per-symbol references to ePrint 2025/901 and 2024/1285; (b) prototype prove/verify wall time on a 1-instance toy example (test `feasibility.rs` measures and writes); (c) extractor argument review: either reuses existing conditional-soundness banner verbatim or itemises the additional assumptions; (d) verdict written and asserted by the test.

**Outcome routing**:

| P0a verdict | Activates | Tasks that proceed |
|---|---|---|
| **Go** | full Path A | P0, P1-pvss .. P6-pvss as written |
| **GoWithCaveat** | Path A with extra assumption | P0 must capture the extra assumption in `assumptions-ledger.md` and conditional-soundness banner before P1-pvss starts |
| **NoGo** | escalate to user | P phase paused; user re-decides between Path B (subtract from baseline) and Path C (vendor `fhe::trbfv`); plan re-baselines |

---

### Task P0 — Spec freeze: lattice PVSS scheme and statement ✅ DONE

| Field | Value |
|---|---|
| **ID** | P0 |
| **Owner** | `.sisyphus/design/spec-pvss.md` (new), `.sisyphus/design/spec-real-p2p3.md` addendum §5 |
| **Depends on** | P0a (verdict ∈ {Go, GoWithCaveat}) |
| **Gate** | pvss-gate |

**RED test** (`crates/pvthfhe-pvss/tests/spec_present.rs`): assert spec docs exist with frozen sections.

**GREEN criteria**: `spec-pvss.md` freezes (a) sharing relation: `s = Σ λ_i · s_i mod Φ_N(X)` with `‖s_i‖_∞ ≤ B_s`; (b) per-recipient encryption: `(u_i, v_i) = BFV.Enc(pk_j, s_i; r_{ij})` with `‖r_{ij}‖_∞ ≤ B_r`; (c) NIZK statement: prove knowledge of `(s_i, r_{ij})` such that the BFV ciphertext encrypts a share consistent with the public commitment `C_i` (D2 hash bridge — already implemented). References ePrint 2025/901 (Hermine) and 2024/1285 (trBFV) for the design space. Parameter table compatible with `parameters.toml [rlwe]`.

---

### Task P1 — New crate `crates/pvthfhe-pvss` + `PvssAdapter` trait ✅ DONE

| Field | Value |
|---|---|
| **ID** | P1-pvss |
| **Owner** | `crates/pvthfhe-pvss/src/lib.rs` |
| **Depends on** | P0 |
| **Gate** | pvss-gate |

**RED test**: trait object-safety compile test.

**GREEN criteria**: `PvssAdapter` exposes `deal(secret, ctx) -> EncryptedShares`, `verify_shares(...)`, `recover(shares) -> Secret`, `backend_id`. Crate skeleton compiles; `cargo test -p pvthfhe-pvss` passes.

---

### Task P2 — Per-recipient BFV encryption of shares ✅ DONE

| Field | Value |
|---|---|
| **ID** | P2-pvss |
| **Owner** | `crates/pvthfhe-pvss/src/encrypt.rs` |
| **Depends on** | P1-pvss |
| **Gate** | pvss-gate |

**RED test** (`crates/pvthfhe-pvss/tests/encrypt_decrypt_roundtrip.rs`): generate `n=3` parties with `fhers` keypairs; deal a random secret; each party decrypts its share and the recovered Lagrange combination equals the secret.

**GREEN criteria**: encryption uses `pvthfhe_fhe::fhers::FhersBackend` (locked backend) for share-by-share BFV encryption; randomness norms enforced; `backend_id == "lattice-pvss-bfv-d2"`.

---

### Task P3 — NIZK at share-encryption time (reuse Sigma+Ajtai) ✅ DONE

| Field | Value |
|---|---|
| **ID** | P3-pvss |
| **Owner** | `crates/pvthfhe-pvss/src/nizk_share.rs` |
| **Depends on** | P2-pvss |
| **Gate** | pvss-gate |

**RED test** (`crates/pvthfhe-pvss/tests/share_nizk.rs`): honest dealer + cheating dealer; honest accepted, cheating rejected; norm-bound violator rejected.

**GREEN criteria**: statement composes Sigma protocol from `pvthfhe-nizk` with the BFV encryption relation; transcript domain separator `"pvthfhe-pvss-share-encryption-v1"`; FS hashing reuses `pvthfhe_nizk::fiat_shamir`. No new `#[allow]`.

---

### Task P4 — Decrypt-side proof (PVSS share-decryption) ✅ DONE

| Field | Value |
|---|---|
| **ID** | P4-pvss |
| **Owner** | `crates/pvthfhe-pvss/src/nizk_decrypt.rs` |
| **Depends on** | P3-pvss |
| **Gate** | pvss-gate |

**RED test** (`crates/pvthfhe-pvss/tests/decrypt_share_nizk.rs`): each party proves correct decryption of its received share; verifier accepts honest, rejects forged.

**GREEN criteria**: same Sigma+Ajtai construction, decrypt-time statement; reuses `pvthfhe-nizk` adapter (no duplicate Sigma machinery).

---

### Task P5 — Wire `PvssAdapter` into `run_demo`, `pvthfhe-e2e`, and `bench-comparison` ✅ DONE

| Field | Value |
|---|---|
| **ID** | P5-pvss |
| **Owner** | `crates/pvthfhe-cli/src/main.rs`, `crates/pvthfhe-cli/src/bin/pvthfhe_e2e.rs`, `crates/pvthfhe-keygen/src/lib.rs`, `crates/pvthfhe-bench/src/bin/bench_comparison.rs` |
| **Depends on** | P4-pvss, W4, W5 |
| **Gate** | pvss-gate |

**RED test** (`crates/pvthfhe-cli/tests/e2e_uses_lattice_pvss.rs`): `pvthfhe-e2e` reports `pvss_backend_id == "lattice-pvss-bfv-d2"` and `bench-comparison` JSON shows `ZkShareEncryption.status == "real"`.

**GREEN criteria**: `HermineAdapter` remains in tree but is no longer wired into the default demo path (per stub protocol; deprecation note added). Default keygen route uses `LatticePvssAdapter`. End-to-end timings now include the share-encryption proof cost.

---

### Task P6 — `just pvss-gate` ✅ DONE

| Field | Value |
|---|---|
| **ID** | P6-pvss |
| **Owner** | `Justfile` |
| **Depends on** | P0–P5-pvss |
| **Gate** | itself |

**GREEN criteria**: recipe runs `cargo test -p pvthfhe-pvss`, the e2e integration test, and a small benchmark assertion that `share_encryption_proof_ms > 0` (sanity guard against silent skip).

---

## 9. Phase E — Apples-to-Apples Comparison Output

Gate: `just bench-comparison-gate`.

### Task E1 — Map our circuit timings to Interfold's circuit names ✅ DONE

| Field | Value |
|---|---|
| **ID** | E1 |
| **Owner** | `crates/pvthfhe-bench/src/comparison_map.rs` (new), `bench/results/interfold-trbfv-baseline.json` (vendored copy of their `integration_summary.json`, with provenance header) |
| **Depends on** | W5 |
| **Gate** | bench-comparison-gate |

**RED test** (`crates/pvthfhe-bench/tests/circuit_name_map.rs`): assert every Interfold circuit name from the vendored baseline JSON has either a PVTHFHE timing or an explicit `gap_reason` string in `comparison_map.rs`.

**GREEN criteria**: vendored baseline JSON includes commit SHA and URL of source; mapping covers all 12 circuits; CI fails if a new Interfold circuit name appears without a mapping entry.

---

### Task E2 — Side-by-side report renderer ✅ DONE

| Field | Value |
|---|---|
| **ID** | E2 |
| **Owner** | `crates/pvthfhe-bench/src/bin/render_comparison.rs` (new), `bench/templates/comparison.md.tera` |
| **Depends on** | E1 |
| **Gate** | bench-comparison-gate |

**RED test** (`crates/pvthfhe-bench/tests/render_comparison.rs`): render with synthetic inputs; assert output Markdown contains the hardware disclosure block (§12), per-circuit rows for all 12 Interfold circuits, ratio columns, and a "real vs. surrogate" status legend.

**GREEN criteria**: output is a self-contained Markdown file under `bench/results/comparison-<commitsha>.md`; numbers carry uncertainty intervals from ≥3 runs; report flags any row where our `status != "real"`.

---

### Task E3 — `just bench-comparison` ✅ DONE

| Field | Value |
|---|---|
| **ID** | E3 |
| **Owner** | `Justfile` |
| **Depends on** | E1, E2, all Phase W/S/N/P gates green |
| **Gate** | bench-comparison-gate |

**GREEN criteria**: single command that runs `pvthfhe-e2e --n 3 --t 1 --seed 1` thrice (matching Interfold's H=N=3, T=1 minus their T=1 edge case which we report verbatim from their JSON), aggregates timings, and writes the comparison Markdown + JSON. Idempotent.

---

### Task E4 — README, ARCHITECTURE, and SECURITY status updates ✅ DONE

| Field | Value |
|---|---|
| **ID** | E4 |
| **Owner** | `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, `SECURITY-ADVISORY-001.md` |
| **Depends on** | E3, N5 (or N5' under N3a NoGo) |
| **Gate** | bench-comparison-gate |

**RED test** (`tests/integration/docs_truthful.rs`, driven by markdown grep): assert (a) README no longer claims "Noir circuits are tautological surrogates" or "on-chain verifier reverts on all inputs"; (b) ARCHITECTURE.md no longer asserts MicroNova as the active compressor (must mention Sonobe substitution per S0); (c) README links to the latest `bench/results/comparison-*.md`; (d) under N3a NoGo, ARCHITECTURE.md describes the off-chain Sonobe + on-chain commitment topology with the trust-assumption shift called out. The existing `phase{1,2,3}-gate` doc-truthfulness checks are preserved (do not regress `Justfile:122-126`-style assertions).

**GREEN criteria**: README, ARCHITECTURE.md, SECURITY.md, and SECURITY-ADVISORY-001 reflect current truth: P1 conditional-soundness banner remains; P2 surrogate language removed; P3 killswitch language removed; benchmark comparison link added; Stage 0 build-time tripwire description retained; Sonobe substitution + bounded migration surface called out; under NoGo, off-chain verification topology documented.

---

### Task E5 — `just bench-comparison-gate` ✅ DONE

| Field | Value |
|---|---|
| **ID** | E5 |
| **Owner** | `Justfile` |
| **Depends on** | E1–E4 |
| **Gate** | itself |

**GREEN criteria**: recipe runs E1/E2/E3 tests and asserts the latest `bench/results/comparison-*.md` has zero `surrogate` rows. `real-fallback` is permitted **only** on the on-chain row and **only** when N3a verdict == NoGo is recorded in `sonobe-wrap-feasibility.md` front matter; the gate parses the spike-doc front matter and rejects any `real-fallback` row otherwise.

---

## 10. Phase F — Final Review & Acceptance

### Task F1 — `/review-work` 5-agent gate ✅ DONE

| Field | Value |
|---|---|
| **ID** | F1 |
| **Owner** | orchestrator |
| **Depends on** | all of W, S, N, P, E |
| **Gate** | terminal |

**GREEN criteria**: Oracle (goals/constraints), Oracle (code quality), Oracle (security), unspecified-high (hands-on QA), unspecified-high (context mining) all pass. Any failure loops back to the relevant phase.

### Task F2 — User acceptance ✅ DONE

| Field | Value |
|---|---|
| **ID** | F2 |
| **Depends on** | F1 |
| **Gate** | terminal |

**GREEN criteria**: user runs `just bench-comparison` on their machine, reviews the output, and signs off. Plan moves to CLOSED.

---

## 11. Dependency Graph (Critical Path)

```
                    ┌─► W1 ─┐
X1 ─► X2 ─► X3 ─────┤      ├─► W3 ─► W4 ─► W5 ─► W6
(prereq-gate)       └─► W2 ─┘                  ▲
                                                │
        S0 ─► S1 ─► S2 ─► S3 ─► S4 ─► S5 ──────┤
                    │                           │
                    └─► N3a ──{verdict}──┐      │
                          │              │      │
                          ▼              ▼      │
                    Go: N3 ─► N4 ─► N5  N3'─►N4'─►N5'  (NoGo branch)
                                  ▲                       ▲
        N0 ─► N1 ─► N2 ───────────┘                       │
                                                          │
                                              ────────────┴─► N6

        P0a ──{verdict}──► P0 ─► P1-pvss ─► P2-pvss ─► P3-pvss ─► P4-pvss ─► P5-pvss ─► P6-pvss
                  │                                                              ▲
                  └─► NoGo: escalate to user; P phase paused                     │
                                                                                  │
E1 ─► E2 ─► E3 ─► E4 ─► E5  (depends on W6 ∧ S5 ∧ N6 ∧ P6) ─────────────────────┘
                          ▲
F1 ◄── all gates ──► F2
```

**Critical path under N3a=Go ∧ P0a=Go**: X → (W ∥ S ∥ N0 → N1 → N2 → N3a → N3 → N4 → N5 → N6) ∥ (P0a → P0 → P1 → ... → P6) → E → F. P phase typically dominates wall time given new spec + new crate + statement composition.

**Schedule rebaseline triggers**: any of {N3a NoGo, P0a NoGo, X1 reveals incompatible spec assumptions, R2 OOM hit at N1} forces the orchestrator to revisit the 8-12 week budget before downstream tasks start.

---

## 12. Honest-Comparison Policy

Every artifact under `bench/results/comparison-*.md` and every JSON output of `bench-comparison` MUST include:

1. **Hardware disclosure block** for both ours and Interfold's: CPU model, core count, RAM, OS.
2. **Toolchain disclosure**: Rust version, Nargo version, BB version, Sonobe commit, fhe.rs commit.
3. **Parameters disclosure**: ring degree N, log₂q, B_e, B_s, B_r, threshold T, party count H — using the X1-canonical parameter table.
4. **Status column** per circuit: `real` / `real-fallback` / `surrogate` / `n/a`.
   - `real-fallback` is permitted ONLY for the on-chain verification row under N3a NoGo (off-chain Sonobe + on-chain commitment); MUST be accompanied by a `comparability_note` describing the proof-vs-attestation asymmetry.
   - `n/a` is for legitimate scheme-level differences (e.g., trBFV-only proofs with no PVTHFHE analogue).
5. **Cardinality column** per row, populated from §3 mapping table: `1:1` / `1:N` / `1:N(N-1)` / `2:2 split-merge` / etc., with `instances_run` and aggregation rule made explicit.
6. **Comparability note** column for any row whose cardinality ≠ `1:1` OR whose proof system differs from trBFV's — one-line "why this is comparable" or "why this is asymmetric" per row.
7. **No normalisation**: do not rescale Interfold's numbers to our hardware. Reader-side normalisation only.
8. **Provenance**: commit SHA of vendored Interfold baseline, URL, retrieval date.
9. Any `surrogate` row blocks `bench-comparison-gate` (E5). `real-fallback` is allowed only on the on-chain row and only under N3a NoGo.

---

## 13. Risk Register

| ID | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Sonobe API churn on the `folding-schemes` crate | M | M | Pin git rev in `pvthfhe-compressor/Cargo.toml`; isolate to `sonobe::*` module per S0; bounded migration surface S4 invariant test catches leakage. |
| R2 | Full-dim Noir circuits exceed BB prover memory at X1-canonical ring degree | M | H | N1 profiles peak RSS first; if OOM, X1 must be re-opened (new ring-degree decision-record) and parameter change documented in §12 disclosure (no silent shrink). |
| R3 | Lattice PVSS NIZK soundness needs a fresh argument | M | H | P0a feasibility spike commits to `Go|GoWithCaveat|NoGo` before any P implementation; GoWithCaveat extends the conditional-soundness banner with the named additional assumption. |
| R4 | Sonobe verifier circuit doesn't fit in UltraHonk | M | H | **N3a feasibility spike** with explicit fallback task graph N3'/N4'/N5' (off-chain Sonobe + on-chain commitment). §12 amended to allow `real-fallback` status on the on-chain row only under NoGo. |
| R5 | Comparison numbers come out worse than trBFV | M | M | Acceptable — the mission is *legitimate* comparison, not winning; document honestly. |
| R6 | MicroNova migration becomes harder than estimated | L | M | S0 freezes the **bounded migration surface** (5 invariants); S4 invariant test enforces touch-point bound ≤ 8 (target 3-5). |
| R7 | Stage 0 tripwires accidentally disabled while wiring real components | L | H | X2 `tests/integration/policy_invariants.rs` is required by every gate, not just W6; tripwire regression fails the offending phase. |
| R8 | 8-12 week budget breached due to P0a / N3a spike outcomes or X1 surprises | M | M | Spikes are timeboxed (5 working days each). On NoGo or rebaseline trigger, orchestrator pauses downstream work and re-prompts user for scope renegotiation. |
| R9 | Sub-agent confusion from §3 mapping rows that are not 1:1 | M | M | E2 renderer enforces per-row cardinality + comparability note (§12 #5,#6); CI fails if any non-1:1 row lacks a comparability note. |

---

## 14. Open Questions to Revisit Before Closing

- **Q1** (resolved by N3a, recorded in `.sisyphus/research/sonobe-wrap-feasibility.md`): does the Sonobe Nova final IVC proof fit in an UltraHonk circuit at X1-canonical parameters?
- **Q2** (resolved by P0a, recorded in `.sisyphus/research/lattice-pvss-feasibility.md`): exact lattice PVSS variant — direct adoption from ePrint 2025/901, custom composition, or escalation to user (Path B/C)?
- **Q3** (revisit at E2): do we report 3 runs, 5 runs, or 10 runs for confidence intervals? Trade-off: bench wall time vs. statistical strength. Default 3, escalate to 5 if variance > 10%.
- **Q4** (revisit at X1): which ring degree is canonical? (`N=8192` per current spec line 75, or `RLWE_N=1024` per lines 200-204.) Decision-record paragraph required before any downstream task.

---

## 15. Cross-References

- `pvthfhe-real-fhe-demo.md` — predecessor, real fhe.rs backend wiring.
- `pvthfhe-real-p2p3.md` — predecessor, P1 NIZK + P2 Cyclo + MicroNova scaffold landed.
- `pvthfhe-followon.md` — long-haul publication / formal-soundness work.
- `pvthfhe-skeptical-audit.md` — historical audit; this plan addresses its concrete gaps.
- `redteam-stage0-killswitch.md` / `redteam-stage1-cryptographic-core.md` — Stage 0/1 invariants this plan must preserve.
- `.sisyphus/design/spec-real-p2p3.md` — the joint freeze; addended in S0 and P0.
- `.sisyphus/design/assumptions-ledger.md` — A-MLWE, A-SIS, A-DLOG, A-FS, A-ROM ledger.
- `.sisyphus/research/cyclo-digest.md`, `micronova-digest.md`, `nizk-selection.md` — research basis.
