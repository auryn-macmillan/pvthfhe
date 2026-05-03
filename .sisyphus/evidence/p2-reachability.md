# P2 Folding Code-Path Reachability (T8)

**Updated:** 2026-05-03  
**Scope:** `crates/pvthfhe-aggregator/src/` + downstream crates (bench, CLI, tests)

---

## 1. Feature Flag: `real-folding`

**Source:** `crates/pvthfhe-aggregator/Cargo.toml` lines 24–28

```toml
[features]
real-folding = []
real-verifier = ["real-folding"]
real-pvss = []
real-nizk = []
```

| Property | Value |
|----------|-------|
| Default features | `[]` (none) — `real-folding` is **NOT** default |
| Enables | `real-verifier = ["real-folding"]` (real-verifier implies real-folding) |
| Enabled by downstream? | **NO** — `pvthfhe-bench` and `pvthfhe-cli` both depend on `pvthfhe-aggregator` without `features = ["real-folding"]` |
| Required by tests | `tests/folding_adversarial.rs`, `tests/p2_bench.rs`, `tests/e2e_real.rs` are `required-features = ["real-folding"]` or `required-features = ["real-verifier"]`; `tests/folding_tamper.rs` has a gated inner module |

**Conclusion:** `real-folding` gates the entire "real" folding API. It is **never activated from any production binary**. Only tests compiled with `--features real-folding` exercise this path.

---

## 2. Public Folding API — Always-Live (no feature gate)

Defined in `crates/pvthfhe-aggregator/src/folding/mod.rs`. Always compiled regardless of features.

| Symbol | Kind | Defined at | Callers | Status |
|--------|------|-----------|---------|--------|
| `FoldingError` | pub enum | `folding/mod.rs:13` | `tests/folding_tamper.rs:21` | **LIVE** |
| `PartyProof` | pub struct | `folding/mod.rs:19` | `tests/folding_n64.rs:3,13`, `tests/folding_tamper.rs:3,11`, `bench/gen_goldens.rs:4,36`, `bench/bench_scaling.rs:10,67`, `cli/main.rs:15,251` | **LIVE** |
| `FinalSnark` | pub struct | `folding/mod.rs:26` | `bench/folding.rs:25`, returned by `FoldingAccumulator::finalize()` | **LIVE** |
| `FoldingAccumulator` | pub struct | `folding/mod.rs:33` | `tests/folding_n64.rs:10`, `tests/folding_tamper.rs:7`, `bench/gen_goldens.rs:26`, `bench/bench_scaling.rs:65`, `cli/main.rs:248` | **LIVE** |
| `FoldingAccumulator::new()` | pub fn | `folding/mod.rs:44` | same callers as struct | **LIVE** |
| `FoldingAccumulator::add_proof()` | pub fn | `folding/mod.rs:48` | `tests/folding_n64.rs:18`, `tests/folding_tamper.rs:16`, `bench/gen_goldens.rs:41`, `bench/bench_scaling.rs:72`, `cli/main.rs:256` | **LIVE** |
| `FoldingAccumulator::finalize()` | pub fn | `folding/mod.rs:53` | `tests/folding_n64.rs:21`, `tests/folding_tamper.rs:19`, `bench/gen_goldens.rs:44`, `bench/bench_scaling.rs:74`, `cli/main.rs:261` | **LIVE** |

---

## 3. Public Folding API — Gated Behind `#[cfg(feature = "real-folding")]`

### 3a. Types

| Symbol | Kind | Defined at | Callers (when feature enabled) | Status |
|--------|------|-----------|-------------------------------|--------|
| `FoldStatement` | pub struct | `folding/mod.rs:85` | `tests/folding.rs:5`, `tests/folding_adversarial.rs:45`, `tests/p2_bench.rs:16`, `tests/e2e_real.rs:27` | **LIVE** (feature-only) |
| `FoldWitness` | pub struct | `folding/mod.rs:94` | `tests/folding.rs:5`, `tests/p2_bench.rs:16`, `tests/e2e_real.rs:27` | **LIVE** (feature-only) |
| `FoldAccumulator` | pub struct | `folding/mod.rs:101` | `tests/folding.rs:46`, `tests/folding_adversarial.rs:45`, `tests/p2_bench.rs:25`, `tests/folding_tamper.rs:39`, `tests/e2e_real.rs:171` | **LIVE** (feature-only) |
| `FinalProof` | pub struct | `folding/mod.rs:111` | `tests/folding.rs:5,70` | **LIVE** (feature-only) |
| `FoldError` | pub struct | `folding/mod.rs:118` | `tests/folding.rs:5`, `tests/folding_adversarial.rs`, `tests/folding_tamper.rs` | **LIVE** (feature-only) |
| `NizkStatement` | pub struct | `folding/mod.rs:122` | `tests/folding.rs`, `tests/e2e_real.rs` | **LIVE** (feature-only) |
| `NizkProof` | pub struct | `folding/mod.rs:129` | `tests/folding.rs`, `tests/p2_bench.rs:16`, `tests/e2e_real.rs` | **LIVE** (feature-only) |
| `FoldingScheme` | pub trait | `folding/mod.rs:135` | Only implemented by `RealFoldingScheme` — **no external callers** use this trait by name | **DEAD** (externally) |
| `RealFoldingScheme` | pub struct | `folding/mod.rs:151` | Never directly named outside `folding/mod.rs`; all calls go through free-function wrappers | **DEAD** (externally) |

### 3b. Free Functions

| Symbol | Signature | Defined at | Callers | Status |
|--------|-----------|-----------|---------|--------|
| `fold` | `(acc: &FoldAccumulator, witness: &FoldWitness, stmt: &FoldStatement) -> Result<FoldAccumulator, FoldError>` | `folding/mod.rs:203` | `tests/folding.rs`, `tests/p2_bench.rs:96`, `tests/e2e_real.rs` | **LIVE** (feature-only) |
| `verify_acc` | `(acc: &FoldAccumulator, expected_params: &(u64, usize, u64)) -> Result<(), FoldError>` | `folding/mod.rs:212` | `tests/folding.rs`, `tests/p2_bench.rs`, `tests/e2e_real.rs` | **LIVE** (feature-only) |
| `finalize` | `(acc: &FoldAccumulator) -> Result<FinalProof, FoldError>` | `folding/mod.rs:220` | `tests/folding.rs:70-71`, `tests/p2_bench.rs:110`, `tests/e2e_real.rs:208` | **LIVE** (feature-only) |

### 3c. `FoldAccumulator` Methods (all gated)

| Method | Defined at | Callers | Status |
|--------|-----------|---------|--------|
| `FoldAccumulator::new(...)` | `folding/mod.rs:226` | `tests/folding.rs:46`, `tests/folding_adversarial.rs:45`, `tests/p2_bench.rs:25`, `tests/folding_tamper.rs:39`, `tests/e2e_real.rs:171` | **LIVE** (feature-only) |
| `FoldAccumulator::acc_commitment()` | `folding/mod.rs:242` | `tests/p2_bench.rs:61`, `tests/folding_tamper.rs:153-154` | **LIVE** (feature-only) |
| `FoldAccumulator::fold_depth()` | `folding/mod.rs:246` | `tests/folding.rs:112`, `tests/folding_adversarial.rs:190,207`, `tests/p2_bench.rs`, `tests/e2e_real.rs:202,270` | **LIVE** (feature-only) |
| `FoldAccumulator::session_id()` | `folding/mod.rs:250` | `tests/p2_bench.rs:61` | **LIVE** (feature-only) |
| `FoldAccumulator::params()` | `folding/mod.rs:254` | **NONE** | **DEAD** |
| `FoldAccumulator::statement_hash_chain()` | `folding/mod.rs:258` | **NONE** | **DEAD** |

---

## 4. pvthfhe-fhe Folding-Related Code

No folding-specific types or functions exist in `crates/pvthfhe-fhe/src/`. The crate provides lattice NIZK primitives (`real_nizk.rs`) consumed via `FoldWitness`/`NizkProof` types in the aggregator, but no direct folding API.

---

## 5. SHA-256 Hash-Chain Surrogate

**Location:** `crates/pvthfhe-aggregator/src/folding/mod.rs:53–80` (`FoldingAccumulator::finalize`)

**What it replaces:** A real LatticeFold+/HyperNova/MicroNova recursive proof over RLWE (open research problem P2).

**Mechanism:**
1. Iterates all `PartyProof` entries, feeding each `share_hash` (32 bytes) and `nizk_bytes` into a running `Sha256` hasher.
2. Returns the 32-byte SHA-256 digest as `FinalSnark::proof_bytes`.
3. Only validation: `nizk_bytes` must be non-empty (`folding/mod.rs:60-62`). No cryptographic proof verification.

**Confirmed by:**
- `tests/folding_n64.rs`: records `"scheme": "simulated_fold_sha256"` in bench output
- `tests/p2_bench.rs:3`: comment: _"All measurements use the surrogate hash-chain implementation of RealFoldingScheme."_
- `tests/p2_bench.rs:135`: _"Surrogate hash-chain implementation of RealFoldingScheme."_
- `folding/mod.rs:3-7`: module-level doc: _"This implementation provides a simulated folding harness that uses a hash-chain accumulation as a surrogate for real folding."_

**Second surrogate (real-folding path):** `validate_witness` (`folding/mod.rs:282-302`) checks that `nizk_proof.proof_bytes` are all-identical bytes (`windows(2).all(|w| w[0]==w[1])`). This is a placeholder uniformity check — **not** a Fiat-Shamir challenge check — and constitutes the P2-T4 arithmetic norm enforcement GAP.

---

## 6. `tests/folding_n64.rs` — What It Tests

The test:
1. Creates a `FoldingAccumulator` (simulated, no feature flag required)
2. Adds 64 `PartyProof`s with `nizk_bytes: vec![1,2,3,4]`
3. Calls `FoldingAccumulator::finalize()` → gets a `FinalSnark` backed by SHA-256 hash of all proofs
4. Asserts `proof_size_bytes > 0`, `prover_time_ms < 5000`, `public_inputs.len() == 64`
5. Writes bench JSON to `.sisyphus/evidence/task-37-bench.json` with `"scheme": "simulated_fold_sha256"`

**Conclusion:** This test validates the SHA-256 hash-chain surrogate only. It does **not** test any cryptographic folding, NIZK verification, or zero-knowledge property.

---

## 7. DEAD Code Summary

| Symbol | Location | Reason |
|--------|----------|--------|
| `FoldingScheme` (trait) | `folding/mod.rs:135` | Never referenced externally; only implemented by `RealFoldingScheme` internally |
| `RealFoldingScheme` (struct) | `folding/mod.rs:151` | Never directly instantiated outside the module; only used via free-fn wrappers |
| `FoldAccumulator::params()` | `folding/mod.rs:254` | Zero callers in entire codebase |
| `FoldAccumulator::statement_hash_chain()` | `folding/mod.rs:258` | Zero callers in entire codebase |

---

## 8. Open Gaps

1. **`validate_witness` placeholder** (`folding/mod.rs:282`): Accepts only proofs where all bytes are identical — a fake "uniformity" check, not a real Fiat-Shamir or norm enforcement (P2-T4 gap: arithmetic norm enforcement).
2. **SHA-256 surrogate** (`FoldingAccumulator::finalize`): Replaces real lattice commitment with SHA-256. Not ZK, not sound.
3. **`real-folding` never default**: Production binaries (`pvthfhe-cli`, `pvthfhe-bench`) never enable this feature; the RealFoldingScheme path is unreachable in production.
4. **Two separate "accumulators"**: `FoldingAccumulator` (always-live, SHA-256 surrogate) and `FoldAccumulator` (feature-gated, real-folding path with its own SHA-256 chain) coexist. The naming is confusing and both are surrogates.
