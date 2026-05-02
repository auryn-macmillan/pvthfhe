## [2026-05-02] Task: T1
- Toolchains installed successfully: cargo 1.95.0, just 1.50.0, forge 1.6.0-v1.7.0, nargo 1.0.0-beta.20, bb 5.0.0-nightly.20260324.
- Workspace scaffolding is intentionally minimal and compiles cleanly with placeholder tests across all 8 Rust crates.
- Foundry tests pass with a standalone Solidity test contract, avoiding forge-std until the later setup task.
- Noir workspace runs with 4 packages and zero test functions, which is enough for the bootstrap phase.
## [2026-05-02] Task: T2
- Established formal threat model with honest-majority threshold (t = ⌊n/2⌋+1).
- Documented 10 cryptographic assumptions covering lattice-based (RLWE, Module-LWE, SIS, knLWE), EC-based (DDH Grumpkin), and proof-system (KZG, AGM) primitives.
- Verified alignment with public verifiability and synchronous network requirements.

## [2026-05-02] Task: T3
- Initializing literature survey on publicly verifiable threshold FHE.
- Verified 2024/1285 as "Robust Multiparty Computation from Threshold Encryption Based on RLWE" (ISC 2024), focusing on robust BFV relinearization.
- Launched background agent to verify 12+ additional ePrint IDs and search for lattice PVSS primitives.

## [2026-05-02] Task: T6
- Decision: DEFER publicly verifiable bootstrapping for the primary BFV/CKKS threshold-FHE path.
- Cost model used in memo: decryption-share proof ~10k-100k ACIR ops at N=4096; CKKS bootstrap proof ~1.15M-3.45M ACIR ops (~30x-80x); BFV bootstrap proof ~1.5M-6.1M ACIR ops (~60x-100x).
- Rationale: CKKS/BFV exact-refresh proofs are far larger than mandatory decryption-share proofs, while TFHE has the only concrete practical PV-bootstrap result and would require a different scheme family / proving stack.
- Phase-1 gate JSON should carry `bootstrapping_pv_decision = "defer"` and a matching rationale string.

## [2026-05-02] Task: T5
- Criterion 0.5.1 used (latest available in lock); `[[bench]] harness = false` required for criterion benches
- `BenchEnv::capture()` reads `/proc/cpuinfo`, `/proc/meminfo`, `/proc/version` for hardware metadata
- `serde(rename = "mean")` pattern used to decouple internal field names (`mean_ns`) from JSON keys (`mean`)
- bench_runner binary outputs single-line JSON to stdout; `just bench-smoke` redirects to `bench/results/smoke-latest.json`
- TDD: wrote RED test first (struct didn't exist), then implemented structs — test went GREEN immediately after implementation
- `cargo test -p pvthfhe-bench` exits 0; `just bench-smoke` produces valid JSON with all envelope fields

## [2026-05-02] Task: T7
- Created cost-model template and JSON schema (Draft 2020-12).
- Validated sample-costs.json using ajv-cli with `--spec=draft2020` flag.
- Observed that ajv-cli requires explicit spec flag for 2020-12 even if $schema is present.
- Allowed union types (number | string) in schema to accommodate "TBD" placeholders in early research phases.
## [2026-05-02] Task: T4
- Chose gnosisguild/fhe.rs as the primary backend because it exposes stable RNS/NTT/Rq APIs, includes threshold BFV share serialization, and was the only candidate benchmarkable in-workspace.
- Poulpy remains the fallback/watchlist backend: promising modular HAL, but current public stack is nightly-only and torus/bivariate rather than the required fixed 4x60-bit RNS adapter surface.
- Recorded pinned SHAs: poulpy 4a1f0c642cef7e5830287c3d6af7e013d8a7bda4, fhe.rs 5f24d0b62a7329b789db07a065b68accd614a47b; benchmark JSON saved at bench/results/backend-compare-2026-05-02.json.

## [2026-05-02] Task: T11
- Noir 1.0.0-beta.20 supports `#[test(should_fail)]`, which is sufficient for RED-first tamper coverage on the RLWE relation circuit.
- `nargo info --package rlwe_relation` reports ACIR opcodes cleanly; the toy coefficient-vector surrogate scaled linearly at 16/32/64 gates for logical N=512/2048/8192 envelopes.
- Canonical `nargo execute` + `bb write_vk/prove/verify` flow works directly against `circuits/target/rlwe_relation.{json,gz}`; tampered witnesses fail during execute before BB proving.
- Added explicit methodology artifact and reproduce-script stub output mapping logical N envelopes to surrogate Noir coefficient counts (16/32/64).

## [2026-05-02] Task: T12
- A lightweight NIFS-style folding simulation was sufficient to surface scaling constants without claiming a full Nova/HyperNova implementation; the benchmark explicitly measures constant-time per-fold accumulation plus a simulated final proof/verifier step.
- The fixed 8-variable R1CS surrogate kept the accumulator size flat at 280 bytes across N ∈ {16,64,256,1024}, while the simulated final proof grew only with log2(N) (320 → 512 bytes).
- The fitted log-log slope on per-fold time was -0.0058 on this host, which is effectively constant and satisfies the sub-linear acceptance check.
## [2026-05-02] Task: T13
- Implemented a simplified BN254 KZG-style batched opening verifier in `contracts/bench/KzgBatchVerifier.sol` that aggregates `(C - [v]₁)` and `π` with powers of a fixed randomizer, then checks equality with a single EIP-197 pairing call.
- Foundry gas report measured verifier-only execution at ~145k, 323k, 936k, and 3.44M gas for batch sizes 1, 8, 32, and 128 respectively; all fit under the 5M target budget, with batch-128 at ~73% of budget after calldata separation.
- Calldata contributes materially at larger batches (`3652`, `18992`, `71396`, `280772` gas by EIP-2028), so reporting total gas without subtracting calldata would overstate verifier work.
