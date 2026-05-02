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
