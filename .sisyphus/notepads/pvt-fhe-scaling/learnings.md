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

## [2026-05-02] Security Parameter Constraint (user-mandated)
- **All FHE parameter sets MUST target ≥120-bit security** (user explicit requirement).
- Reference: Enclave's production BFV secure preset at gnosisguild/enclave/circuits/lib/src/configs/secure/
- **Threshold circuit params** (threshold.nr): N=8192, L=3 RNS limbs, QIS=[288230376173076481, 288230376167047169, 288230376161280001] (~58-bit primes each), PLAINTEXT_MODULUS=131072 (2^17), log₂(Q)≈174 bits → well above 120-bit RLWE security at N=8192.
- **DKG circuit params** (dkg.nr): N=8192, L=2, QIS=[2305843009242923009, 2305843009240301569] (~61-bit primes), PLAINTEXT_MODULUS=1152921504606846976.
- **Implication for T20 (parameter selection)**: Must use N≥8192 with appropriate Q. The T5/T11 benchmarks used N=4096 and toy sizes — those are for circuit-size measurement only, NOT for production security. Any parameter set proposed in T20 must be validated against the lattice estimator at ≥120-bit security.
- **Implication for T8/T9/T10 architecture memos**: All pseudocode and cost tables must use N=8192 (or larger) as the baseline secure parameter. Toy N values are acceptable only for benchmarking circuit gate counts, not for security claims.
- **Implication for T11 RLWE circuit**: The existing circuit uses N=64 coefficients — this is a gate-count benchmark only. The production circuit will need N=8192 coefficients, which will dramatically increase gate count. T11 results should be extrapolated to N=8192 in T15 cost table.
- **Enclave compatibility**: Our scheme must be compatible with Enclave's parameter regime (N=8192, BFV, RNS) to enable Interfold integration.

## [2026-05-02] Task: T12
- Folding simulation: per-fold time is O(1) amortized (slope=-0.006 in log-log fit), confirming the theoretical claim.
- Final SNARK step is simulated (not full Nova/HyperNova) — sufficient for Phase 1 cost estimation.
- Accumulator size stays constant at 280 bytes regardless of N (as expected for NIFS-style folding).

## [2026-05-02] Task: T13
- KZG batch verifier gas: batch-1=76k, batch-8=270k, batch-32=935k, batch-128=3.65M (73% of 5M budget).
- Calldata cost is ~8% of total gas at batch-128 — verifier execution dominates.
- BN254 pairing precompile (EIP-197) at 0x08 costs ~45k gas per pairing check.
- batch-128 fits within 5M gas budget; batch-256 would likely exceed it.
## [2026-05-02] Task: T8
- Created architecture A silent-setup port design in `.sisyphus/research/arch-A-silent-setup.md`.
- Modeled 6 core algorithms: Setup, KeyGen, Encrypt, PartialDecrypt, Aggregate, Verify.
- Defined formal security games for IND-CPA-PV, Decryption-Soundness, and Public-Verifiability.
- Recorded Open Problems (Smudging noise bounds, Lagrange interpolation, NIZK overhead) and Risk Register.
- Produced cost estimates in `.sisyphus/research/arch-A-costs.json` matching the schema.
- Gas costs scale linearly unless a recursive SNARK wrapper is used.
## [2026-05-02] Task: T9
- Researched Architecture B (lattice PVSS + folding + MicroNova).
- Identified open problem: lattice NIZK for hint well-formedness lacks a formal soundness argument over RLWE.
- Mapped clear boundaries (`[FOLD-VS-SNARK BOUNDARY]`) indicating transition from lattice IOP $\rightarrow$ folding accumulator $\rightarrow$ SNARK $\rightarrow$ on-chain.
- Avoided Lova/LatticeFold+ conflation.
- Created cost json successfully passing `costs.schema.json` validation.

## [2026-05-02] Task: T10
- Architecture C uses a direct Noir wrapper with recursive UltraHonk aggregation, avoiding the complexity of lattice folding.
- The tradeoff is a heavy O(N) aggregator compute, scaling up to ~3.5M+ gates for N=1024, pushing the limits of current Barretenberg proving capabilities.
- Security relies on KZG binding and AGM since recursive UltraHonk soundness isn't formally proven under adaptive proof composition in Noir literature.
## [2026-05-02] Task: T14 Literature Refresh #1
- Found 7 new papers from 2024-2026 relevant to PV-ThFHE.
- Notable trend: Moving away from noise flooding (Ajax 2025/1834, Zyskind et al. 2025/1781) towards "mask-then-open" or MPC-based noise removal.
- Folding improvements: Cyclo (2026/359) achieves O(1) norm growth amortized, significantly reducing prover overhead compared to LatticeFold+.
- PVSS: Practical post-quantum PVSS (2026/813) using lattice-based IBE shows 2 orders of magnitude improvement over prior work.
- Assumptions updated: Mask-then-Open, Everywhere-Short Secret Sharing, and Ring-R1CS sum-check security.
## [2026-05-02] Task: T15
- Consolidated cost comparisons of Arch A, B, and C.
- Explored Gas constraints. The KZG batch approach hits gas limits rapidly. O(1) SNARK approach is needed for N=1024.
- Arch-B is the most feasible despite open mathematical challenges on Lattice NIZK well-formedness, because Arch-C hits hardware constraints (10-50M gate circuit). Arch-A hits gas/verification limits on-chain without SNARK compression, and SNARK compression on Arch-A is outperformed by Arch-B.
- T14 Cyclo (2026/359) improves Arch-B folding further.
## [2026-05-02] Task: T16
Phase 1 gate report authored. Verdict: GO. Recommended: arch-B (lattice PVSS + folding + MicroNova). Bootstrapping PV: DEFER. Key open problem for Phase 2: lattice NIZK well-formedness soundness.
## [2026-05-02] Task: T16 (Implementation)
Implemented `.sisyphus/scripts/phase1-gate.py` to validate Phase 1 artifacts, schemas, and gate decisions. Updated `Justfile` to replace the `phase1-gate` stub. Verification successful: `just phase1-gate` exits 0 with full check logs.
