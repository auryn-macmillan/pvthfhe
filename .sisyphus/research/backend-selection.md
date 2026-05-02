# Backend Selection: Poulpy vs gnosisguild/fhe.rs

## Executive Summary

Recommendation: use **gnosisguild/fhe.rs** as the primary backend for the PVTHFHE research artifact and keep **Poulpy** as the fallback/watchlist backend.

Why: fhe.rs already exposes the closest match to the required Rq/RNS/NTT layer on stable Rust, includes an in-tree threshold BFV path with share serialization, and was the only candidate that could be wired into the benchmark harness and executed in this workspace. Poulpy is architecturally promising, but its torus/bivariate HAL and nightly-only toolchain are a feature gap for the fixed `N=4096`, `4 x 60-bit RNS` benchmark contract used here.

## Evaluation Axes

### Schemes supported

- **Poulpy**: repo README describes a torus-oriented, backend-agnostic stack with `poulpy-ckks` and `poulpy-bin-fhe`; README also frames the architecture as aiming to unify RLWE families such as TFHE/FHEW/BGV/BFV/CKKS through a common plaintext space, but the currently exposed crates are CKKS and binary FHE, not a ready BFV/BGV RNS stack.
- **gnosisguild/fhe.rs**: README explicitly ships an RNS variant of **BFV**. The fork also carries a `trbfv` module for threshold BFV based on ePrint 2024/1285.

### API stability

- **Poulpy**: README and changelog both call out API churn (`poulpy-ckks` first iteration, API subject to change). The HAL is modular, but the crate currently requires nightly.
- **gnosisguild/fhe.rs**: README labels the project **beta** with possible breaking changes before 1.0. Still unstable, but the exported `fhe-math::{ntt,rns,rq,zq}` layering is already directly usable for the benchmark adapter.

### NTT/RNS quality

- **Poulpy**: high-quality low-level arithmetic story, but centered on torus/bivariate arithmetic and HAL backends such as `FFT64Ref` and `NTT120Ref` (CRT over four ~30-bit primes), not the requested `4 x 60-bit` RNS basis. Good architectural fit for acceleration work, poor apples-to-apples fit for this benchmark contract.
- **gnosisguild/fhe.rs**: `fhe-math` exposes `ntt::NttOperator`, `rq::Context`, and `rq::Poly` over explicit prime moduli. This matched the requested `N=4096` / `4 x 60-bit` RNS benchmark harness directly.

### PRNG hygiene

- **Poulpy**: `poulpy-hal::source::Source` uses deterministic **ChaCha8** and documents that it is for reproducible sampling/benchmarks rather than cryptographic key generation.
- **gnosisguild/fhe.rs**: `fhe-math` also uses **ChaCha8Rng** in math/sampling paths. For benchmark determinism this is adequate and easy to seed.

### Serialization

- **Poulpy**: workspace uses `byteorder`; docs.rs notes little-endian binary serialization and warns that format stability is not guaranteed across minor versions.
- **gnosisguild/fhe.rs**: math/scheme crates use `serde`, `bincode`, and `prost`; the `trbfv` module explicitly provides `serialize_secret_share`, `serialize_decryption_share`, `serialize_smudging_data`, and matching deserializers.

### no_std/wasm potential

- **Poulpy**: hardware-abstraction design is attractive long-term for alternative targets, but current crates are std/nightly-oriented and not ready for this workspace’s stable baseline.
- **gnosisguild/fhe.rs**: also std-oriented; no immediate `no_std` advantage observed. Neutral for this task.

### License

- **Poulpy**: **Apache-2.0**.
- **gnosisguild/fhe.rs**: **MIT**.

Both are acceptable for research use. MIT is slightly simpler for downstream embedding; Apache-2.0 gives clearer patent language. License is not the deciding axis.

### Maturity (commits, contributors, last release)

- **Poulpy**: repository page showed ~635 commits, latest visible release `v0.5.0` on 2026-03-31, cloned HEAD `4a1f0c642cef7e5830287c3d6af7e013d8a7bda4`, latest commit dated 2026-04-30. Exa metadata reported 4 named contributors.
- **gnosisguild/fhe.rs**: repository page showed ~468 commits, no GitHub release page for the fork, cloned HEAD `5f24d0b62a7329b789db07a065b68accd614a47b`, latest commit dated 2026-04-15. Exa metadata reported a broader contributor set due to fork ancestry.

Operationally: Poulpy looks newer/faster-moving; fhe.rs looks older but more directly consumable for RNS math.

### Test coverage

- **Poulpy**: benchmark/test macros and reference backend structure suggest serious internal testing discipline.
- **gnosisguild/fhe.rs**: CI/codecov badges are present; math and threshold modules include unit tests and examples. This was sufficient for adapter integration.

### Benchmark numbers

Only **gnosisguild/fhe.rs** could be benchmarked under the task’s exact stable-workspace constraints. Poulpy is a feature gap for this apples-to-apples benchmark because `poulpy-hal` requires `#![feature(trait_alias)]` on nightly and its exposed backend arithmetic is not the required `4 x 60-bit` RNS interface.

Results from `bench/results/backend-compare-2026-05-02.json` (`n_runs = 12`, single machine, same workspace, same binary):

| Case | Backend | Median ns | Mean ns | Stddev ns |
| --- | --- | ---: | ---: | ---: |
| `ntt_forward(N=4096,q=q0)` | fhe_rs | 1,563,922.5 | 7,238,837.3 | 18,813,302.3 |
| `ntt_inverse(N=4096,q=q0)` | fhe_rs | 2,134,030.0 | 2,134,366.8 | 6,467.7 |
| `poly_mul_ntt_domain(N=4096,RNS={q0..q3})` | fhe_rs | 15,288,035.0 | 15,288,359.2 | 51,410.1 |
| `sample_uniform_rq(N=4096,RNS={q0..q3})` | fhe_rs | 3,792,320.0 | 3,804,534.2 | 58,883.6 |

Interpretation: fhe.rs is benchmarkable now, but the forward-NTT variance suggests warm-up/system noise sensitivity; treat the first run as exploratory rather than publication-grade.

### Threshold-friendliness

- **Poulpy**: roadmap/docs mention threshold HE primitives as future work, but no concrete secret-share-friendly keygen/transcript API was found in the current public crates.
- **gnosisguild/fhe.rs**: `trbfv` already includes threshold decryption flow, share aggregation, share serialization, and coordinator types. Caveat: the README says the current implementation is **passively secure**, omits PVSS, and currently omits relinearization-key generation.

### Audit history

- **Poulpy**: security policy exists, but no independent audit claim found.
- **gnosisguild/fhe.rs**: README explicitly states the implementation has **never been independently audited**.

## Feature Gaps Encountered

### Poulpy

1. **Toolchain gap**: `cargo check -p pvthfhe-bench --features backend-poulpy` failed on stable because `poulpy-hal` uses `#![feature(trait_alias)]`; Poulpy pins `nightly-2026-03-21`.
2. **Representation gap**: exposed arithmetic is torus/bivariate HAL (`FFT64Ref`, `NTT120Ref`) rather than the benchmark’s fixed `4 x 60-bit` RNS ring interface.
3. **Threshold gap**: no concrete secret-share-friendly keygen / threshold transcript API found in the current public crates.

### gnosisguild/fhe.rs

1. **Stability gap**: still beta and pre-1.0.
2. **Security gap**: no independent audit claim.
3. **Threshold gap**: threshold path is passive-security only and not yet publicly verifiable.

## Benchmark Results

Raw JSON lines live in `bench/results/backend-compare-2026-05-02.json`.

Environment capture from the harness exists, but the current JSON-line output records only per-case statistics. For later reproducibility work, extend the schema to include environment metadata per run or in a sidecar file.

## Recommendation

Choose **gnosisguild/fhe.rs** as primary.

This recommendation is justified by at least these three axes:

1. **API fit**: fhe.rs already exposes raw `NTT`, `RNS`, and `Rq` operators compatible with the required benchmark abstraction.
2. **Threshold-friendliness**: fhe.rs already has a threshold BFV path with share/decryption serialization, which is materially closer to PVTHFHE needs than Poulpy’s current roadmap-only threshold story.
3. **Execution evidence**: fhe.rs was the only backend successfully integrated and benchmarked inside this workspace without breaking `cargo check --workspace` on stable.

Secondary support:

4. **Serialization** is more complete for distributed threshold experiments.
5. **Scheme alignment**: BFV + threshold BFV are directly relevant to the 2024/1285 baseline and downstream PVTHFHE tasks.

## Fallback Plan

Switch to **Poulpy** if any of the following happen:

- Poulpy lands a stable-compatible arithmetic surface or this workspace moves to a pinned nightly toolchain.
- Poulpy exposes a direct RNS/Rq adapter or an equivalent low-level threshold-friendly interface that removes today’s representation mismatch.
- fhe.rs threshold support stalls at passive security while Poulpy ships stronger threshold/PVSS-oriented primitives.

Until then, keep Poulpy as a watchlist backend rather than a production dependency in the research artifact.

## Risk Register

- **fhe.rs passive threshold security**: current threshold support is not enough for final malicious/publicly verifiable goals.
- **fhe.rs pre-1.0 churn**: adapter code may need updating as APIs move.
- **benchmark variance**: current forward-NTT measurements show high variance; repeat with warm-up/affinity before publishing comparative claims.
- **Poulpy missed upside**: by not choosing Poulpy now, we may defer a stronger long-term acceleration architecture.

## Pinned Commit SHAs

- poulpy: `4a1f0c642cef7e5830287c3d6af7e013d8a7bda4`
- gnosisguild/fhe.rs: `5f24d0b62a7329b789db07a065b68accd614a47b`
