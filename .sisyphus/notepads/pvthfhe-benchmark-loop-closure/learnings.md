# Learnings — pvthfhe-benchmark-loop-closure

## 2026-05-06 Session bootstrap

### Codebase state
- `crates/` members: pvthfhe-{core,fhe,circuits,aggregator,keygen-spec,keygen,cli,bench,api,enclave-adapter,nizk,cyclo,micronova}
- `crates/pvthfhe-compressor` — does NOT exist yet (Phase S)
- `crates/pvthfhe-pvss` — does NOT exist yet (Phase P)
- `crates/pvthfhe-circuit-tests` — does NOT exist yet (Task N0)
- `circuits/` packages: aggregator_final, decrypt_share, micronova_wrap, share_wf, bench, tests (tmp_poseidon_calc)
- `tests/` directory — does NOT exist yet (created by X2)
- `parameters.toml` — does NOT exist yet (X1 must create/fix it)
- `Justfile` exists; no prereq-gate/wire-gate/compressor-gate/noir-onchain-gate/pvss-gate/bench-comparison-gate yet

### Spec ring degree issue (X1)
- `spec-real-p2p3.md` line 75: `N=8192` (production RLWE parameter)
- `spec-real-p2p3.md` lines 200-204: `RLWE_N=1024` (illustrative sigma_proof_bytes sizing)
- Line 699 also confirms `RLWE ring degree N = 8192`
- Decision: N=8192 is the **canonical** ring degree; RLWE_N=1024 at line 200-204 is illustrative sizing example

## 2026-05-06 X2 policy invariants

- Root `Cargo.toml` can host a second `[[test]]` target for repo-wide policy checks; `cargo test --test policy_invariants` works from repo root.
- The policy invariants test should use `env!("CARGO_MANIFEST_DIR")` plus filesystem traversal to assert repo-wide strings without touching implementation files.
- Current policy baselines verified by the test: Stage-0 mock banner in `crates/pvthfhe-fhe/build.rs`, mock env guard in `crates/pvthfhe-aggregator/src/keygen/simulator.rs`, only `crates/pvthfhe-core/tests/vectors.rs` contains `#[allow(...)]`, and forbidden `nargo prove` / `nargo verify` strings remain absent from `bench/scripts/*.sh` and `Justfile`.

### Policy
- TDD strict: RED test committed before implementation
- No new `#[allow(...)]` anywhere
- `cargo ... -p <crate>` from repo root
- Forbidden: `nargo prove`, `nargo verify`
- Stub protocol: replace in place, never delete-and-recreate
- Plan files read-only for sub-agents; only orchestrator marks checkboxes

## 2026-05-06 W3 bench_scaling real backend wiring

- After W2, `pvthfhe_aggregator::folding::FoldingAccumulator` and `PartyProof` are no longer available in default builds; `pvthfhe-bench` bins that referenced them must migrate to the real-folding-safe path (`CycloFoldingAdapter` + `CcsPShareInstance`) or avoid folding entirely.
- For the W3 RED test, the fastest reliable behavior is a true `--dry-run` branch in `bench_scaling` that still emits the required backend disclosure lines on stderr (`backend_id`, `nizk_backend_id`, `folding_backend_id`, `compressor_backend_id`) but skips heavy pipeline execution so the spawned process exits comfortably within the 2-second harness timeout.
- W3's benchmark JSON shape fits naturally in `pvthfhe_bench::ScalingEnvelope`; extending that shared struct with `backend_id`, `nizk_backend_id`, `folding_backend_id`, `compressor_backend_id`, `t`, `seed`, and `env.cpu_cores`/`env.mem_kb` keeps both serialization checks and binary output aligned.
- `gen_goldens.rs` also depended on the old hash-chain folding types, so `cargo test -p pvthfhe-bench` required migrating that bin as well; otherwise the crate still fails to compile even if `bench_scaling.rs` is fixed.

## 2026-05-06 X1 spec consistency

- Root `Cargo.toml` can host a minimal package plus `[[test]]` target, which makes `cargo test --test spec_consistency` work from repo root without adding a new workspace crate.
- The spec consistency guard should check both the canonical source (`parameters.toml [rlwe]`) and inline tagging rules for any non-production ring-degree mention.
- The `RLWE_N=1024` occurrence in `.sisyphus/design/spec-real-p2p3.md` is now explicitly marked `(illustrative)` both in the decision-record paragraph and in the sizing example itself so the policy is machine-checkable.

## 2026-05-06 W1 run_demo NIZK wiring

- `run_demo` can layer the W1 prove/verify accounting on top of the existing keygen simulator transcript: one proof per dealer maps cleanly to `round1_messages`, and verifier-side work can be counted by iterating all `(dealer, peer)` pairs from `participant_set` except self.
- For the new CLI integration test, spawning `cargo run -p pvthfhe-cli -- demo ...` and counting tracing markers from the combined captured output is more robust than checking stderr alone under `cargo test`, because the harness may surface runtime tracing on stdout while compiler warnings still arrive on stderr.
- Printing `backend_id == "cyclo-ajtai-d2-conditional"` in the keygen banner satisfies the plan's no-silent-fallback requirement without changing the existing P2/P3 banner lines.

## 2026-05-06 W4 e2e binary wiring

- Adding a second binary to `pvthfhe-cli` changes `cargo run -p pvthfhe-cli -- ...` behavior unless the package sets `default-run = "pvthfhe-cli"`; preserving the existing demo-oriented integration tests requires that manifest pin.
- The W4 RED harness expects the executable name `pvthfhe-e2e`, so the new bin needs an explicit `[[bin]]` entry with `name = "pvthfhe-e2e"` even though the source file is `src/bin/pvthfhe_e2e.rs`.
- For the current pre-S3 state, a lightweight in-crate compressor scaffold can satisfy the phase-coverage contract by deterministically hashing Cyclo fold outputs while still surfacing a startup warning and a stable `compressor_backend_id` in tracing/output.
- A reserved future feature should fail closed rather than advertise an unimplemented backend: for W4, `sonobe-compressor` now compile-errors until Phase S3 instead of silently reusing the surrogate scaffold under a Sonobe-looking backend id.

## 2026-05-06 W5 bench-comparison JSON shape

- A minimal W5 green path can emit the Interfold-shaped comparison envelope before real timing integration, as long as it preserves the exact top-level keys (`circuit_timings`, `phase_totals`, `hardware`, `backend_ids`, `commit_sha`, `comparison_target`) and every one of the 12 Interfold circuit names in order.
- The RED test is easiest to keep stable by invoking `just bench-comparison-dryrun 3 1 1` from the repo root and asserting `bench/results/comparison-dryrun.json`; this mirrors the plan verbatim and catches both missing Just recipes and missing bench binary wiring.
- For pre-Phase-P / pre-Phase-N rows, `null` timing/size fields plus `status = "n/a"` and an explicit `gap_reason` satisfy the comparison-shape contract without pretending parity that does not yet exist.

## 2026-05-06 W6 wire-gate RED evidence

- `just wire-gate` is currently missing from the Justfile and exits non-zero with: `error: Justfile does not contain recipe \`wire-gate\``.
- Verified from the repo root with: `just wire-gate >/tmp/wire_gate_red.txt 2>&1`.
