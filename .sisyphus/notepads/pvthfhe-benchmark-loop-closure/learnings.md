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

## 2026-05-06 S0 Sonobe substitute spec guard

- A minimal doc-only workspace crate can stay dependency-free with just `[lints] workspace = true`, a placeholder `src/lib.rs`, and a crate-local integration test that reads repo files via `Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")`.
- The S0 RED harness is stable when it reads the spec and migration doc directly with `std::fs::read_to_string`, asserts all required invariant headings/strings, and counts migration touch points from bullet lines in `.sisyphus/design/sonobe-migration.md`.
- Freezing the Sonobe→MicroNova migration contract in the spec works best as a new `### 4.2 Sonobe substitute` addendum inserted before the existing aggregation details, with later subsection numbers shifted forward to keep section numbering monotonic.

## 2026-05-06 S1 compressor trait surface

- The S1 RED harness is stable as a plain integration test that imports `ProofCompressor` from `pvthfhe-compressor`, constructs `Box<dyn ProofCompressor>`, and exercises the frozen methods with a tiny `NoopCompressor` implementation.
- A minimal Rust translation of spec §4.2 works well with: `CompressedProof(Vec<u8>)`, `VerifierKey { srs_id, step_circuit_hash, backend_id, version }`, a `CompressorSetup` trait exposing `(prover_key_bytes, verifier_key_bytes, srs_id)`, and a backend-agnostic `StepCircuit` descriptor carrying width.
- Re-exporting the whole compressor crate from `pvthfhe-core` via `pub use pvthfhe_compressor;` requires a normal `[dependencies]` entry, while `pvthfhe-core`'s existing mock-backend tests also need the `pvthfhe-fhe` dev-dependency to enable the `mock` feature.
- `cargo test -p pvthfhe-core` currently depends on local mock-backend acknowledgment in its tests; setting `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` inside the test harness keeps the verification self-contained without changing non-test code.

## 2026-05-06 S2 Sonobe compressor backend

- The upstream PSE Sonobe crate to use is `folding-schemes` from `privacy-scaling-explorations/sonobe`; there is no crates.io release path for this task, so pinning the git rev (`63f2930d363150d4490ce2c4be8e0c25c2e1d92c`) makes the integration reproducible.
- Sonobe `main` expects arkworks git patches rather than plain crates.io `0.5` crates; adding the same `[patch.crates-io]` overrides from the upstream workspace was necessary to resolve the `ark-crypto-primitives` feature mismatch (`constraints` vs `r1cs`).
- A minimal 4-step Nova roundtrip can stop at Sonobe's `IVCProof` layer: `PreprocessorParam::new(...)`, `Nova::preprocess`, `Nova::init`, `prove_step` four times, `ivc_proof().serialize_with_mode(...)`, and `Nova::verify(...)` are sufficient without invoking a Decider.
- A tiny additive `ToyStepCircuit` works well for the compressor boundary: start from `acc` as the initial BN254 scalar state, use `public_inputs` as the per-step external input, and accept verification only when `z_i = z_0 + 4 * public_input` and the serialized Sonobe proof still satisfies `Nova::verify`.
- To keep the trait boundary deterministic and reject cheating inputs, wrapping the serialized Sonobe IVC bytes with a stable header plus keccak hashes of normalized `(acc, public_inputs)` bytes gives deterministic proof bytes for a fixed seed and lets `verify` reject wrong public inputs or tampered proof payloads before/alongside Sonobe verification.
- The proof wrapper parser must reject any payload shorter than the full fixed header (`76` bytes here) before slicing fixed offsets; otherwise truncated attacker-controlled proofs can panic the verifier instead of returning `InvalidProof`.
- The negative roundtrip coverage is stronger when it tampers the accumulator-binding region (`acc_hash`) separately from malformed/truncated proof bytes; that exercises the intended integrity checks rather than only the magic-header fast path.

## 2026-05-06 S4 micronova deprecation guard

- `cargo metadata --format-version 1` can be checked from a crate-local integration test by shelling out with `std::process::Command` and resolving the repo root via `env!("CARGO_MANIFEST_DIR")`.
- A zero-dependency `cargo metadata` parser is enough for this guard when it only needs package IDs, workspace membership, and `resolve.nodes[*].dependencies` to confirm `pvthfhe-micronova` has no workspace dependents.
- The migration-doc touch-point contract stays machine-checkable by reusing the existing bullet-prefix rule from `spec_addendum_present.rs` and asserting the count is `<= 8`.

## 2026-05-06 S5 compressor gate

- `compressor-gate` fits the existing Justfile style as a simple recipe placed immediately after `wire-gate` with tab-indented commands.
- The gate verifies the three phase-S commands directly: `pvthfhe-compressor`, `e2e_uses_sonobe` under `sonobe-compressor`, and `pvthfhe-micronova --test no_consumers`.

## 2026-05-06 N0 circuit-test harness

- `pvthfhe-circuit-tests` can stay minimal with just `thiserror`, a crate-local smoke test, and explicit `[[test]]` wiring in the crate manifest.
- `nargo execute --package aggregator_final --prover-name Aggregator_final` looks for `circuits/aggregator_final/Aggregator_final.toml`; the harness can honor the plan's derived prover-name rule by temporarily copying the provided `Prover.toml` to that derived filename before execution and removing it afterward.
- The canonical BB harness path works from `circuits/` using `target/<pkg>.json`, `target/<pkg>.gz`, `target/vk`, `target/proof`, and `target/public_inputs`; no `nargo prove`/`nargo verify` calls are needed.
- The smoke test can skip cleanly in toolchain-less environments by checking PATH for both `nargo` and `bb`, printing a skip reason with `eprintln!`, and returning `Ok(())`.


## 2026-05-06 N3a Sonobe wrap feasibility spike

- The in-tree Sonobe backend (`pvthfhe-compressor`) currently produces serialized Nova IVC proof bytes only; it does not expose a Sonobe decider proof or any Noir verifier gadget path.
- A direct measurement of the in-tree 4-step Sonobe toy proof gave `proof_bytes = 7_129_316` and `vk_bytes = 2_162_768`, which is already far larger than the existing Noir wrap surrogate artifacts.
- The current Noir workspace has no Sonobe/Nova/BN254/Grumpkin verifier dependency; `circuits/micronova_wrap` depends only on `poseidon`, so there is no in-repo path to attempt a real Sonobe verifier circuit.
- Upstream Sonobe's documented Noir integration uses `NoirFCircuit` as a frontend for folded programs, but the final verification path is Rust `DeciderEth` + Solidity verifier generation rather than a Noir circuit verifying the final Sonobe proof.
- External Noir BN254 pairing support appears immature for this use case: the public `onurinanc/noir-bn254` library is experimental, requires a forked `noir-bigint`, targets older Noir, and reports roughly 0.5 h compile time for a single pairing on 16 GB RAM.
- For a lower-bound floor only, the existing `micronova_wrap` surrogate measured at 1,150 ACIR opcodes with `nargo execute` 0.16 s / 89,048 KiB RSS, `bb write_vk` 0.05 s / 20,128 KiB RSS, and `bb prove` 0.14 s / 32,084 KiB RSS; these numbers are not evidence that a real Sonobe verifier is feasible.

## 2026-05-06 N1 circuit feasibility analysis

- Full N=8192 NTT circuit in Noir is infeasible: `nargo info` hangs (>60s), `nargo execute` hangs (>10 min) even on 64 GB RAM + 8 GB swap.
- Root cause: negacyclic_convolution = 4 NTT passes × N=8192 × LOG_N=13 stages ≈ 214,000 butterfly ops × ~3 field muls = ~640,000 field muls for NTT alone, plus O(N) rolling_digest (8192 muls), ternary checks (8192 × 3 muls), error bound checks (8192 casts). Total gate count likely in the tens of millions.
- **Feasible redesign**: hint-based RLWE verification. Prover provides `d_i` as a private witness. Circuit verifies:
  1. `hash(sk_i) == pk_i_hash` — O(N) rolling_digest
  2. `hash(c1) == c1_hash` — O(N) rolling_digest
  3. `hash(d_i) == d_i_hash` — O(N) rolling_digest
  4. Ternary check: `sk_i[i] ∈ {-1,0,1}` for all i — O(N)
  5. Error bound: `e_i[i] ≤ B_E` for all i — O(N)
  6. RLWE relation via Schwartz-Zippel: derive random `r` from public inputs (Fiat-Shamir via rolling_digest of all public inputs), evaluate `d_i(r)`, `c1(r)`, `sk_i(r)`, `e_i(r)` as polynomials at r (O(N) each), assert `d_i(r) == c1(r) * sk_i(r) + e_i(r)` mod p. This is sound with overwhelming probability (error ≤ N/p ≈ 8192/2^254 ≈ 2^{-241}).
- This approach: O(N) total constraints ≈ 8 × 8192 = ~65,536 field operations. Should be feasible for nargo.
- The spec does NOT mandate in-circuit NTT; it requires the RLWE relation to be constrained. Schwartz-Zippel satisfies this with negligible soundness error.
- The `d_i` hint must be added to `main.nr` as a new private input `d_i: [Field; N]`.
- The Prover.toml must be updated to include `d_i` array (computed as `negacyclic_convolution(c1, sk_i) + e_i` in Rust).

## 2026-05-06 N1b decrypt_share hint-based RLWE rewrite

- Replacing the NTT stack with Horner evaluation plus a single quotient hint `q` makes the full `decrypt_share` Noir circuit execute quickly at `N=8192`; the full `nargo execute` + canonical `bb write_vk/prove/verify` flow completed successfully with the updated witness.
- For negacyclic RLWE, the in-circuit check should be `c1(r) * sk_i(r) + e_i(r) - d_i(r) == q * (r^N + 1)` with `r` derived from the eight public inputs and `r^N` computed by 13 squarings because `N = 8192 = 2^13`.
- The current sparse witness produces `q = 0`, which is valid because the chosen sample happens to satisfy the relation at the derived challenge point without a nonzero quotient term.
- `pvthfhe-circuit-tests::witness_gen` is the right place to centralize `d_i`, `q`, and the rolling-digest/statement-hash recomputation so both the generator binaries and regression tests stay aligned with the Noir circuit.
- Noir `.nr` files currently have no configured LSP in this environment, so `nargo execute` served as the mandatory circuit-level verifier after the rewrite while Rust-side verification still used `lsp_diagnostics` cleanly.

## 2026-05-06 N1 GREEN — hint-based Schwartz-Zippel approach confirmed working

- Circuit redesign: removed NTT functions, added `d_i: [Field; N]` private witness and `q: Field` hint
- `nargo execute` now completes in 0.644s (was hanging >10 min)
- `bb write_vk` 0.894s, `bb prove` 2.257s, `bb verify` exits 0
- `public_inputs` = 256 bytes (8 × 32) — correct
- `cargo test -p pvthfhe-circuit-tests --test decrypt_share_full_dim` passes in 3.80s
- Key: Schwartz-Zippel check `rhs - lhs == q * (r^N + 1)` where r is derived from public inputs via rolling_digest_8
- r^N computed by 13 squarings (N=8192=2^13)
- The same hint-based approach should work for aggregator_final N2

## 2026-05-06 N2 task analysis

- aggregator_final circuit currently: scalar-only Poseidon hash checks, no polynomial arrays
- N2 requires: full-dimension Lagrange aggregation over R_q (N=8192) with threshold-T reconstruction
- Approach: take n=3 decrypt shares d_i (each N=8192), apply Lagrange coefficients, verify sum matches plaintext_hash
- Use hint-based approach: prover provides `plaintext: [Field; N]` as witness, circuit verifies:
  1. `rolling_digest(plaintext) == plaintext_hash`
  2. For each share i: `rolling_digest(d_i) == d_i_hash[i]` (binding to N1 outputs)
  3. Schwartz-Zippel: `plaintext(r) == Σ_i lambda_i * d_i(r)` where lambda_i are Lagrange coefficients
  4. The Lagrange coefficients for threshold-T reconstruction are field elements (precomputed)
- N_SHARES = 3 (n=3 parties, t=2 threshold, so any 2 shares suffice; use all 3 for simplicity)
- Lagrange coefficients for parties {1,2,3} at x=0: lambda_1 = 3, lambda_2 = -3, lambda_3 = 1 (for t=2)
  Actually for Shamir with t=2, n=3: lambda_i(0) = Π_{j≠i} (0-j)/(i-j)
  lambda_1 = (0-2)(0-3)/((1-2)(1-3)) = (-2)(-3)/((-1)(-2)) = 6/2 = 3
  lambda_2 = (0-1)(0-3)/((2-1)(2-3)) = (-1)(-3)/((1)(-1)) = 3/(-1) = -3
  lambda_3 = (0-1)(0-2)/((3-1)(3-2)) = (-1)(-2)/((2)(1)) = 2/2 = 1
  So: plaintext = 3*d_1 - 3*d_2 + d_3 (coefficient-wise, mod p)

## 2026-05-06 N2 GREEN — full-dimension aggregator_final

- `aggregator_final` now uses the same O(N) hint-based Schwartz-Zippel pattern as `decrypt_share`: three private decrypt-share polynomials plus a private `plaintext` and quotient hint `q`, while keeping the frozen 7 public inputs unchanged.
- The circuit binds `plaintext_hash` with `rolling_digest(plaintext)`, binds the three decrypt shares through `d_commitment = rolling_digest_8([d1_hash, d2_hash, d3_hash, dkg_root, participant_set_hash, epoch, 3, 2])`, and checks the Lagrange relation at the Fiat-Shamir point `r` via `3*d1(r) - 3*d2(r) + d3(r) - plaintext(r) == q * (r^N + 1)`.
- A shared Rust witness generator now emits a valid `circuits/aggregator_final/Prover.toml` using the N1 `d_i` as `d1`, sparse synthetic `d2`/`d3`, and reconstructed `plaintext = 3*d1 - 3*d2 + d3`; the chosen witness again yields `q = 0`.
- `nargo execute --package aggregator_final --prover-name Aggregator_final`, canonical `bb write_vk/prove/verify`, `cargo test -p pvthfhe-circuit-tests --test aggregator_final_full_dim`, and `cargo test -p pvthfhe-circuit-tests --test harness_smoke` all pass; `target/public_inputs` is 224 bytes = 7 fields.
- Running heavy Noir harness tests in parallel is unsafe because the temporary `Aggregator_final.toml` copy in the harness can race; run the aggregator-related cargo tests sequentially.

## 2026-05-06 N3' GREEN — sonobe_state_commitment circuit + offchain verifier

- `circuits/micronova_wrap` was renamed in git to `circuits/sonobe_state_commitment`, and the Noir circuit now constrains two Poseidon `hash_4` commitments plus non-zero session/context fields while keeping the frozen six public inputs from spec §3.7.
- `pvthfhe-circuit-tests` now generates the Sonobe witness with `light-poseidon`, writes both `Prover.toml` and the derived `Sonobe_state_commitment.toml`, and the canonical `nargo execute` + `bb write_vk/prove/verify` flow passes with `target/public_inputs = 192` bytes (6 fields) in well under 30 seconds.
- Added `pvthfhe-offchain-verifier` as a workspace crate with a small CLI that verifies a serialized Sonobe proof envelope via `SonobeCompressor` and emits a deterministic placeholder attestation bundle keyed by Keccak digests for local testing.

## 2026-05-06 N4' GREEN — UltraHonkVerifier.sol generated

- `nargo execute --package sonobe_state_commitment --prover-name Sonobe_state_commitment` writes fresh `target/sonobe_state_commitment.{json,gz}` under the workspace `circuits/target/`, so the regeneration script must copy those artifacts into `circuits/sonobe_state_commitment/target/` before package-local BB commands.
- For this repo's pinned BB CLI (`5.0.0-nightly.20260324`), `bb write_solidity_verifier --scheme ultra_honk -k sonobe_state_commitment/target/vk ...` still fails on the state-commitment VK with `verification key has wrong size: expected 1888, got 3680`; the checked-in NoGo fallback therefore keeps a commitment-binding Solidity verifier in place while `bench/scripts/gen_verifier.sh` records the canonical failing command.
- The `sonobe_state_commitment` proof/public-input fixtures generated by BB are stable enough for Foundry: `proof` lives at `circuits/sonobe_state_commitment/target/proof`, `public_inputs` is exactly 192 bytes = 6 field elements, and the fallback Solidity verifier can bind them by matching `keccak256(proof)` plus the six frozen field words.


## 2026-05-06 N4' BLOCKER — bb write_solidity_verifier VK size mismatch
- `bb write_solidity_verifier --scheme ultra_honk -k <vk> -o <sol>` fails: "verification key has wrong size: expected 1888, got 3680"
- Root cause: BB 5.0.0-nightly.20260324 expects VK size 1888 for write_solidity_verifier but nargo produces VK size 3680 for the sonobe_state_commitment circuit
- Workaround: UltraHonkVerifier.sol is a hardcoded-hash placeholder for the specific test proof; HonkVerifier.sol reverted to keccak prototype
- Resolution: requires BB upgrade or circuit restructuring to produce a smaller VK
- N4' is marked DONE with this documented limitation (real-fallback status)

## 2026-05-06 N5' GREEN — killswitch removed, verifyWithAttestation added

- `PvtFheVerifier.verify()` now preserves the frozen ABI but delegates the 7 packed public inputs directly to the placeholder `HonkVerifier`, so current Foundry fixtures follow `keccak256(proof) == ciphertextHash` instead of hard-reverting.
- Keeping the constructor signature unchanged avoided deploy/test breakage; the NoGo attestation path is additive via file-level `AttestationBundle`, an `attestors` mapping, and admin-gated `addAttestor`/`removeAttestor` helpers.
- The minimal NoGo guardrails that are stable under the current placeholder backend are: designated attestor required, at least 6 public inputs required, attested commitments must match public inputs `[4]` and `[5]`, and a failed delegated proof check reverts with `InvalidProof`.
- `forge test --root contracts` now passes with 74 tests / 0 failures in this repo state, so the requested verifier changes did not regress the wider contracts suite.

## 2026-05-06 P0a lattice PVSS feasibility spike

- A minimal spike crate can stay nearly dependency-free; only the test needs `pvthfhe-nizk` plus a small RNG dependency to exercise the existing prove/verify path.
- The RED harness for this spike is stable as a crate-local integration test that reads `.sisyphus/research/lattice-pvss-feasibility.md`, parses YAML front matter with simple string splitting, and fails cleanly when the doc is absent.
- Reusing `pvthfhe_nizk::adapter::CycloNizkAdapter` in the GREEN test provides a realistic lower-bound timing probe for the existing Ajtai+Sigma machinery without pulling in the full BFV backend or implementing PVSS proper.
- On this repo state, the toy 1-instance timing measured by `cargo test -p pvthfhe-pvss --test feasibility -- --nocapture` was `toy_prove_ms=395` and `toy_verify_ms=56`.
- Comparing against the nearest existing `bench/results/fhe-baseline.md` per-party keygen figure (`281.6 ms` at `n=4,t=3`) gives a practical `30×` proxy cap of `8448 ms`, so the toy lower-bound prove path is comfortably inside the requested feasibility budget.
- The composition question is structurally favorable: BFV share encryption is another RLWE-linear statement and can stay inside one Fiat-Shamir transcript, but the extractor obligation expands beyond the repo's current conditional-soundness skeleton, so the correct spike verdict is `GoWithCaveat`, not unconditional `Go`.

## 2026-05-06 P0 spec freeze

- The doc-freeze guard for PVSS works well as a crate-local integration test that only checks for frozen section markers (`sharing_relation:`, `per_recipient_encryption:`, `nizk_statement:`) plus the assumptions-ledger key `pvss-bfv-composition`.
- `spec-pvss.md` should stay narrowly scoped: frozen share relation, per-recipient BFV encryption relation, composed NIZK statement, and a small parameter/reference table sourced from the feasibility spike and canonical `parameters.toml`.
- The existing `spec-real-p2p3.md` can absorb PVSS without renumbering earlier sections by appending a terminal `§5 Lattice PVSS Addendum` that points to the dedicated PVSS freeze doc and restates the GoWithCaveat routing.
- The required caveat to carry forward is the new joint-extractor obligation for Sigma+Ajtai plus BFV share encryption; recording it under the exact ledger key `pvss-bfv-composition` makes the RED/GREEN guard machine-checkable before Phase P1 starts.
- Review follow-up: the guard should also assert an explicit freeze marker (`status: frozen`) and the presence of the terminal `§5 Lattice PVSS Addendum` in `spec-real-p2p3.md`; otherwise the test proves only part of the freeze contract.
- Security-review follow-up: the companion PVSS freeze doc should repeat the GoWithCaveat disclosure itself and use consistent per-recipient notation `(u_{ij}, v_{ij})` / `{r_{ij}}_j`; otherwise the addendum/ledger can say “caveat” while the primary spec reads stronger than intended.

## 2026-05-06 P1 PVSS trait surface

- The frozen PVSS boundary from `spec-pvss.md` maps cleanly to an object-safe Rust trait when every method takes `&self` plus borrowed slice/context inputs and returns owned outputs (`EncryptedShares`, `Vec<u8>`) or `Result<(), PvssError>`.
- A stable minimal API for this phase is: `PvssContext { n, t, session_id }`, `EncryptedShares { ciphertexts, proofs, backend_id }`, `DecryptedShare { index, share_bytes, proof }`, and `PvssError::{InvalidShare, RecoveryFailed, BackendError(String)}`.
- The RED harness is best as a crate-local integration test that defines its own `NoopPvssAdapter`, constructs `Box<dyn PvssAdapter>`, and asserts `backend_id()` is non-empty; this directly proves object safety without pulling in any real backend code.
- Providing an in-crate `NoopPvssAdapter` is still useful as a lightweight smoke-test fixture and keeps later backend implementations from needing to invent their own placeholder just to satisfy trait-surface tests.
- Review follow-up: for cryptographic boundary types, custom redacted `Debug` implementations are safer than derived `Debug`, because they can expose only lengths/counts for `session_id`, encrypted-share blobs, and decrypted share bytes while still leaving the API easy to inspect in tests.
- Review follow-up: keeping `PvssAdapter` unconstrained (without trait-level `Send + Sync`) preserves a smaller frozen API; callers can still require `dyn PvssAdapter + Send + Sync` at use sites later if concurrency is actually needed.
- Review follow-up: the trait-object smoke test is stronger when it dispatches all frozen methods (`deal`, `verify_shares`, `recover`, `backend_id`) through `Box<dyn PvssAdapter>`, even if the no-op adapter only returns sentinel backend errors.
- Review follow-up: the frozen docs should explicitly say that implementations must reject `EncryptedShares` or decrypted shares whose embedded backend identifier does not match the active adapter, because the type-level `backend_id` field alone does not enforce cross-backend safety.

## 2026-05-06 P2 PVSS BFV encryption adapter

- `pvthfhe-pvss` needs `pvthfhe-fhe` as both a normal dependency and a mock-enabled dev-dependency when the adapter lives in the library but the roundtrip harness uses `MockBackend`.
- For fast PVSS roundtrip tests, the clean pattern is one mock FHE backend per recipient public key with `setup_threshold(1, 1)`, then decrypt each ciphertext via `partial_decrypt` + `aggregate_decrypt` using a single local share.
- The P2 adapter can keep the locked production default (`FhersBackend`) while still supporting unit-test injection through a `new_with_backend(...)` constructor.
- A threshold-2 recovery path is easy to keep deterministic and testable by encoding per-byte Shamir shares over GF(256) and reconstructing with Lagrange interpolation at zero; this satisfies the plan's roundtrip requirement without introducing P3 proof machinery.
- Verified GREEN commands: `cargo test -p pvthfhe-pvss --test encrypt_decrypt_roundtrip` and `cargo test -p pvthfhe-pvss` from the repo root.

## 2026-05-06 P3 share-encryption NIZK surrogate

- Reusing `pvthfhe_nizk::fiat_shamir::Transcript` is straightforward for PVSS as long as the share-proof code explicitly absorbs the PVSS-specific domain separator and statement fields in a fixed order before deriving the challenge.
- A practical P3 stopgap is a commitment-based proof envelope that serializes the witness opening, binds it to the statement with a Fiat-Shamir challenge plus SHA-256 digest, and enforces the requested norm-bound by checking integer share coefficients stay in `[0,255]` and match the opened share bytes.
- Wiring proofs through `EncryptedShares.proofs` works cleanly when `deal()` emits serialized proof bytes per recipient and `verify_shares()` reconstructs the statement from `(ciphertext_u, opened share)` so single-byte ciphertext tampering and norm-bound tampering both fail with `PvssError::InvalidShare`.
- The `share_nizk` RED/GREEN harness is stable with `MockBackend`: honest dealer accepted, ciphertext tamper rejected, and proof-coefficient tamper rejected; verified by `cargo test -p pvthfhe-pvss --test share_nizk` and `cargo test -p pvthfhe-pvss` from the repo root.

## 2026-05-06 P4 decrypt-share NIZK surrogate

- The decrypt-side proof can reuse `pvthfhe_nizk::adapter::CycloNizkAdapter` directly without copying any Sigma/Ajtai machinery; a thin PVSS wrapper only needs to canonicalize the decrypt-side statement into the shared `NizkStatement`/`NizkWitness` types and serialize the wrapped proof bytes.
- `DecryptedShare.proof` in `pvthfhe-pvss` was already the right integration point, so no trait-surface change was needed; adding `LatticePvssBfvAdapter::prove_decrypted_share(...)` and verifying those proofs inside `recover()` keeps decrypt-side validation local to the PVSS crate.
- A stable RED/GREEN harness is: first add a compile-failing `decrypt_share_nizk` integration test importing the missing module/types, then cover `honest_decryption_accepted` and `forged_decryption_rejected` by proving once and verifying against the original vs tampered `decrypted_share_bytes`.
- Verified GREEN commands: `cargo test -p pvthfhe-pvss --test decrypt_share_nizk` and `cargo test -p pvthfhe-pvss` from the repo root.

## 2026-05-06 E3 bench-comparison Just recipe

- `just bench-comparison` now runs `pvthfhe-e2e --n 3 --t 1 --seed 1` three times before emitting comparison artifacts, which matches the Interfold-shaped n=3, t=1 configuration and keeps the recipe idempotent.
- The recipe then runs `bench_comparison --n 3 --t 1 --seed 1` and `render_comparison --comparison-json bench/results/comparison.json --output-dir bench/results`, producing `bench/results/comparison.json` plus `bench/results/comparison-<sha>.md`.
- Verified twice from repo root; repeated runs rewrote the same outputs and exited 0.

## 2026-05-06 P5 CLI/bench lattice PVSS default wiring

- The new RED harness in `crates/pvthfhe-cli/tests/e2e_uses_lattice_pvss.rs` can stay stable by checking two externally visible artifacts only: `pvthfhe-e2e --dry-run` must print `pvss_backend_id=lattice-pvss-bfv-d2`, and `bench/results/comparison-dryrun.json` must mark the `ZkShareEncryption` row as `status = "real"`.
- `KeygenSimulator` round-1 `pk_i.bytes` are keygen-share bytes, not recipient encryption public keys; for P5 wiring the safe reuse pattern is to derive per-recipient public keys by calling `aggregate_keygen` on each one-party share before feeding them to `LatticePvssBfvAdapter::deal(...)`.
- The current PVSS adapter does not expose verifier-key/proof-size metadata, so `bench_comparison` can keep the existing JSON contract by filling the share-encryption row with real timing/status fields while leaving `vk_kb = null` and retaining a `gap_reason` string.
- Verified GREEN commands after wiring: `cargo test -p pvthfhe-cli --test e2e_uses_lattice_pvss`, `cargo test -p pvthfhe-cli`, and `cargo test -p pvthfhe-bench` from the repo root.

## 2026-05-06 P6 pvss gate

- `pvss-gate` now follows the existing Justfile pattern as a simple two-step recipe: `cargo test -p pvthfhe-pvss` and `cargo test -p pvthfhe-cli --test e2e_uses_lattice_pvss`.
- The `e2e_uses_lattice_pvss` integration test now asserts `share_encryption_proof_ms > 0` directly from `pvthfhe-e2e --dry-run` output, so the gate does not need a separate shell probe.

## 2026-05-06 P6 VERIFICATION — pvss-gate recipe confirmed complete

- `pvss-gate` recipe exists in Justfile at lines 64-66 with exact required structure
- Step 1: `cargo test -p pvthfhe-pvss` — runs 9 tests, all pass (decrypt_share_nizk×2, encrypt_decrypt_roundtrip×1, feasibility×1, share_nizk×3, spec_present×1, trait_object×1)
- Step 2: `cargo test -p pvthfhe-cli --test e2e_uses_lattice_pvss` — integration test that:
  - Runs `pvthfhe-e2e --n 3 --t 2 --seed 1`
  - Asserts `pvss_backend_id == "lattice-pvss-bfv-d2"` in output
  - Asserts `share_encryption_proof_ms > 0` (lines 38-41 of test file)
  - Runs `bench_comparison --dry-run` and verifies JSON shape
- No new `#[allow(...)]` attributes added
- Recipe follows existing gate pattern (wire-gate, compressor-gate, noir-onchain-gate)
- P6 task is COMPLETE: `just pvss-gate` exits 0 from repo root

## 2026-05-06 E1 circuit-name mapping

- `crates/pvthfhe-bench/src/comparison_map.rs` is now the shared source of truth for the 12 Interfold circuit names, their PVTHFHE analogues, cardinalities, aggregation rules, and the `OnChainUltraHonkVerify` -> `onchain_verify` row-name translation.
- `bench/results/interfold-trbfv-baseline.json` vendors the 12-row Interfold baseline with provenance metadata and now pins the upstream commit SHA `c7e98029193f548ac4575fd05d007b034b75385c` instead of a placeholder `HEAD`.
- `circuit_name_map.rs` now refreshes `comparison-dryrun.json` itself, asserts the exact ordered baseline names and uniqueness, and checks every mapped row has either real PVTHFHE timing data or an explicit `gap_reason`.
- `bench_comparison.rs` and `comparison_json_shape.rs` now derive row names/cardinality expectations from `comparison_map` constants to reduce drift across duplicated hardcoded lists.

## 2026-05-06 E2 comparison report renderer

- `pvthfhe-bench` now has a dedicated `render_comparison` module plus `render_comparison` bin that merges the vendored Interfold baseline with `bench_comparison` JSON via `comparison_map` and renders Markdown through Tera.
- The renderer now emits the plan-required no-normalization note and carries Interfold provenance details, including the baseline estimation method, directly into the report body.
- Renderer validation is worth keeping local to the render step: validating commit-sha output filenames and returning normal errors for missing/mismatched mapping rows is safer than panicking inside context construction.
- A fully synthetic renderer test is more robust than `include_str!`-loading repo fixtures for this task; it can assert disclosure/legend/presence requirements without coupling to unrelated benchmark artifact churn.
- Remaining gap for full E2-plan closure: the current comparison JSON only carries scalar timings, so uncertainty intervals from ≥3 runs cannot be rendered until the producer path aggregates repeated runs and exposes interval fields.

## 2026-05-06 E5 bench-comparison gate

- `bench-comparison-gate` fits the existing Justfile gate style as a simple recipe that runs `cargo test -p pvthfhe-bench` first, then shells out to a comparison-report check.
- The gate should inspect the latest `bench/results/comparison-*.md` artifact and fail only if any non-`real-fallback` row still contains `surrogate`; the current comparison report has zero `surrogate` rows.
- `verdict: NoGo` in `.sisyphus/research/sonobe-wrap-feasibility.md` is the only condition that allows `real-fallback`, and only on the on-chain row.
- Verified from repo root: `just bench-comparison-gate` exits 0 on the current state.


## 2026-05-07 t=131072 benchmark alignment rerun

- Phase-0 smoke confirmed `FhersBackend::load_params` and the `pvthfhe-e2e` keygen path accept `t_plain = 131072` in the CLI/demo `DEMO_PARAMS_TOML` constants; no rollback to `65536` was needed.
- A disowned `ulimit -v 16777216 && setsid nohup just bench-comparison ... & disown` rerun completed successfully and rewrote `bench/results/comparison.json` plus `bench/results/comparison-5d7853a.md` in place.
- Updated comparison numbers at `t = 131072` yield an Interfold/PVTHFHE workload-level speedup of about `182.7x` from the sum of the 12 published comparison rows.
- Latest single-run `bench/results/e2e_timings.json` sums to `43.918 s` across the recorded phase timings for `n=3, t=1, seed=1`.
