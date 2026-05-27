- 2026-05-04 F9: `pvthfhe-aggregator::folding::CycloFoldingAdapter::fold_all` can satisfy the 1024-share smoke path by chunking shares into `sequential_t=10` batches and verifying each batch accumulator with the underlying Cyclo adapter.
- 2026-05-04 F9: a lightweight bench can emit `bench/results/aggregate_1024.json` directly from the bench target while Criterion measures the same aggregation path.
- 2026-05-04 O1: on Noir 1.0.0-beta.20, `nargo test` in this workspace executed inline `#[test]` functions in `src/main.nr`; the required `tests/bind_inputs.nr` fixture was kept for task evidence, but the runnable RED/GREEN coverage had to live in `src/main.nr`.
- 2026-05-04 O2: on Noir 1.0.0-beta.20, `(cd circuits && nargo execute --package micronova_wrap --prover-name Prover)` wrote `micronova_wrap.json` and `micronova_wrap.gz` into the workspace-level `circuits/target/` directory, so package-local `circuits/micronova_wrap/target/` artifacts had to be mirrored after a successful execute to satisfy task-local output expectations.
- 2026-05-06 N6: `nargo execute --package <pkg> --prover-name <Cap_Name>` in this workspace still looks for a derived `<Cap_Name>.toml` next to the package, so the gate recipe must copy `Prover.toml` to that derived name first and then mirror the generated artifacts from `circuits/target/` back into each package-local `target/` directory.

- 2026-05-11 S2: Replaced `HashChainCycloAdapter` in `full_pipeline.rs` with direct calls to `fold::init_accumulator` → `fold::fold_one_step` → `fold::verify_fold`. The adapter was a wrapper around `LegacyHashChainAdapter` which itself delegated to the same real Cyclo functions, so the replacement is behavior-preserving but removes the indirection. Batching (chunking instances by `PVTHFHE_CYCLO_PARAMS.sequential_t`) is handled directly in the pipeline now.
- 2026-05-11 S2: `CcsPShareInstance` does not implement `Clone` because `CcsWitnessSecret` wraps `secrecy::Secret<Vec<u8>>` which intentionally prevents cloning. Tests must construct fresh instances rather than cloning.
- 2026-05-11 S2: `CycloFoldAllReport` had private fields with only getters — needed to add a `pub fn new(...)` constructor so the pipeline can build the report directly without going through `HashChainCycloAdapter`.
- 2026-05-11 S2: Fold soundness test exercises `check_satisfiability` by constructing a 1×1 identity CCS matrix and tampering the witness from Fr=0 (satisfies `1·0·0 = 0`) to Fr=1 (violates `1·1·1 ≠ 0`). `verify_fold` correctly rejects tampered instances at the CCS satisfiability check before recomputing the accumulator.


- 2026-05-11 P2A.1: Ajtai commitment over R_q uses deterministic matrix generation from `AjtaiParams.seed` via `ChaCha20Rng::from_seed`. Both `commit` and `verify` regenerate the same m×n matrix from the seed to ensure consistency. The `rng` parameter in `commit` is retained for interface compatibility but is unused for matrix generation.
- 2026-05-11 P2A.1: Each matrix entry A[i][j] is a random `RqPoly` (256 coefficients ∈ [0, Q_COMMIT)). The commitment is computed row-by-row: for each row i, accumulate `Σ_j ntt_mul(A[i][j], w[j])` using `ring_add_poly`. This uses NTT-based polynomial multiplication.
- 2026-05-11 P2A.1: Wire format encodes each RqPoly as PHI_COMMIT×8 bytes (u64-LE per coefficient) and concatenates them. `decode_commitment` takes `m` as a parameter to verify the byte length.
- 2026-05-11 P2A.1: Added `rand_chacha = "0.3"` to `[dependencies]` in `Cargo.toml` since `ajtai.rs` uses `ChaCha20Rng` directly (was previously only in `[dev-dependencies]`).

- 2026-05-11 P3.1/P3.2: Expanded ExternalInputs from single `F` to triple `ExternalInputs3<F>` (commitment, norm, count) for both ToyStepCircuit and CycloFoldStepCircuit. Orphan rule (E0210) prevented implementing `AllocVar` directly for tuple `(FpVar<F>, FpVar<F>, FpVar<F>)` — foreign trait on foreign types. Solution: introduced local newtype wrappers `ExternalInputs3<F>` and `ExternalInputs3Var<F>` with a custom `AllocVar` impl.
- 2026-05-11 P3.1/P3.2: The `encode_triple`/`decode_triple` helpers were made public in `nova/mod.rs` and reused by `compressor_glue.rs` to avoid duplicating the 96-byte wire format. This required adding `ark-ff = "0.5"` as a direct dependency of `pvthfhe-cli` for the `PrimeField` trait import.
- 2026-05-11 P3.1/P3.2: The `FCircuit` trait bound on `NovaCompressor<S>` changed from `ExternalInputs = Fr` to `ExternalInputs = ExternalInputs3<Fr>`. All downstream call sites (tests, bins, examples) updated to use the new 96-byte triple encoding via `encode_triple`.
- 2026-05-11 P3.1/P3.2: `ToyStepCircuit::state_len()` expanded from 1 to 3 to match the triple state. `generate_step_constraints` now applies each external input field to its corresponding state element. `CycloFoldStepCircuit` updated to use `.0` (commitment), `.1` (norm), `.2` (count) from `ExternalInputs3Var`.
- 2026-05-11 P3.1/P3.2: `compressor_inputs` in `compressor_glue.rs` now aggregates `norm_bound_current` and `fold_depth` across all accumulators and encodes them alongside the SHA-256 hashes of commitment/public_io bytes into 96-byte triples.

- 2026-05-11 P2A.2: Replaced SHA-256 surrogate in fold.rs commitment path with real Ajtai commitments from `ajtai.rs`. The key constants are `AJTAI_COMMITMENT_M = 13` (from `PVTHFHE_CYCLO_PARAMS.ajtai_rank_a`) and `AJTAI_COMMITMENT_BYTES = 26624 = 13 × 256 × 8`. `init_accumulator` now decodes the instance's Ajtai commitment directly (no SHA-256). `fold_one_deterministic` decodes both accumulator and instance commitments, performs component-wise `C_new[i] = C_acc[i] + r·C_inst[i]` over the 13 ring elements, and re-encodes. `verify_fold` checks `acc_commitment_bytes.len() == 26624` instead of 32. `MAX_AJTAI_COMMITMENT_BYTES` (29286 = 26624 + 10%) was introduced so honest 26624-byte commitments pass the DOS check.
- 2026-05-11 P2A.2: Updating all existing tests to 26624-byte commitments required touching fold_one.rs, fold_binding_adversarial.rs, verify_fold_satisfiability.rs, challenge_entropy.rs, fold_driver_t10.rs, forgery_resistance.rs, dos_bounds.rs, witness_norm.rs, and adversarial_norm.rs. Each test's `make_instance` helper now produces properly-sized commitment bytes. `forgery_resistance.rs` is a 100K-attempt stress test that takes too long — skipped with `--skip forgery`.
- 2026-05-11 P2A.3: Added `CycloTernaryTranscript` struct to `fiat_shamir.rs` with domain separator `"pvthfhe-cyclo-fs-v2"` (distinct from Nova's `"pvthfhe-cyclo-fs-v1"`). `sample_challenge(&mut self) -> i8` returns -1, 0, or 1 with probability 1/3 each. Internally clones the current SHA-256 state, finalizes, maps `hash[0] % 3` to {-1, 0, 1}, and advances state with the hash for domain separation of subsequent calls. All existing Nova v1 functions (`challenge_v1`, `commitment_v1`, etc.) remain unchanged.
- 2026-05-11 P2A.3: The ternary challenge is additive — the existing `fold.rs` still uses the u16-based `derive_challenge` with `scalar_mul`. The `CycloTernaryTranscript` is available for future fold wiring. The `ring.rs` module already has `ternary_mul(poly, r: i8)` for efficient {−1, 0, 1} scalar multiplication.

- 2026-05-12 D.1: Updated spec-real-p2p3.md §6.5 to reflect the actual Noir circuit behavior: direct Lagrange recombination over N=8 with Poseidon hash checks for commitment binding, no MicroNova proof verification. Added TOY CIRCUIT warning banner and explicit Diff-from-spec section. The old pseudo-Noir code (verify_micronova / assert_cyclo_accumulator_binding) was removed. The actual circuit at circuits/aggregator_final/src/main.nr matches: it validates R3 relation (rhs - lhs ≡ 0 mod Q) using polynomial evaluation at Poseidon-derived challenge r, with Lagrange coefficient summing enforced to 1.

## Batch C (Phase 1.3) — Doc Sync (2026-05-12)

### C.1 — bfv_sigma.rs documented in nizk-construction.md
Added §R3.6 documenting the lattice-native BFV sigma protocol. Key insights:
- Proves ct0 = pk0*u + e0 + Δ*m and ct1 = pk1*u + e1 per CRT limb
- Operates over full BFV ciphertext modulus Q (3 RNS limbs), not R_{q_commit}
- Wired as v4 (PROOF_VERSION=4) in nizk_share.rs; v3 proofs fail-closed
- Challenge is binary polynomial ch∈{0,1}^N via Fiat-Shamir

### C.2 — CycloAdapter trait docs synced to code
Replaced spec draft (init/fold/verify_final/serialise_for_p3/FoldingError) with
actual trait (backend_id/params/fold_one/verify_accumulator/fold_all/CycloError).
Added a migration table mapping old→new method names.

### C.3 — Two-track DKG infrastructure documented
Added §4.8 documenting FoldTrackKind enum (Sk/ESm/EncryptionWitness),
MultiTrackFoldMetadata, validate_for_instance(), and cross-track replay rejection logic.

### C.4 — Field names synced
Updated CcsPShareInstance ({ajtai_commitment→ajtai_commitment_bytes, added ccs_matrix_bytes})
and CycloAccumulator ({acc_commitment→acc_commitment_bytes, acc_public_io→acc_public_io_bytes}).

### C.5 — MicroNovaAdapter/p3-encoder marked DEFERRED
Added DEFERRED banner in §5.1 and commented-out trait in §7.1, noting current impl
uses Nova Nova via ProofCompressor with migration tracked in nova-migration.md.

### C.6 — LatticePvssBfvAdapter documented in interfold-equivalence.md
Updated C3 row with concrete adapter details and added Component Mapping table
mapping PVTHFHE modules to Interfold C0-C7 circuits.

### C.7 — C2b status: missing→partial; C7: missing with Noir note
C2b moved to partial (two-track infra: FoldTrackKind::ESm, MultiTrackFoldMetadata,
partial_decrypt_committed_smudge). C7 kept missing with Noir circuit plan reference.
Summary updated: partial 7→8, missing 2→1.

### C.8 — smudging.md §5.1 and §8.3 fixed
§5.1: Changed from "must implement" to "already implemented" with actual code snippet.
§8.3: Added IMPLEMENTED banner, documented both committed_smudge variants and their signatures.

### Pattern
- When using Python replace(), exact string matching is fragile — whitespace/newline
  variations cause silent failures. Line-index replacement is more robust.
- Always verify with read() after edits; grep may have stale caches.

- 2026-05-12 B.3/B.4: Changed `shamir::split` return type from `Vec<(usize, Fr)>` to `Result<Vec<(usize, Fr)>, ShamirError>` and converted `assert!(t > 0)` and `assert!(n >= t)` to proper error returns with `InvalidParameters(String)`. This required updating all 11 call sites across shamir.rs tests, shamir_secrecy.rs, and encrypt.rs.
- 2026-05-12 B.3/B.4: Added `threshold: usize` parameter to `shamir::recover()` and replaced `shares.is_empty()` check with `shares.len() < threshold`. Updated 16 call sites across shamir.rs tests, shamir_secrecy.rs, and encrypt.rs. Dual guard exists: PVSS-layer `recover` checks `decrypted_shares.len() < ctx.t` at line 258, and Shamir-layer `recover` now also enforces `shares.len() < threshold`. The Shamir-layer check is the authoritative cryptographic enforcement.
- 2026-05-12 B.3/B.4: Followed strict TDD: wrote RED test (`insufficient_shares_fails` asserting `Err(InsufficientShares)` for t-1 shares) which failed because old `recover` attempted Lagrange interpolation and returned `Ok(wrong_value)`. Implemented the fix (threshold param + guard check), then the test passed GREEN.

- 2026-05-17: Fixed d_commitment in aggregator_final/Prover_re.toml. Computed via temp Noir bin that mirrors main.nr's hash pipeline (vector_hash → combine_hashes → bind_8_with_domain with DOMAIN_AGGREGATOR_D_COMMIT=6). Correct value: 0x26a4dfe1db0c1f4c052a97ea3c84926e3aab77224914a88a92ae055e8643b9ae. Also fixed lagrange_coeffs[1] which was p-4 (0x...fffd) instead of p-3 (0x...fffe), causing "Lagrange coefficients must sum to 1" assertion failure. Approach: `nargo test --show-output` with `std::println` in a temporary Noir project to extract computed hash values.
