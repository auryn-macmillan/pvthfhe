# Round 10 Adversarial Remediation — Batch A Learnings

## A.1: Cross-share RS parity check in encrypt.rs

- `verify_batched_share_computation` at `share_computation.rs:155` takes a single `&BatchedShareComputationStatement` argument, NOT individual ciphertexts/proofs/threshold/BFV params as the pseudo-code in the task implies.
- The task pseudo-code was aspirational — implemented the cross-share check as an inline RS parity verification using the actual `share_bytes` plaintext data from `EncryptedShares`.
- The check verifies that for each Fr chunk, all n shares form evaluations of the same degree-(t-1) polynomial, preventing the share-poisoning attack.
- Added `PvssError::ShareVerification(String)` variant for this error path.
- Added helpers: `verify_share_rs_consistency`, `interpolate_bn254`, `eval_bn254_poly_coeffs`.
- Required `ark_ff::AdditiveGroup` import for `Fr::ZERO`.

## A.2: Decrypt byte cross-validation

- Straightforward: compare `payload.share.bytes.0` (the raw DecryptShare bytes) with `opened.statement.decrypted_share_bytes` from the NIZK proof.
- `payload.share` is `DecryptShare` (from `pvthfhe_fhe::types`), which has `bytes: ProtocolBytes` where `ProtocolBytes(pub Vec<u8>)`.
- Access via `.0` on the ProtocolBytes tuple struct.

## A.4: LegacyLocalSmudge → CommittedSmudge

- `partial_decrypt` receives a `DecryptionWitness` from the backend, NOT `DecryptNizkWitness`.
- `DecryptionWitness` has `esm_committed: bool` and `esm_noise_poly_bytes: Vec<u8>`, but NOT `sk_agg_share` or `esm_agg_share`.
- Used `witness.esm_committed` to decide between CommittedSmudge and LegacyLocalSmudge fallback.
- For `sk_agg_share`: used `expected_sk_agg_share` from `derive_party_binding(party_pk_bytes)`.
- For `esm_agg_share`: derived from SHA256 of `decryption_noise_bytes`.
- Required `ark-bn254` as a regular dependency in `pvthfhe-aggregator` (was dev-only).
- Required new imports: `compute_sk_aggregate_commitment`, `compute_esm_aggregate_commitment`, `compute_decrypt_ciphertext_hash`.

## A.3: Simulator stub documentation

- Expanded the NIZK stub comment in `generate_r1_msg` to document what a real NIZK would need to prove (3 properties: pk validity, commitment binding, encrypted shares correctness).
- Added round10-adversarial-remediation F3 reference.

## Build verification

- Full workspace builds successfully.
- All pvss and aggregator lib tests pass.
- Pre-existing: `decrypt_real.rs` integration test fails due to missing `session_id` argument — not caused by these changes.

## Batch B.4 + C.1–C.4 Learnings

### B.4: aggregate_pk_hash binding in C7 circuit

- `run_c7_verification` originally used `Fr::zero()` as a placeholder for the third `ExternalInputs3` field.
- Added `aggregate_pk_bytes: &[u8]` parameter to the function signature.
- Computed the hash as `Fr::from_be_bytes_mod_order(&Sha256::digest(aggregate_pk_bytes))` — this binds the Nova IVC to the specific aggregate public key, preventing cross-session proof reuse.
- Updated the call site at line 773 to pass `&aggregate_pk.bytes` from the pipeline scope.
- The aggregate_pk is available as `transcript.round3_aggregate.aggregate_pk.clone()` at line 295, and `aggregate_pk.bytes` is accessible throughout the function.

### C.1: Remove pipeline-extra-checks gate around C7

- **No change needed.** The C7 decryption aggregation verification block (lines 757–777) is already unconditional — no `#[cfg(feature = "pipeline-extra-checks")]` gate wraps it.
- The `aggregate_decrypt` code (lines 730–745) does have a `pipeline-extra-checks` gate, but that's separate from C7 verification.
- The `sonobe-compressor` gate on `run_c7_verification` function definition (line 1257) is kept as instructed (Nova dependency).
- Verified via full `#[cfg]` grep: no cfg attributes between lines 750–778.

### C.2: slot_id parameter

- Three locations used hardcoded `slot_id: 1` / `1`:
  1. `compute_esm_aggregate_commitment(..., 1, ...)` at line 653
  2. `DecryptNizkMode::CommittedSmudge { slot_id: 1, ... }` at line 668
  3. `smudge_slot_registry.check_and_record(..., 1)` at line 688
- Added `let slot_id = u16::try_from(party_index).unwrap_or(0);` using the loop variable `party_index` (ranges 1..=cfg.t).
- Changed all three hardcoded `1`s to use the `slot_id` variable for consistency.

### C.3: SmudgeSlotRegistry consolidation comment

- Added module-level doc comment to `slot_registry.rs` noting the dual implementation (HashSet-based here, separate counterpart in `pvthfhe-fhe`) and consolidation plan.

### C.4: Max byte limit in wire.rs

- Added `const MAX_DECRYPT_SHARE_BYTES: usize = 196_608;` (8192 coeffs × 3 moduli × 8 bytes ≈ 196K).
- Added early return `WireError::Other` when `d_share_poly.is_empty()` or exceeds the maximum.
- `WireError::Other` is a unit variant — used without message to maintain consistency with existing call sites across the codebase.

## Build verification

- Full `cargo build --workspace` succeeds with only pre-existing warnings.
- No new warnings or errors introduced.

## B.1: Noir aggregator_final circuit wiring in C7 pipeline

- Wired Noir `aggregator_final` circuit as an optional phase after Core C7 Nova IVC verification in `full_pipeline.rs`.
- Guarded by `PVTHFHE_RUN_NOIR_C7` env var (default: off) to keep it optional.
- All errors are non-fatal: use `tracing::warn!` instead of `?` so pipeline doesn't break if nargo/bb are missing.
- `build_c7_prover_toml` builds a TOML string with placeholder hash values (0x0000...) and real data for sizing (n_participants, threshold). Pads arrays to 8 to match Noir circuit's `MAX_PARTICIPANTS=8`, `N=8`.
- Canonical flow: nargo execute → bb write_vk → bb prove → bb verify, run from `circuits/` workspace directory.
- Observer hooks in main.rs: `c7_noir_aggregator` added to both phase_start (print_step 11) and phase_end match arms.
- Circuit directory resolved from `CARGO_MANIFEST_DIR` (crates/pvthfhe-cli) → `../../circuits/aggregator_final`.
- Existing `run_noir_aggregator_final_optional()` in `pvthfhe_e2e.rs` bin uses `PVTHFHE_RUN_NOIR_CIRCUIT` env var and `pvthfhe_circuit_tests` helpers — separate from this pipeline-level integration.
