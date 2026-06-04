# Paper-Code Alignment

## C5: Aggregate Public-Key Formation Proof

**Claim**: The aggregate public key `pk_agg = Σ pk_i` is correctly formed from participant public keys, verifiable by third parties.

**Status**: ✅ **RESOLVED** (2026-06-04)

**Implementation**:
| Component | File | Description |
|-----------|------|-------------|
| Proof generation | `crates/pvthfhe-aggregator/src/keygen/c5_proof.rs` | `prove_pk_formation()` bundles per-party PoPs + aggregate metadata |
| Proof verification | `crates/pvthfhe-aggregator/src/keygen/c5_proof.rs` | `verify_pk_formation()` checks sum relation, session binding, duplicates |
| Wire into keygen | `crates/pvthfhe-aggregator/src/keygen/simulator.rs` | Called in `run()` after `aggregate_keygen()` |
| Data model | `crates/pvthfhe-aggregator/src/keygen/types.rs` | `c5_proof_root: [u8; 32]` on `Round3Aggregate` |
| Pipeline integration | `crates/pvthfhe-cli/src/full_pipeline.rs` | `PipelineReport.c5_proof_root` populated from transcript |
| On-chain binding | `contracts/src/PvtFheVerifier.sol` | `c5ProofRoot` in `IvcBinding`, validated in `_computeIvcStatementHash()` |

**Test coverage**: 9 tests (`cargo test -p pvthfhe-aggregator --test c5_formation_proof --features mock`):
- `honest_n_party_produces_valid_c5_proof`
- `manipulated_pk_fails_c5_verification`
- `rogue_aggregate_pk_fails_c5_verification`
- `duplicate_party_id_fails`
- `mismatched_counts_fails`
- `proof_root_changes_with_different_nonces`
- `wrong_session_id_fails_pop_verification`
- `proof_root_is_nonzero_and_consistent`
- `empty_participant_set_rejected`

**Design doc**: `.sisyphus/design/c5-formation-proof.md`

---

## C7: Threshold-Decryption Correctness

**Claim**: The aggregated partial decryption shares correctly reconstruct the plaintext via Lagrange recombination under the threshold logic.

**Status**: ✅ **RESOLVED** (2026-06-04)

**Implementation**:
| Component | File | Description |
|-----------|------|-------------|
| Circuit constraints | `circuits/aggregator_final/src/main.nr` | Schwartz-Zippel: `sum(lambda_i) = 1` + `sum(lambda_i * d_i(r)) = pt(r)` |
| Witness generation | `crates/pvthfhe-cli/src/full_pipeline.rs` | `build_c7_prover_toml()` with share_evals, lagrange_coeffs, pt_eval |
| G3 plaintext binding | `crates/pvthfhe-cli/src/full_pipeline.rs` | `aggregate_decrypt_raw_result_poly()` evaluation at same challenge point |
| G4 PK binding | `circuits/aggregator_final/src/main.nr` | Merkle-path verification (depth=8, Poseidon) binding `aggregate_pk_hash` to `dkg_root` |
| Prover template | `circuits/aggregator_final/Prover.toml` | Witness values for execution |

**Circuit metrics**: 7,959 ACIR opcodes, 27,602 UltraHonk circuit size (with G4 Merkle-path)

**Test coverage**: 18 tests (`nargo test --package aggregator_final`):
- 8 C7-specific: honest recombination, wrong Lagrange sum, wrong recombination, wrong share eval, manipulated coefficients, zero-padded shares, plaintext commitment inconsistency, n_shares zero
- 4 G4 PK binding: honest binding, missing rejects, wrong leaf rejects, forged path rejects
- 6 existing: simplified_honest, plaintext_mismatch, ivc_hash_zero, 3× verification_statement_v1

**Design doc**: `.sisyphus/plans/c7-correctness.md`

---

## A1: Cyclo Accumulator Transcript Verification

**Claim**: The Cyclo fold accumulator transcript is verifiable, ensuring folded-accumulator soundness.

**Status**: ✅ **RESOLVED** (2026-06-04)

**Implementation**:
| Component | File | Description |
|-----------|------|-------------|
| Codec | `crates/pvthfhe-cyclo/src/accumulator_codec.rs` | Versioned wire format (618 lines), encode/decode, `AccumulatorInstanceRef` |
| Adapter dispatch | `crates/pvthfhe-nizk/src/adapter.rs` | `verify_accumulator_transcript()` replacing fail-closed stub |
| Post-prove append | `crates/pvthfhe-nizk/src/adapter.rs` | `append_accumulator_to_proof()` for accumulator encoding |
| Dependency fix | `crates/pvthfhe-nizk/Cargo.toml` | Added `pvthfhe-cyclo` dependency |

**Codec validation** (10 items):
- Version match, params_digest match, commitment/pub_io lengths, norm ≤ beta_at_t, duplicate participant IDs, fold_depth == instance_count, no trailing bytes, roundtrip, empty, truncated

**Test coverage**: 21 tests:
- 10 codec unit tests (`cargo test -p pvthfhe-cyclo accumulator_codec`)
- 5 fail-closed tests (`cargo test -p pvthfhe-nizk --test accumulator_fail_closed`)
- 6 adversarial tests (`cargo test -p pvthfhe-nizk --test accumulator_transcript_adversarial`)

**Design doc**: `.sisyphus/plans/a1-accumulator-transcript.md`

---

## G3: Full Plaintext Binding

**Status**: ✅ **RESOLVED** (2026-06-04)

**Implementation**: `crates/pvthfhe-cli/src/full_pipeline.rs` — `run_c7_verification()` owns G3 backend binding: receives concrete `FhersBackend`, ciphertext, decrypt shares, threshold, session_id; calls `aggregate_decrypt_raw_result_poly()` inside C7 verification path; CRT-reconstructed result polynomial evaluated at Schwartz-Zippel challenge point `r` and compared against `sum(lambda_i * d_i(r))`.

---

## G4: In-Circuit PK Binding (Merkle-Path)

**Status**: ✅ **RESOLVED** (2026-06-04)

**Implementation**: `circuits/aggregator_final/src/main.nr` — Binary Merkle tree (arity=2, depth=8), Poseidon sponge for node hashing. Three constraints: (1) `dkg_root != 0`, (2) `Poseidon([aggregate_pk_leaf]) == aggregate_pk_hash`, (3) `compute_merkle_root(aggregate_pk_leaf, merkle_path, leaf_index) == dkg_root`.

---

## Remaining Gaps

| ID | Problem | Status |
|----|---------|--------|
| P1 | Lattice NIZK well-formedness soundness (Greco M-SIS) | OPEN |
| P2 | Lattice-native folding over RLWE (Nova substitute) | OPEN |
| P4 | On-chain IVC decider verification (currently fail-closed) | OPEN |
| C6 | Committed-smudge enforcement | PARTIAL |
| D1 | HonkVerifier.sol regeneration (CI-deferred — bb `val.on_curve()` bug) | PENDING |
