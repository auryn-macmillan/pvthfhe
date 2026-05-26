
## G.7 + G.8 Implementation (2026-05-19)

### G.7 — Committee binding
- Inserted after party_id non-zero assertion loop (after line 100)
- Approach: assert unused committee_party_ids[i] for i >= n are zero, then hash full MAX_PARTICIPANTS array with `vector_hash(committee_party_ids, DOMAIN_VECTOR_MERKLE)` and constrain equality with `participant_set_hash`
- This closes the committee identity gap — prover can no longer supply arbitrary committee_party_ids independent of participant_set_hash

### G.8 — Threshold enforcement
- Inserted after G.6 combined_share_hash equality check (after line 135)
- Counts non-zero shares by checking `participant_shares[i][0] != 0` as a proxy for the whole vector
- If first element is zero, asserts all N elements are zero (all-or-nothing invariant)
- Constrains `share_non_zero_count == threshold + 1`

### Test updates
- `test_honest_lagrange_recombination`: Made d[1], d[2] non-zero (threshold+1=3), computed participant_set_hash from committee_party_ids, updated expected plaintext to [1,0,...] (was [3,0,...] due to Lagrange with all-same shares)
- `test_tamper_duplicate_party_ids`: Computed participant_set_hash (needed to pass G.7 before reaching Lagrange failure)
- `test_ciphertext_equals_plaintext_hash`: Added non-zero d[1], d[2], computed participant_set_hash, updated expected_plaintext
- `test_tamper_d_commitment_mismatch`: Added non-zero d[1], d[2], computed participant_set_hash
- Tests that fail before G.7/G.8 (epoch zero, wrong threshold, zero party_id) unchanged — they still fail on their original assertions

### Verification
- `nargo check`: passes (only pre-existing unused-result warnings)
- `nargo test --package aggregator_final`: 9/9 tests pass

## 2026-05-19: Poseidon hash inlining for participant_set_hash

- Inlined `light_poseidon::Poseidon::<Fr>::new_circom` at `full_pipeline.rs:2031` for participant_set_hash.
- Note: `poseidon_hash_native` already used `Poseidon::new_circom` internally, so the behavioral change is zero.
- The hasher must be declared `mut` since `.hash()` takes `&mut self`.
- `cargo check -p pvthfhe-cli` passes.

## 2026-05-19: Fixed-arity Poseidon hash_9 for G.7 (sponge replacement)

### Problem
The sponge-based `vector_hash` / `poseidon_sponge_native_noir` had hidden compat issues with Noir's exact sponge behavior (pre-permute, initialization, padding).

### Solution
Replaced sponge with fixed-arity Poseidon `hash_9` (1 domain + 8 party IDs) on both sides:
- **Noir**: `poseidon::poseidon::bn254::hash_9(ps_hash_inputs)` — already available in the circuit (used by `bind_8_with_domain`)
- **Rust**: `light_poseidon::Poseidon::<Fr>::new_circom(9).hash(&inputs)` — already imported, used in `schnorr.rs`

Both use the same Circom-compatible BN254 Poseidon parameters.

### Changes
- `circuits/aggregator_final/src/main.nr:110` — circuit assertion: sponge → hash_9
- `circuits/aggregator_final/src/main.nr` — 4 test functions: `participant_set_hash` computation → hash_9
- `crates/pvthfhe-cli/src/full_pipeline.rs:2103-2115` — `poseidon_sponge_native_noir` → `Poseidon::<Fr>::new_circom(9).hash()`

### Verification
- `nargo test --package aggregator_final`: 9/9 pass
- `cargo check -p pvthfhe-cli`: passes
