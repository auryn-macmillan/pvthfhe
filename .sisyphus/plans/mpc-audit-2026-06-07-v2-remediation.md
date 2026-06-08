# MPC Audit Remediation Plan — v2 (2026-06-07)

**Source**: MPC-AUDIT-2026-06-07-FRESH-v2.md
**Status**: DRAFT — awaiting Momus review
**Model**: Actively malicious adversary, only verifier trusted

---

## P0: F0 — Fix 16-bit Fold Challenge (CRITICAL)

### Problem
`crates/pvthfhe-cyclo/src/fold.rs:60` extracts only 16 bits from SHA-256 for fold challenge (`u64::from(u16::from_le_bytes([h[0], h[1]]))`). This gives only 65,536 possible challenge values, making the fold layer trivially breakable by brute force.

### Fix
1. Change `derive_challenge` return type from `u64` to `u128`.
2. Extract 128 bits (16 bytes) from the 256-bit hash output.
3. Add `params_digest: &[u8; 32]` parameter to `derive_challenge` (per N1).
4. Update `fiat_shamir::challenge_v1` to accept `params_digest` and include it in the hash.
5. Update all callers: `init_accumulator_inner`, `fold_one_deterministic_inner`, `fold_one_step`, `verify_fold`.

### Files changed
- `crates/pvthfhe-cyclo/src/fold.rs` — `derive_challenge`, all callers
- `crates/pvthfhe-cyclo/src/fiat_shamir.rs` — `challenge_v1` → `challenge_v2` with `params_digest`
- Callers in `folding/mod.rs`

### Tests needed
- `test_derive_challenge_has_128_bit_entropy`
- `test_derive_challenge_params_digest_binding`
- `test_fold_soundness_with_full_challenge`

### Verification
```bash
cargo test -p pvthfhe-cyclo -- fold
```

---

## P1: F1 — Fix ajtai_sigma_session_binding Domain Separation (HIGH)

### Problem
`crates/pvthfhe-nizk/src/adapter.rs:604-617` uses raw concatenation of session_id, ajtai_bytes, ciphertext_bytes, decrypt_share_bytes without domain tag or length prefixes. Ambiguous concatenation enables cross-domain substitution.

### Fix
1. Add `Tag::CycloAjtaiBinding` domain separator.
2. Add length-prefixed encoding for each field (`u32 BE`).
3. Update `Tag::CycloAjtaiBinding` to `"pvthfhe/cyclo-ajtai-binding/v1"`.

### Files changed
- `crates/pvthfhe-nizk/src/adapter.rs` — `ajtai_sigma_session_binding`

### Tests needed
- `test_ajtai_binding_is_injective`
- `test_ajtai_binding_uses_domain_tag`
- `test_ajtai_binding_length_prefix_prevents_concat_collision`

### Verification
```bash
cargo test -p pvthfhe-nizk -- adapter
```

---

## P1: F2 — Fix Witness Exact-Length Validation (HIGH)

### Problem
`crates/pvthfhe-nizk/src/adapter.rs:374-381` only checks `is_empty()` for witness polynomials. `pad_or_truncate_to_rlwe_n` silently pads short witnesses or truncates long ones. A 1024-element witness can produce a valid-looking proof for N=8192.

### Fix
1. Add exact length checks in `validate_witness`: `secret_share_poly.len() == rlwe_n()` and `error.len() == rlwe_n()`.
2. Replace `pad_or_truncate_to_rlwe_n` with direct use of the validated witness (no padding/truncation).
3. Update `prove()` in `CycloNizkAdapter` to pass the validated witness directly to sigma without padding.

### Files changed
- `crates/pvthfhe-nizk/src/adapter.rs` — `validate_witness`, `prove` (remove pad_or_truncate_to_rlwe_n calls)

### Tests needed
- `test_witness_rejected_when_too_short`
- `test_witness_rejected_when_too_long`
- `test_witness_accepted_when_exact_length`

### Verification
```bash
cargo test -p pvthfhe-nizk -- adapter
```

---

## P1: N1 — Add params_digest to Fold Challenge (HIGH)

### Problem
`derive_challenge` in `fold.rs` does not bind `params_digest`, enabling cross-parameter-set challenge replay. Combined with the 16-bit extraction (F0), this exacerbates the attack surface.

### Fix
1. Add `params_digest: &[u8; 32]` parameter to `derive_challenge`.
2. Add `params_digest` to `fiat_shamir::challenge_v2`.
3. Update all callers to pass `params_digest` from the accumulator (already stored in `CycloAccumulator.params_digest`).

### Files changed
- `crates/pvthfhe-cyclo/src/fold.rs` — `derive_challenge`, all callers
- `crates/pvthfhe-cyclo/src/fiat_shamir.rs` — `challenge_v2`

### Overlaps with
- **F0** (add params_digest at same time as fixing 16-bit issue)

---

## P2: FF10 — Fix LaZer Session/Party Binding (MEDIUM)

### Problem
`crates/pvthfhe-nizk/src/lazer_bridge.rs:273-276` explicitly discards `_session_id` and `_participant_id` with `let _ = ...`. LaZer-generated proofs are not bound to session or participant identity.

### Fix
1. Compute a binding hash: `SHA256(Tag::LazerSessionBinding || session_id || participant_id.to_le_bytes())`.
2. **Approach**: Append the 32-byte binding hash as an additional witness element to `witness_data` under a reserved key `"__pvthfhe_session_binding"`. This avoids corrupting existing witness coefficients (unlike XOR). The LaZer C library receives the binding as additional witness material, making it part of the proof without breaking algebraic relations.
3. The verifier reconstructs the same binding hash using the statement's session_id and participant_id, constructs `witness_data` with the same binding entry, and calls `lazer::lin_verify`. The LaZer library will reject proofs where the binding witness doesn't match.
4. **Non-Lazer fallback**: When `enable-lazer` is NOT active, the function is a no-op stub — the session binding is verified at the adapter layer (adapter.rs already cross-checks session_id and participant_id from the proof bytes).

### Files changed
- `crates/pvthfhe-nizk/src/lazer_bridge.rs` — `LazerSigmaProver::prove`, `LazerSigmaVerifier::verify`
- `crates/pvthfhe-domain-tags/src/lib.rs` — (Tag::LazerSessionBinding already exists, value `"pvthfhe/lazer-session-binding/v1"`)

### Tests needed
- `test_lazer_proof_binds_session_id`
- `test_lazer_proof_binds_participant_id`
- `test_lazer_proof_replay_rejected`

### Files changed
- `crates/pvthfhe-nizk/src/lazer_bridge.rs` — `LazerSigmaProver::prove`, `LazerSigmaVerifier::verify`

### Tests needed
- `test_lazer_proof_binds_session_id`
- `test_lazer_proof_binds_participant_id`
- `test_lazer_proof_replay_rejected`

### Verification
```bash
cargo test -p pvthfhe-nizk --features enable-lazer -- lazer
```

---

## P2: N3 — Fix Fiat-Shamir Counter-Mode Per-Block Label Binding (MEDIUM)

### Problem
`crates/pvthfhe-nizk/src/fiat_shamir.rs:102-111` — during counter-mode expansion for outputs > 32 bytes, each new SHA-256 hasher receives only `(counter || state)`, not `(label || counter || state)`.

### Fix
1. Include the label in each counter-mode block hash.
2. Update the hashing to: `SHA256(label || counter.to_be_bytes() || state)`.

### Files changed
- `crates/pvthfhe-nizk/src/fiat_shamir.rs` — `challenge_bytes`

### Tests needed
- `test_challenge_bytes_per_block_label_binding`
- `test_different_labels_produce_different_expansion`

### Verification
```bash
cargo test -p pvthfhe-nizk -- fiat_shamir
```

---

## P2: N4 — Fix Poseidon Panic (MEDIUM)

### Problem
`crates/pvthfhe-nizk/src/sigma.rs:725-728` panics with `unwrap_or_else(|_| panic!(...))` instead of returning an error. This can cause a verifier thread to abort without blame identification.

### Fix
Replace panics with error returns. Requires changing `poseidon_hash` return type from `Fr` to `Result<Fr, NizkError>` and propagating through callers.

### Files changed
- `crates/pvthfhe-nizk/src/sigma.rs` — `poseidon_hash`, `derive_challenge_from_commitment`

### Tests needed
- `test_poseidon_error_on_invalid_arity`

---

## P2: N2 — Verify CCS Witness Soundness in Fold · RESOLVED (code confirmation)

### Verification
`crates/pvthfhe-cyclo/src/fold.rs:357` already calls `ccs_encode::check_satisfiability(&encoded)?;` which performs real CCS relation verification (M·z ⊙ z == 0). The function body was confirmed free of SHA-256 tautologies by test `no_sha_tautology.rs`. 47 test references across 11 test files validate satisfiability checking end-to-end.

**No fix needed.** N2 is resolved in current code.

---

## P2: FF1 — Real CCS Witness Extraction (PARTIAL → COMPLETE)

### Problem
1. `extract_ccs_witness_from_proof` is imported at `folding/mod.rs:43` but DOES NOT EXIST in `adapter.rs`. Compilation fails with `--features real-folding,real-nizk`.
2. `mod.rs:450-459` falls back to `demo_zero_witness_bytes()` when (the non-existent) `extract_ccs_witness_from_proof` fails.
3. `ccs_matrix_bytes` always uses `demo_one_by_one_matrix_bytes()`.
4. `ajtai_commitment_bytes` at `mod.rs:437-447` uses a SHA-256 hash padded to 26KB, not the actual Ajtai commitment from the proof.

### Fix
1. Create `extract_ccs_witness_from_proof` in `adapter.rs`: a `pub fn` that parses the sigma proof bytes to extract the witness polynomial coefficients from the sigma multi-proof response values `z_s` (which encode s_i + mask).
2. Create `extract_ccs_matrix_from_proof` in `adapter.rs`: extracts the CCS matrix from proof metadata.
3. Extract `ajtai_commitment_bytes` from the actual proof bytes (offset 2+32=34, length 26624) rather than from a SHA-256 hash.
4. Remove the silent fallback to `demo_zero_witness_bytes()` — return `anyhow::Error` on extraction failure.
5. Remove `demo_one_by_one_matrix_bytes()` usage — use extracted matrix or return error.

### Files changed
- `crates/pvthfhe-nizk/src/adapter.rs` — add `extract_ccs_witness_from_proof`, `extract_ccs_matrix_from_proof`, `extract_ajtai_commitment_from_proof`
- `crates/pvthfhe-aggregator/src/folding/mod.rs` — `fold_stmt_witness_to_cyclo_instance`

### Tests needed
- `test_extract_witness_from_real_proof_roundtrip`
- `test_extract_witness_fails_on_demo_proof`
- `test_extract_ajtai_from_proof_matches_original`
- `test_ccs_instance_uses_real_not_demo_data`

---

## P3: N5 — Fix encode overflow error handling (LOW)

### Problem
`crates/pvthfhe-nizk/src/adapter.rs:654-668` uses `unwrap_or(u32::MAX)` for length encoding overflow, silently producing wrong data.

### Fix
Return `NizkError::InvalidInput` on overflow instead of `unwrap_or(u32::MAX)`.

### Files changed
- `crates/pvthfhe-nizk/src/adapter.rs` — `encode_u64s_le`, `encode_i64s_le`

---

## Documentation Updates

After all code changes:
1. **SECURITY.md** — Update P1 banner to reflect current state, note F0 fix
2. **ARCHITECTURE.md** — Update fold challenge description
3. **README.md** — Update status table
4. **WARNING.md** — Update known limitations
5. **paper/main.tex** — Update fold challenge, sigma binding descriptions
6. **docs/OPEN-PROBLEM-BLOCKERS.md** — Add entries for findings that remain open after remediation

---

## Implementation Order

```
Phase 1 (P0): F0 + N1 together (fold.rs + fiat_shamir.rs)
Phase 2 (P1): F1 (ajtai binding) + F2 (witness validation)
Phase 3 (P2): FF10 (LaZer) + N3 (FS counter-mode) + N4 (Poseidon panic) + FF1 (CCS witness)
Phase 4 (P3): N5 (encode overflow) + Documentation updates
```

## Verification Gates

After each phase, run:
```bash
cargo test -p pvthfhe-cyclo
cargo test -p pvthfhe-nizk
cargo test -p pvthfhe-aggregator
cargo test -p pvthfhe-pvss
```

Full e2e gate:
```bash
just demo-e2e
just test-all
```
