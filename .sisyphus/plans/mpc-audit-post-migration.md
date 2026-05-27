# Post-Migration MPC Audit — Remediation Plan

**Status**: PLAN
**Date**: 2026-05-27

## HIGH Severity (4 findings)

### H1 — Deterministic commitment seed enables rushing adversary
**File**: `crates/pvthfhe-pvss/src/nizk_share.rs:1398-1412`
**Issue**: `compute_commitment_seed` derives ChaCha20 seed entirely from public statement fields. A rushing adversary can precompute commitment/proof pairs before seeing honest messages. Nothing fresh (OsRng nonce) is injected.
**Fix**: Mix 32 fresh bytes from `OsRng` into the commitment seed hash. Include the nonce in the proof envelope for verifier validation.
**Effort**: ~30 min

### H2 — G.5 d_commitment = zero in BFV sigma binding
**File**: `crates/pvthfhe-pvss/src/nizk_share.rs:828, 949`
**Issue**: `bfv_sigma_binding_data(stmt, &[0u8; 32])` — the d_commitment parameter that binds the BFV sigma proof to the RLWE algebraic sigma proof is hardcoded to zero. An adversary can reuse a valid BFV sigma proof from a different statement.
**Fix**: Compute and pass `d_commitment = SHA256("pvthfhe-share-dcommit/v1" || session_id || recipient_index || share_commitment)` as done in `compute_share_d_commitment()`.
**Effort**: ~30 min

### H3 — derive_party_binding bypasses DKG anchoring
**File**: `crates/pvthfhe-aggregator/src/decrypt/mod.rs:177-178`, `crates/pvthfhe-pvss/src/nizk_decrypt.rs:448-454`
**Issue**: `expected_sk_agg_share` is derived from the party's self-claimed public key (`derive_party_binding(party_pk_bytes)`), not from a DKG-registered commitment. Any adversarial key satisfies the binding.
**Fix**: Look up `expected_sk_agg_share` from the DKG transcript's `DkgAnchorSet.sk_agg_commits[party_id]` instead of deriving from the self-claimed public key.
**Effort**: ~1 hr

### H4 — Sigma scalar challenge: 2/3 soundness error (P1)
**File**: `crates/pvthfhe-nizk/src/sigma.rs:519-556`
**Issue**: Ternary scalar challenge `ch ∈ {-1, 0, 1}` provides ~1.58 bits of soundness per execution. Single round means 2/3 soundness error. Acknowledged P1 open problem.
**Fix**: Deferred to P1. Document with explicit soundness budget annotation.
**Effort**: Documentation only

## MEDIUM Severity (4 findings)

### M1 — BFV sigma opaque binding_data
**File**: `crates/pvthfhe-nizk/src/bfv_sigma.rs:197, 282, 387-423`
**Fix**: Add `session_id: &[u8]` and `participant_id: u32` as first-class parameters (deferred L2 refactor).
**Effort**: Deferred

### M2 — Variable-length accumulator hashing
**File**: `crates/pvthfhe-cli/src/compressor_glue.rs:183-214`
**Fix**: Hash count prefix: `acc_hasher.update(&(num_accumulators as u64).to_be_bytes())`
**Effort**: ~15 min

### M3 — Shamir seed lacks session_id
**File**: `crates/pvthfhe-fhe/src/fhers.rs:467-481`
**Fix**: Pass `session_id` to `setup_threshold` and incorporate into seed derivation.
**Effort**: ~1 hr (API change)

### M4 — hash_all_coeffs without domain tag
**File**: `crates/pvthfhe-compressor/src/witness.rs:92-120`
**Fix**: Initialize Poseidon state with domain tag before absorption.
**Effort**: ~30 min

## Execution Order
1. H1 (nizk_share commitment seed) — 30 min
2. H2 (G.5 d_commitment) — 30 min
3. H3 (derive_party_binding DKG anchoring) — 1 hr
4. M2 (accumulator count prefix) — 15 min
5. M4 (hash_all_coeffs domain tag) — 30 min
6. M3 (Shamir seed session_id) — 1 hr
7. M1 (BFV sigma refactor) — deferred
8. H4 (sigma scalar challenge) — documented

## Success Criteria
- `cargo check --workspace` = 0 errors
- `just demo-e2e` runs with ACCEPT
- No new surrogates or dummy proofs introduced
