# A1 — Cyclo Accumulator Transcript Verification

**Status**: PLAN
**Parent**: meta-plan-all-deferred.md (Phase F, H.3)
**Created**: 2026-06-04

## Goal

Implement a real versioned Cyclo accumulator transcript plus a verifier wired to the Cyclo fold relation and the NIZK statement. Replace the current fail-closed stub that rejects all nonzero accumulator bytes with a cryptographically sound accumulator transcript verification path.

## Current State

### The Fail-Closed Gap

Cyclo accumulator transcript verification is **not implemented**. The NIZK proof encodes a `cyclo_accumulator_bytes` field at the proof trailer, but the verifier treats any nonzero accumulator length as a hard rejection. The only proofs that pass `CycloNizkAdapter::verify()` are those carrying the empty (`acc_len = 0`) non-folded placeholder, which represents the initial (empty, depth-0) fold state, not a folded accumulator at all.

**The exact fail-closed seam** lives at `crates/pvthfhe-nizk/src/adapter.rs:187-193`:

```rust
// line 187:
let acc_len = usize::try_from(cur.read_u32()?)
    .map_err(|_| NizkError::InvalidProof("acc_len overflow"))?;
if acc_len != 0 {
    return Err(NizkError::VerificationFailed(
        "cyclo accumulator present but unverified (fail-closed)",
    ));
}
```

The `cur.finish()` at line 195 then enforces that no trailing bytes follow. This means: if a prover encodes any accumulator bytes (nonzero `acc_len`), the verifier immediately rejects. Only a trailing `0u32::to_be_bytes()` (four zero bytes, meaning length=0) is accepted.

### Proof Encoding (Prove Side)

The prover side at `crates/pvthfhe-nizk/src/adapter.rs:599-601` also emits only the empty placeholder:

```rust
// Non-folded A1 placeholder: accumulator transcript verification is OPEN (A1)
// and unimplemented.
out.extend_from_slice(&0u32.to_be_bytes());
```

The encoding DSL is documented at lines 23-25 of the same file:

```
cyclo_accumulator_bytes  : u32 BE length=0 (non-folded A1 placeholder;
                           accumulator transcript verification is OPEN (A1)
                           and unimplemented)
```

### What DOES Exist (CycloFoldStepCircuit Validation — NOT Transcript Verification)

The `close-nova-gaps.md` plan (all 12/12 items checked, COMPLETE) addressed CycloFoldStepCircuit validation: porting sigma/ring/BFV verification to bellperson gadgets (Wave 3, deferred). This ensures per-step CCS satisfiability is checked (ccs_encode.rs:201-228, `check_satisfiability`) and fold recomputation is verified recompute-then-compare (fold.rs:360-375, `verify_fold_inner`). **But this is CycloFoldStepCircuit validation, not accumulator transcript verification.** The distinction matters because:

- CycloFoldStepCircuit checks that the fold relation is satisfied given a list of instances and an accumulator *in Rust memory*.
- Accumulator transcript verification checks that the *serialized bytes* in the NIZK proof trailer decode to a valid Cyclo accumulator and that the decoded accumulator matches the fold statement — bridging the NIZK adapter and the Cyclo fold verifier across the wire format boundary.

### The 26,658-Byte Minimum-Proof-Size Surrogate (NOT A1 Verification)

In `crates/pvthfhe-aggregator/tests/fold_e2e_soundness.rs:127-136`, note the `#[cfg_attr(not(feature = "real-nizk"), ignore = "...")]` attribute:

> "Under real-nizk this runs only as a 26,658-byte minimum-proof-size surrogate regression, NOT full A1 folded-accumulator transcript verification"

This test rejects 32-byte forged proofs using a size gate (proof must be at least 26,658 bytes — the size of version + ccs_id + Ajtai commitment). It is an adversarial-soundness test that checks the NIZK structure passes the size floor, **not an accumulator transcript verification test**. The 26,658-byte size is the minimum for a non-accumulator NIZK proof; a real accumulator transcript would be strictly larger.

## Relevant Source Files

### Primary Files (Where the Gap Lives)

| File | Lines | Role |
|------|-------|------|
| `crates/pvthfhe-nizk/src/adapter.rs` | 187-193, 599-601 | Fail-closed verify seam and empty prover placeholder |
| `crates/pvthfhe-nizk/tests/accumulator_fail_closed.rs` | 1-142 | Regression tests for current behavior |
| `crates/pvthfhe-cyclo/src/fold.rs` | 247-378 | `verify_fold` / `verify_fold_inner` — the Cyclo fold verifier |
| `crates/pvthfhe-cyclo/src/lib.rs` | 309-324 | `CycloAccumulator` struct (fields to encode/decode) |
| `crates/pvthfhe-cyclo/src/lib.rs` | 326-346 | `CycloError` enum (error variants for verification) |
| `crates/pvthfhe-cyclo/src/adapter.rs` | 29-35 | `verify_accumulator` dispatches to `fold::verify_fold` |

### Secondary Files (Context and Constraints)

| File | Lines | Role |
|------|-------|------|
| `crates/pvthfhe-cyclo/src/fiat_shamir.rs` | 1-118 | Fiat-Shamir challenge derivation (used by fold verifier) |
| `crates/pvthfhe-cyclo/src/ccs_encode.rs` | 40-56, 185-228 | `CcsRqInstance` and `check_satisfiability` — CCS instance encoding |
| `crates/pvthfhe-cyclo/src/lib.rs` | 238-249 | `PVTHFHE_CYCLO_PARAMS` — locked parameter set |
| `crates/pvthfhe-cyclo/src/lib.rs` | 280-298 | `MultiTrackPShareInstance` — multi-track fold support |
| `crates/pvthfhe-aggregator/tests/fold_e2e_soundness.rs` | 1-273 | Adversarial soundness tests (size surrogate, not transcript verif) |
| `docs/OPEN-PROBLEM-BLOCKERS.md` | 86-103 | Canonical problem description §A1 |

## Forbidden Shortcuts

Per `docs/OPEN-PROBLEM-BLOCKERS.md §A1.7`, the following are explicitly disallowed as remedies for this gap:

1. **Hash-only binding**: Computing a SHA-256 digest of the accumulator and comparing hashes, without verifying the fold relation itself. Hash binding does not prove the accumulator was produced by correctly folding honest instances.

2. **Fake Merkle / commitment roots**: Providing a synthetic root that claims to commit to a well-formed accumulator without the verifier reconstructing the leaf path. The verifier must independently recompute the accumulator from the instance list.

3. **Parser-only / framing-only validation**: Accepting accumulator bytes that parse as a `CycloAccumulator` without running `verify_fold`. The codec must be a step toward verification, not a substitute for it.

4. **Dummy or verifier-supplied folded instances**: Allowing the verifier to claim that certain instances were folded without the prover having committed to them. The transcript must carry the per-instance list in the proof itself, bound to the statement.

5. **Norm-bound checks over claimed metadata**: Accepting the `norm_bound_current` field from the decoded accumulator without recomputing it from the instances. The norm bound must be verified by (a) recomputing the accumulator from the instance list and (b) checking that every per-instance witness norm falls within the per-step budget.

6. **Treating `pvthfhe-cyclo` `verify_fold` unit tests as adapter integration evidence**: The Cyclo crate's internal fold verification tests demonstrate that the fold relation is correct in isolation. They do not prove that the NIZK adapter correctly decodes, stitches, and dispatches accumulator transcript bytes to `verify_fold`.

## Task Breakdown

### T1: Design the Versioned Accumulator Transcript Codec

Design a wire format for encoding a `CycloAccumulator` into `cyclo_accumulator_bytes` and decoding it back. The codec must be versioned so the wire format can evolve without breaking backward compatibility.

**Proposed wire format (design starting point):**

```
accumulator_version    : u16 BE = 0x0001
params_digest          : 32 bytes (SHA-256 of CycloParams, must match PVTHFHE_CYCLO_PARAMS)
fold_depth             : u32 BE
acc_commitment_bytes   : u32 BE len (must equal AJTAI_COMMITMENT_BYTES = 26624) + data
acc_public_io_bytes    : u32 BE len (must equal 32) + data
norm_bound_current     : u64 BE
session_id             : u32 BE len + data (UTF-8)
instance_count         : u32 BE (number of folded instances, must match fold_depth)
--per-instance section (repeated instance_count times):
  participant_id        : u16 BE
  ajtai_commitment_hash : 32 bytes (SHA-256 of the Ajtai commitment)
  public_io_binding     : 32 bytes (SHA-256 of public I/O, including multi-track metadata)
  sha256_binding        : 32 bytes
```

The per-instance section provides the verifier with the instance list needed to call `verify_fold`. The commitment hashes and public-IO hashes bind each instance cryptographically to the statement without including the full Ajtai commitment (26,624 bytes per instance) in the transcript.

**Constraints:**
- The version field must be validated first; unknown versions must reject.
- `params_digest` must match `fiat_shamir::params_digest_v1(b"pvthfhe-cyclo-params-v1")` to prevent cross-parameter-set confusion.
- `acc_commitment_bytes` length must exactly equal `AJTAI_COMMITMENT_BYTES` (26,624 bytes), matching the constraint in `fold.rs:324-328`.
- `acc_public_io_bytes` length must exactly equal 32 bytes, matching `fold.rs:330-334`.
- `instance_count` must match `fold_depth` (checked by the fold verifier at fold.rs:272-278).
- Each per-instance binding hash must match the corresponding entry in the NIZK statement. The verifier cross-checks the instance list against the statement's session_id, participant_id, and ciphertext/decrypt-share binding.

**Decision needed**: Whether to include the full serialized Ajtai commitment per instance (26,624 bytes × N instances, making the proof very large) or use hash references (32 bytes each, relying on the NIZK verification having already confirmed commitment integrity). The hash-reference approach is storage-friendly but must not fall afoul of the "hash-only binding" forbidden shortcut. The resolution is: hash references for the commitment *are acceptable only if* the full Ajtai commitment has already been cryptographically verified by the NIZK sigma proof (which includes `sha256_binding`). The accumulator transcript verifier re-derives the hash and checks equality, which serves as a binding check, not a standalone proof of accumulator correctness.

### T2: Implement Codec (Encode / Decode Functions)

**File**: New or extended module in `crates/pvthfhe-nizk/src/` (e.g., `accumulator_transcript.rs`) or in `crates/pvthfhe-cyclo/src/`.

Implement:
- `encode_accumulator_transcript(acc: &CycloAccumulator, instances: &[CcsPShareInstance]) -> Vec<u8>`: Serializes an accumulator and its instance list to the versioned wire format.
- `decode_accumulator_transcript(bytes: &[u8]) -> Result<(CycloAccumulator, Vec<AccumulatorInstanceRef>), NizkError>`: Deserializes the wire format, returning the reconstructed accumulator and instance references.
- Define `AccumulatorInstanceRef` struct with fields: `participant_id: u16`, `ajtai_commitment_hash: [u8; 32]`, `public_io_binding: [u8; 32]`, `sha256_binding: [u8; 32]`.

**Error handling**: Deserialization must return distinct errors for:
- Unknown version
- Truncated data at any field boundary
- Invalid lengths (commitment not 26,624 bytes, public IO not 32 bytes)
- `fold_depth != instance_count`
- Duplicate participant IDs
- `norm_bound_current` exceeding `PVTHFHE_CYCLO_PARAMS.beta_at_t`

**RED tests (write first, before implementation):**
1. `decode_rejects_unknown_version`: Feed bytes with version != 0x0001 → reject.
2. `decode_rejects_truncated`: Feed partial bytes at each field boundary → reject.
3. `decode_rejects_wrong_commitment_len`: Feed 26,623 bytes instead of 26,624 → reject.
4. `decode_rejects_wrong_public_io_len`: Feed 31 bytes instead of 32 → reject.
5. `decode_rejects_depth_mismatch`: Feed `fold_depth=3` with `instance_count=2` → reject.
6. `decode_rejects_norm_bound_exceeded`: Feed `norm_bound_current > beta_at_t` → reject.
7. `encode_decode_roundtrip`: Encode a valid accumulator + instance list, decode, check roundtrip equality.
8. `empty_accumulator_roundtrip`: Encode depth=0 accumulator with zero instances, decode, verify.

### T3: Wire Codec into the Prover Path

**File**: `crates/pvthfhe-nizk/src/adapter.rs`

Replace lines 599-601 (the current `0u32.to_be_bytes()` placeholder) with a call to `encode_accumulator_transcript`. The prover must:

1. Accept an `Option<&CycloAccumulator>` and `Option<&[CcsPShareInstance]>` parameter. When `None` (non-folded path), emit the empty placeholder `0u32` as today.
2. When `Some`, call `encode_accumulator_transcript(acc, instances)` and emit it into the proof byte stream.
3. The accumulator and instances must be supplied by the caller. For the C1/C4/C5/C7 Nova IVC paths, the Cyclo accumulator is constructed as part of the fold step. For the non-folded demo path, no accumulator is supplied.

**Interface change needed**: `NizkStatement` or a new proof-context parameter must carry the optional accumulator reference. This is the key design decision: whether to thread the accumulator through the existing `NizkStatement` type or through a separate proof-construction context.

**Decision needed**: Where does the prover get the accumulator from? Options:
- (A) Add an `Option<(CycloAccumulator, Vec<CcsPShareInstance>)>` field to `NizkStatement`. Simple but pollutes the statement type.
- (B) Add a separate `AccumulatorContext` parameter to `NizkAdapter::prove`. Cleaner separation.
- (C) Don't thread through prove() at all. Instead have the caller append accumulator bytes after `prove()` returns. Requires the caller to know the proof format, violating encapsulation.

Recommendation: Option (B) — add `accumulator_ctx: Option<&AccumulatorContext>` to the adapter trait's `prove` signature, where `AccumulatorContext` wraps `(&CycloAccumulator, &[CcsPShareInstance])`.

**RED tests (write first):**
1. `prove_with_accumulator_emits_nonzero_trailer`: Prove with accumulator → verify trailer bytes are non-empty and versioned.
2. `prove_without_accumulator_emits_empty_trailer`: Prove without accumulator → verify trailer is the current `0u32` placeholder.

### T4: Wire Codec into the Verifier Path (UNLOCK A1)

**File**: `crates/pvthfhe-nizk/src/adapter.rs`

Replace lines 187-193 (the fail-closed rejection) with:

```rust
if acc_len > 0 {
    let acc_bytes = cur.read_exact(acc_len)?.to_vec();
    let (acc, instance_refs) = decode_accumulator_transcript(&acc_bytes)?;
    verify_accumulator_transcript(stmt, &acc, &instance_refs)?;
}
```

The `verify_accumulator_transcript` function must:

1. **Decode** the accumulator transcript (T2's decode function).
2. **Cross-check** each `AccumulatorInstanceRef` against the NIZK statement: the `participant_id` and `sha256_binding` must match known statement fields. The `ajtai_commitment_hash` and `public_io_binding` must match values derivable from the statement.
3. **Reconstruct** `CcsPShareInstance` entries from the NIZK proof. The full Ajtai commitment bytes and public IO bytes are in the already-parsed NIZK proof body (lines 164 and 183-185 of adapter.rs). The verifier already holds these after parsing the non-accumulator prefix of the proof.
4. **Dispatch** to `fold::verify_fold(&acc, &reconstructed_instances)` (or `verify_fold_multitrack` for multi-track instances).
5. **Report** the result. If `verify_fold` returns `Ok(())`, the accumulator transcript verification passes. If it returns `Err(...)`, the NIZK verification fails with a descriptive error.

**Critical ordering**: The accumulator transcript must be verified *after* the sigma proof (line 209-215) and the pvss commitment binding (line 217-221). This ensures the per-instance cryptographic bindings are intact before the fold verifier trusts the reconstructed instances.

**RED tests (write first):**
1. `verify_rejects_wrong_statement_hash`: Modify the accumulator transcript so one instance's `sha256_binding` doesn't match the statement → reject.
2. `verify_rejects_wrong_commitment_root`: Modify `acc_commitment_bytes` in the transcript → `verify_fold` recomputation mismatch → reject.
3. `verify_rejects_norm_bound_violation`: Modify `norm_bound_current` to exceed `beta_at_t` → reject (before `verify_fold`), or encode a witness whose norm exceeds per-step budget → `verify_fold` reject.
4. `verify_rejects_wrong_instance_count`: Set `fold_depth=3` but include only 2 instances → reject.
5. `verify_rejects_wrong_params_digest`: Use params_digest from a different parameter set → reject.
6. `verify_accepts_honest_accumulator`: Fold a real sequence of instances, encode, verify → accept.

### T5: Adversarial Test Suite

**File**: `crates/pvthfhe-nizk/tests/accumulator_transcript_adversarial.rs` (new)

Implement adversarial tests that attempt to produce an accepted accumulator transcript without satisfying the fold relation. These are the A1 analogs of the `fold_e2e_soundness.rs` tests but operate at the accumulator transcript layer.

**Tests:**

1. `adversary_cannot_bypass_with_hash_only`: Attacker provides a well-formed transcript with correct hash bindings but the commitment bytes don't reconstruct to a fold that satisfies `verify_fold`. The verifier must recompute and reject.

2. `adversary_cannot_bypass_with_fake_merkle_root`: Attacker provides a commitment root that matches the transcript hash but `verify_fold` recomputes a different commitment. Rejection.

3. `adversary_cannot_bypass_with_parser_only`: Attacker provides syntactically valid transcript bytes but encoded instance commitments don't match the actual Ajtai commitments in the proof body. Cross-check must reject.

4. `adversary_cannot_bypass_with_claimed_norm_bound`: Attacker claims `norm_bound_current = 100` but actual recomputed norm is 5000. `verify_fold` recomputation must detect overflow.

5. `adversary_cannot_bypass_with_wrong_instance_count`: Attacker sets `instance_count = 5` but only provides 3 instances in the proof body. Cross-check rejects.

6. `adversary_cannot_reuse_across_sessions`: Transcribe an accumulator from session A into a proof for session B. Session ID mismatch in cross-check must reject.

7. `adversary_cannot_skip_intermediate_fold`: Attacker provides only the final accumulator without intermediate instances. The verifier must check that `fold_depth == instance_count` and both match.

### T6: Update Existing Fail-Closed Tests

**File**: `crates/pvthfhe-nizk/tests/accumulator_fail_closed.rs`

Once T4 is complete:

1. The test `accumulator_nonzero_transcript_bytes_fail_closed` (lines 79-103) must be updated. After T4, nonzero accumulator bytes that decode and verify correctly should be *accepted*, not rejected. The test must now verify that *invalid* nonzero accumulator bytes (e.g., with tampered commitment bytes) still reject, but *valid* nonzero accumulator bytes are accepted.
2. The test `accumulator_nonzero_length_without_bytes_fails_closed` (lines 107-129) must remain. A nonzero length prefix without corresponding bytes is a framing-level error that must still reject.
3. The test `accumulator_empty_placeholder_honest_proof_still_verifies` (lines 132-142) must remain. The empty (non-folded) placeholder path must still work.

Add new tests:
4. `valid_accumulator_transcript_accepted`: Construct a real fold, encode it as an accumulator transcript, append to proof, verify → accept.
5. `accumulator_too_many_bytes_rejected`: Encode a valid transcript, pad with extra trailing bytes → reject (the `cur.finish()` at line 195 already catches this).

### T7: Size Gate Documentation

**File**: `crates/pvthfhe-aggregator/tests/fold_e2e_soundness.rs`

Update the `#[cfg_attr(not(feature = "real-nizk"), ignore = "...")]` attributes on tests (lines 133-136, 164-167, 198-201) to reflect that this only tests the NIZK minimum proof size. Once A1 is solved, the fold-e2e-soundness tests should be updated to use real accumulator transcript verification rather than the size gate. This is tracked as a follow-on task, not required for A1 closure.

### T8: Multi-Track (H.2) Support

**File**: `crates/pvthfhe-cyclo/src/lib.rs:280-298`

If the accumulator transcript encodes `MultiTrackPShareInstance` instances (those with `multi_track_metadata: Some(...)`), the verifier must:

1. Decode the per-instance metadata from the transcript.
2. Construct `MultiTrackPShareInstance` entries from decoded data.
3. Dispatch to `fold::verify_fold_multitrack` instead of `fold::verify_fold`.

The codec must include a per-instance flag indicating whether multi-track metadata is present and, if so, encode the `MultiTrackFoldMetadata` canonical bytes (lib.rs:81-110).

## Acceptance Criteria

- [ ] **AC1**: An honest folded accumulator transcript decodes, verifies, and is accepted by `CycloNizkAdapter::verify()`.
- [ ] **AC2**: Random bytes in the accumulator trailer field are rejected (not just by the length check, but by the codec or fold verifier).
- [ ] **AC3**: A transcript with one instance's statement hash tampered (e.g., mismatched `sha256_binding`) is rejected.
- [ ] **AC4**: A transcript with a wrong final commitment (tampered `acc_commitment_bytes`) is rejected.
- [ ] **AC5**: A transcript with `norm_bound_current` exceeding `beta_at_t` (1344), or whose per-instance witness norms exceed the per-step budget, is rejected.
- [ ] **AC6**: A transcript claiming `fold_depth = 3` but containing only 2 instances is rejected.
- [ ] **AC7**: A transcript with a `params_digest` that doesn't match `PVTHFHE_CYCLO_PARAMS` is rejected.
- [ ] **AC8**: A transcript with duplicate participant IDs is rejected.
- [ ] **AC9**: An empty (`acc_len = 0`) non-folded placeholder still verifies (backward compatibility).
- [ ] **AC10**: All existing `accumulator_fail_closed.rs` tests pass (updated for new behavior).
- [ ] **AC11**: All new adversarial tests in `accumulator_transcript_adversarial.rs` pass.
- [ ] **AC12**: `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-nizk accumulator -- --nocapture` passes.
- [ ] **AC13**: `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-cyclo fold_verify -- --nocapture` passes.

## Out of Scope

1. **P1 Lattice NIZK soundness**: Accumulator transcript verification depends on the NIZK sigma proof having cryptographic soundness (P1). The accumulator transcript layer does not fix P1. It verifies the fold relation given instances that the NIZK sigma proof has already bound.

2. **P2 LatticeFold+ over RLWE**: The Cyclo fold verifier (`fold::verify_fold`) uses the current Nova-substitute Cyclo commitment scheme. Full adoption of LatticeFold+ (Symphony with T1 high-arity and T2 FS outside circuit) is tracked in P2, not A1.

3. **In-circuit accumulator verification**: The CycloFoldStepCircuit validates per-step CCS satisfiability. Full in-circuit accumulator transcript verification (recomputing the fold in Noir) is a separate problem tracked under P2 and P4 (on-chain IVC). A1 only covers the Rust-verifier path.

4. **Proof size optimization**: The accumulator transcript adds data to every NIZK proof. Optimizations (e.g., compressed instance representations, batch accumulator Merkle proofs) are follow-on work.

5. **Real-NIZK feature gate unification**: The `real-nizk` and `real-folding` feature flags are separate from A1. The accumulator transcript should work with both the current surrogate path and the real-NIZK path.

## Verification Commands

```bash
# Full accumulator test suite (requires research-build flag)
PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-nizk accumulator -- --nocapture

# Cyclo fold verifier unit tests
PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-cyclo fold_verify -- --nocapture

# Adversarial accordion test suite (once T5 is implemented)
PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-nizk accumulator_transcript_adversarial -- --nocapture

# End-to-end fold soundness (size surrogate, after A1 closure update)
cargo test -p pvthfhe-aggregator fold_e2e_soundness --features real-folding,real-nizk -- --nocapture
```

## Cross-References

- `docs/OPEN-PROBLEM-BLOCKERS.md §A1` (lines 86-103): Canonical problem description
- `.sisyphus/plans/close-nova-gaps.md` (12/12 checked, COMPLETE): CycloFoldStepCircuit validation done; A1 accumulator transcript NOT addressed
- `.sisyphus/plans/meta-plan-all-deferred.md` (H.3): This plan is the H.3 deliverable
- `SECURITY.md` (lines 66-68, 86-88): Security caveats mentioning A1
- `WARNING.md`: Known surrogates list
