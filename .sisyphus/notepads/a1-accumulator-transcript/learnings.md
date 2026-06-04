# A1 Learnings

## 2026-06-04: Plan Creation

### Source Files Mapped

- **Fail-closed seam**: `crates/pvthfhe-nizk/src/adapter.rs:187-193` — the exact 7-line code block that rejects all nonzero accumulator bytes
- **Prover placeholder**: `crates/pvthfhe-nizk/src/adapter.rs:599-601` — emits `0u32.to_be_bytes()` as empty placeholder
- **Encoding DSL**: `crates/pvthfhe-nizk/src/adapter.rs:23-25` — documents the `cyclo_accumulator_bytes` field
- **CycloAccumulator struct**: `crates/pvthfhe-cyclo/src/lib.rs:309-324` — 7 fields to encode/decode
- **CycloError enum**: `crates/pvthfhe-cyclo/src/lib.rs:326-346` — error variants relevant for transcript verification
- **verify_fold**: `crates/pvthfhe-cyclo/src/fold.rs:247-378` — the fold verifier to wire to
- **verify_accumulator dispatch**: `crates/pvthfhe-cyclo/src/adapter.rs:29-35` — adapter delegates to `fold::verify_fold`
- **Fail-closed tests**: `crates/pvthfhe-nizk/tests/accumulator_fail_closed.rs` — 3 existing tests, lines 79-142
- **Size surrogate**: `crates/pvthfhe-aggregator/tests/fold_e2e_soundness.rs:127-136,164-167,198-201` — igonre attributes documenting 26,658-byte size gate

### Key Distinction: CycloFoldStepCircuit Validation vs Accumulator Transcript

The `close-nova-gaps.md` plan (COMPLETE, 12/12 checked) resolved CycloFoldStepCircuit validation: CCS satisfiability is checked in Rust via `check_satisfiability` (ccs_encode.rs:201-228) and fold recomputation is verified by `verify_fold_inner` (fold.rs:360-375). But this is in-memory validation within the Rust process, not accumulator transcript verification across the wire-format boundary between the NIZK adapter and the Cyclo fold verifier.

### Size Surrogate Clarified

The 26,658-byte minimum-proof-size check in `fold_e2e_soundness.rs` enforces that proof bytes are large enough to contain a non-accumulator NIZK proof (version + ccs_id + Ajtai commitment). It is not A1 verification. A real accumulator transcript will make proofs significantly larger than this minimum.

### Multi-Track (H.2) Impact

The codec must handle both single-track (`CcsPShareInstance`) and multi-track (`MultiTrackPShareInstance`) fold paths. The latter includes `MultiTrackFoldMetadata` (lib.rs:281-298) which binds session_id, participant_id, party_binding, instance_count, and per-track commitments/norm-bounds. The transcript must encode a flag per instance indicating whether multi-track metadata is present.

### Interface Design Decision: How to Thread Accumulator into Prove

Three options considered:
- (A) `NizkStatement` field: simple but pollutes the statement type
- (B) Separate `AccumulatorContext` parameter: clean separation
- (C) Post-hoc append: violates encapsulation

Recommendation: Option (B), which requires modifying the `NizkAdapter` trait's `prove` signature.
