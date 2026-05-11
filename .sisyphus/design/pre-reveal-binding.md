# Pre-Reveal Binding — Atomic Plaintext Release Design

> **Status**: DRAFT — R8.2 GATE artifact  
> **Date**: 2026-05-09  
> **Fixes**: F57, F67  
> **References**: `.sisyphus/plans/pvthfhe-remediation.md` §R8.2, `SECURITY.md` §SEC-7, `.sisyphus/design/proof-boundary.md`

## 1. Context

### 1.1 The Plaintext Release Problem

In the PVTHFHE threshold decryption pipeline, the aggregator collects partial
decryption shares from ≥t parties, folds them through the aggregation layer (P2,
Cyclo/Sonobe), compresses the fold witness (P3, MicroNova/UltraHonk), and
produces a final proof for on-chain verification. **The plaintext MUST NOT be
released until every step of this chain has been cryptographically verified.**

Audit finding **F57** documents that the prototype pipeline decouples plaintext
recovery from the proof system: `aggregate_decrypt` returns plaintext via BFV
recombination without the fold-compressed proof ever being produced or verified.
A malicious aggregator could:

- Substitute shares from a different DKG session (cross-session forgery)
- Replay shares from a prior epoch (replay attack)
- Claim decryption succeeded without producing any verifiable proof (audit bypass)
- Use different RLWE parameters than the agreed canonical set (parameter
  downgrade attack)

### 1.2 Design Goal

The pre-reveal binding enforces a single, atomic gate:

> Plaintext is released **if and only if** (a) all partial decryption shares carry
> valid NIZK proofs, (b) the fold-compressed proof verifies against the canonical
> parameters, and (c) the full binding tuple matches the session context.

Until all three conditions hold, the aggregator MUST NOT return plaintext to
any caller.

## 2. Full Tuple Binding

### 2.1 Tuple Components

The pre-reveal binding commits **seven components** atomically into the fold
transcript, sourced from the RED test `pre_reveal_binding_tuple.rs` (102 lines,
`crates/pvthfhe-cli/tests/`):

| # | Component | Type | Source |
|---|-----------|------|--------|
| 1 | `session_id` | `bytes32` | `keygen_session_id()` at `full_pipeline.rs:307` — `SHA-256("pvthfhe-e2e/keygen_nizk/v1" ∥ seed_be ∥ threshold_be ∥ SHA-256(aggregate_pk))` |
| 2 | `epoch` | `u64` | `PipelineConfig.seed` (transitioning to dedicated epoch/nonce; reuses seed for current prototype) |
| 3 | `ct_hash` | `bytes32` | `sha256_bytes(&ciphertext.bytes)` at `full_pipeline.rs:202` |
| 4 | `roster_hash` | `bytes32` | Maps to `participant_set_hash: [u8; 32]` — Keccak256 of ABI-encoded participant set, produced by `KeygenSimulator::participant_set_hash()` in `keygen/simulator.rs:85`. Corresponds to proof-boundary public input #6. |
| 5 | `param_hash` | `bytes32` | SHA-256 of `parameters.toml` canonical encoding (or `CycloParams` canonical bytes when Cyclo is the fold backend) |
| 6 | `srsHash` | `bytes32` | SRS commitment hash from `Compressor::srs_hash()` at `compressor/src/sonobe/mod.rs:232` — Keccak256 of (epoch, step-circuit hash, backend ID) |
| 7 | `dkg_root` | `bytes32` | DKG transcript Merkle root from keygen — corresponds to proof-boundary public input #4 |

### 2.2 Binding Construction

The tuple is committed via **Poseidon over the BN254 scalar field**, consistent
with the P3 proof layer parameterisation (`spec-real-p2p3.md` §5.4):
```
pre_reveal_binding = Poseidon_BN254(
    session_id ∥ epoch_le ∥ ct_hash ∥ roster_hash ∥ param_hash ∥ srsHash ∥ dkg_root
)
```

**Rationale for Poseidon over SHA-256**: The P2→P3 encoding step connects the
Cyclo accumulator to a MicroNova IVC chain over BN254. Poseidon is natively
efficient in BN254 R1CS and avoids the `HASH-to-HAC RoK` bridge that SHA-256
would require. The binding carries into the on-chain verifier as a public input
without extra cross-hash translation.

**Fallback**: If the P3 gate confirms SHA-256 as the canonical on-chain hash,
the binding switches to `SHA-256(...)` — both are equivalent for the binding's
security purpose (collision resistance).

### 2.3 Where Binding Is Enforced

| Level | Check | Enforcement Point |
|-------|-------|-------------------|
| **Rust aggregator (B)** | Pre-reveal gate: refuses plaintext unless `pre_reveal_binding` matches expected tuple | `full_pipeline.rs` — before `aggregate_decrypt` |
| **Inside SNARK (A)** | The final UltraHonk proof embeds `pre_reveal_binding` as public input #0, binding the accepted proof to this exact session | Noir circuit `main.nr` (per `proof-boundary.md` §Accumulator Encoding) |
| **Solidity verifier (C)** | `IPvthfheVerifier.verify(...)` enforces proof validity against all 7 frozen public inputs | `PvtFheVerifier.sol` |

### 2.4 Current Implementation Status

As of the current working tree (`build_fold_instances` at `full_pipeline.rs:322`):

| Field | Status |
|-------|--------|
| `session_id` | **MISSING** from `build_fold_instances` binding — only used in `keygen_session_id` and per-dealer NIZK statement, not in pre-reveal hasher |
| `epoch` | **PARTIAL** — `seed.to_le_bytes()` is a proxy; not a dedicated epoch field |
| `ct_hash` | **PRESENT** — `binding_hasher.update(ct_hash)` at line 340 |
| `roster_hash` | **MISSING** — `participant_set_hash` exists in keygen but not in pre-reveal hasher |
| `param_hash` | **MISSING** — no canonical parameter hash in pipeline |
| `srsHash` | **MISSING** — `Compressor::srs_hash()` exists but not bound to pre-reveal |
| `dkg_root` | **MISSING** — not produced or consumed in current pipeline |

The RED test `binding_currently_missing_fields` at
`pre_reveal_binding_tuple.rs:66` passes, confirming fields are absent. The GREEN
fix must add all seven to a `Sha256` (or Poseidon) hasher in the pipeline
before any plaintext is released.

## 3. Atomicity Guarantee

### 3.1 The Atomic Gate

```
release_plaintext(plaintext) ⇔
    (∀i ∈ S: verify_nizk(share_i.nizk) == VALID)                           // (A) Per-share WF
    ∧ verify_fold_compressed(all_shares, binding_tuple, compressed_proof) == ACCEPT  // (B) Proof valid
    ∧ binding_tuple == expected_tuple(session_context)                     // (C) Context match
```

Where `S` is the set of submitted partial decryption shares (`|S| ≥ t`),
`verify_nizk` checks the Greco/MPCitH per-share NIZK proof, and
`verify_fold_compressed` runs the full Cyclo fold + compressor + UltraHonk path.

**If any condition fails, the aggregator MUST return an error without
performing BFV recombination.** The FHE backend's `decode` operation is never
invoked until all checks pass.

### 3.2 F67: Submitted Shares, Not Internal State

Audit finding **F67** documents that `aggregate_decrypt` silently recomputes
decryption shares from internal `PartyState` by `party_id`, discarding the
submitted share bytes. This means:

- A malicious aggregator submits garbage share bytes but still recovers the
  correct plaintext (since internal state is used)
- The binding to `ct_hash` becomes meaningless — the ciphertext proved in the
  NIZK can differ from the ciphertext actually decrypted

The GREEN fix (`aggregate_uses_submitted_shares.rs`, 78 lines,
`crates/pvthfhe-fhe/tests/`) enforces that `aggregate_decrypt` MUST consume
the **submitted** share bytes — parsed, validated, and used directly for BFV
recombination. Internal state is never consulted during decryption.

### 3.3 Proof-Before-Plaintext API Contract

```rust
/// Atomic pre-reveal gate. Returns plaintext only if ALL conditions hold.
///
/// # Errors
/// - `RevealError::ProofVerifyFailed` — any NIZK proof is invalid
/// - `RevealError::BindingMismatch { field, expected, actual }` — tuple mismatch
/// - `RevealError::ReplayDetected { run_id }` — runId already consumed
fn guarded_aggregate_decrypt(
    backend: &impl FheBackend,
    ct: &Ciphertext,
    shares: &[PartialDecryptionShare],
    threshold: usize,
    expected_binding: &PreRevealBinding,
    compressed_proof: &CompressedProof,
) -> Result<Vec<u8>, RevealError>;
```

## 4. Replay Protection

### 4.1 `runId` Concept

Each ceremony run produces a unique `runId`:

```
runId = SHA-256(session_id ∥ epoch ∥ ct_hash ∥ rand_nonce)
```

Where `rand_nonce` is sampled from `OsRng` at ceremony start.

The `runId` is:
1. Included in the pre-reveal binding tuple (extending the 7-field binding when
   replay protection is active)
2. Stored in the aggregator's consumed-set: once a `runId` has been used to
   release plaintext, it is permanently consumed (no reuse)
3. Passed through the fold transcript as part of the domain separator

### 4.2 Attack Vectors Prevented

| Attack | How pre-reveal binding prevents it |
|--------|-----------------------------------|
| Cross-session share substitution | `session_id` blocks shares from different DKG ceremonies |
| Cross-epoch replay | `epoch` prevents re-submission from a prior epoch |
| Ciphertext substitution | `ct_hash` ties the proof to the exact ciphertext |
| Participant-set manipulation | `roster_hash` prevents claiming decryption from a different participant set |
| Parameter downgrade | `param_hash` blocks use of weaker RLWE parameters |
| SRS swap | `srsHash` prevents substitution of a weaker or backdoored reference string |
| DKG manipulation | `dkg_root` prevents claiming shares from a different keygen ceremony |
| Repeated decryption claim | `runId` consumption prevents the aggregator from claiming the same result twice |

## 5. Implementation Sketch

### 5.1 Files and Tests

| File | Role |
|------|------|
| `crates/pvthfhe-cli/src/full_pipeline.rs` | Pipeline driver: constructs binding tuple, enforces pre-reveal gate (`build_fold_instances` at L322) |
| `crates/pvthfhe-cli/tests/pre_reveal_binding_tuple.rs` | RED: asserts all 7 field names appear in `binding_hasher.update(...)` calls (102 lines) |
| `crates/pvthfhe-cli/tests/atomic_decrypt.rs` | RED/GREEN: tampered NIZK → no plaintext returned (78 lines) |
| `crates/pvthfhe-aggregator/tests/no_plaintext_without_proof.rs` | RED: `aggregate_decrypt` returns error if NIZK proof invalid (61 lines) |
| `crates/pvthfhe-fhe/tests/aggregate_uses_submitted_shares.rs` | RED/GREEN: F67 — consumes submitted share bytes, not internal state (78 lines) |
| `crates/pvthfhe-aggregator/src/decrypt/mod.rs` | Aggregator decrypt: NIZK-verify-before-plaintext gate |
| `crates/pvthfhe-fhe/src/fhers.rs` | FHE backend: consumes submitted shares (GREEN F67 fix at L626-654) |
| `crates/pvthfhe-aggregator/tests/adversarial/replay.rs` | Replay protection: `runId` consumption + double-spend rejection |

### 5.2 Integration with Fiat-Shamir Transcript

The `pre_reveal_binding` is included in the Cyclo fold transcript as a
domain-separated input:
```
"pvthfhe/pre-reveal-binding/v1/" ∥ hex(pre_reveal_binding)
```
This ensures the fold proof is non-malleably bound to the session context
before any plaintext is released.

### 5.3 Relationship to Proof Boundary

The pre-reveal binding closes the gap between three enforcement layers
(from `.sisyphus/design/proof-boundary.md`):

- **PB-07 (Replay prevention)**: `runId` consumption provides the primary-B
  check previously off-chain only
- **PB-10 (Proof binding)**: `pre_reveal_binding` appears inside the SNARK as
  a public input, enforcing session-context binding at the Solidity verifier
- **PB-12 (Parameter consistency)**: `param_hash` in the binding ensures the
  on-chain verifier rejects proofs computed under different parameters

### 5.4 GREEN Implementation Steps

1. Add `roster_hash`, `param_hash`, `srsHash`, `dkg_root`, and `session_id`
   (as a 32-byte hash) to the `build_fold_instances` binding hasher
2. Replace `seed.to_le_bytes()` with a dedicated `epoch` field (u64 LE in
   hasher input)
3. Add `runId` generation at pipeline start and include in binding tuple
4. Implement `guarded_aggregate_decrypt` gate: NIZK verify → fold verify →
   binding check → BFV recombination
5. Verify `binding_currently_missing_fields` transitions from RED (some
   fields missing) to GREEN (all fields present, test passes)

## 6. Open Questions

1. **Poseidon vs SHA-256**: The choice of Poseidon for in-circuit binding is
   pending P3 gate confirmation that Poseidon-BN254 is the canonical hash for
   the MicroNova IVC chain. If SHA-256, the binding switches — both are
   equivalent for collision resistance.
2. **`runId` nonce source**: Fresh `OsRng` is simpler but requires the
   aggregator to store the nonce. FS-derivation from the transcript is
   deterministic but couples run identity to proof structure. Default:
   `OsRng` sample at ceremony start.
3. **Partial decryption share digests**: Per-party NIZK proof digests are
   consumed at the fold level (`build_fold_instances`) rather than at the
   pre-reveal gate. This avoids duplicating per-share checks but should be
   reviewed for completeness — a malicious aggregator could submit a valid
   NIZK + wrong share value.
4. **`dkg_root` content**: The DKG transcript Merkle root must be agreed upon
   before keygen completes and must be available at decryption time. The
   current pipeline does not produce or consume a `dkg_root`; this requires
   R1 (DKG) to land first.

## 7. References

| Source | Description |
|--------|-------------|
| `.sisyphus/plans/pvthfhe-remediation.md` §R8.2 | Atomic plaintext release plan |
| `.sisyphus/design/proof-boundary.md` | Frozen proof boundary (PB-07, PB-10, PB-12) |
| `.sisyphus/design/spec-real-p2p3.md` §2 | 7 frozen public inputs |
| `.sisyphus/design/threat-model-v1.md` §SEC-7 | Session binding property |
| `.sisyphus/audit/AUDIT-2026-05-08.md` F57, F67 | Original audit findings |
| `crates/pvthfhe-cli/src/full_pipeline.rs` | Pipeline driver with `build_fold_instances` |
| `crates/pvthfhe-cli/tests/pre_reveal_binding_tuple.rs` | RED test: 7-field tuple check (102 lines) |
| `crates/pvthfhe-cli/tests/atomic_decrypt.rs` | RED/GREEN test: tampered NIZK → no plaintext (78 lines) |
| `crates/pvthfhe-fhe/tests/aggregate_uses_submitted_shares.rs` | F67 test: submitted shares, not internal state (78 lines) |
| `crates/pvthfhe-compressor/src/sonobe/mod.rs` | `srs_hash()` method at L232 |
