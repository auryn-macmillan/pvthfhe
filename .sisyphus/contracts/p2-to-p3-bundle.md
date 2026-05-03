# P2→P3 Downstream Contract Bundle

This bundle freezes the P2 implementation handoff that P3 must consume. It is produced after IG-P2 passes all subchecks. P3 must not assume any accumulator internals or proof structure beyond the surface defined here.

---

## 1. Frozen Accumulator Format

The following types are the canonical P2 output surface as of the `real-folding` feature in `crates/pvthfhe-aggregator/src/folding/mod.rs`.

### `FoldAccumulator`

```
FoldAccumulator binary encoding (encode_accumulator):
  [8B  acc_commitment_len ] u64, big-endian
  [32B acc_commitment     ] SHA-256 digest (current impl); backend-defined in full LatticeFold+
  [8B  fold_depth         ] u64, big-endian
  [8B  session_id_len     ] u64, big-endian
  [N   session_id         ] UTF-8 bytes (variable length)
  [8B  params.q           ] u64 = 65537, big-endian
  [8B  params.N           ] u64 = 1024 (or 128/512), big-endian
  [8B  params.B_e         ] u64 = 17, big-endian
  [32B statement_hash_chain] SHA-256 rolling hash over all folded statements
```

Total wire size (n=1024, session_id="pvthfhe-session-001"): 99 bytes (confirmed by bench/p2 `acc_size_bytes`).

### `FinalProof`

```rust
pub struct FinalProof {
    pub proof_bytes: Vec<u8>,  // 32 bytes: SHA-256("pvthfhe/finalize/v1" || encode_accumulator(acc))
}
```

The `finalize()` function produces:
```
proof_bytes = SHA-256("pvthfhe/finalize/v1" || encode_accumulator(acc))
```

This yields exactly **32 bytes** regardless of fold depth — well within the ≤ 14 KB target from P2-T5.

**Surrogate note:** The current `FoldAccumulator.acc_commitment` is itself a SHA-256 hash (not a real lattice commitment). The full LatticeFold+ algebraic commitment will replace `acc_commitment` internals without changing the `encode_accumulator` framing.

### Frozen parameters

| Parameter | Value | Frozen as of |
|-----------|-------|--------------|
| `q`       | 65537 | P1→P2 bundle |
| `N`       | 1024 (bench sizes: 128, 512, 1024) | P1→P2 bundle |
| `B_e`     | 17    | P1→P2 bundle |
| `finalize` tag | `"pvthfhe/finalize/v1"` | IG-P2 |

---

## 2. On-Chain Verifier Op-Budget

**Obligation source:** `docs/security-proofs/p2/T5.md` — VERDICT: APPROVE (partially discharged).

P3 must verify the terminal `FinalProof` on-chain. For the current surrogate implementation the on-chain work is:

| Operation | Gas estimate | Notes |
|-----------|-------------|-------|
| SHA-256 preimage check (32-byte input) | ~60 + 12 gas | EVM precompile `0x02` |
| Seven public-input equality checks | ~7 × 30 = 210 gas | `keccak256` or direct comparison |
| Total (current surrogate) | ~500 gas | Far under 5M budget |

**Phase D obligation:** For full LatticeFold+ with algebraic commitment, on-chain verification requires either a native Solidity/Yul lattice verifier or a P3 wrapping proof (e.g., UltraHonk over the LatticeFold+ verifier circuit). Gas for the full path is **not yet measured** and is a Phase D deliverable. The 5M gas cap remains the target.

**O(1) verifier property (design target):** The EVM verifier checks only the terminal accumulator state; it does not re-scan individual fold steps. Demonstrated at `d=10` for the surrogate; Phase D must confirm for the algebraic path.

---

## 3. Public-Input Encoding

`P3PublicInputs` is serialized as a fixed 200-byte blob in the following order. All hash fields are exactly 32 bytes; `epoch` is big-endian u64 (8 bytes).

| Field | Byte offset | Byte length | Derivation |
|-------|------------|------------|------------|
| `ciphertext_hash` | 0 | 32 | `SHA-256(concat of all nizk_statement.ciphertext_bytes for participating parties, ordered by participant_id)` |
| `plaintext_hash` | 32 | 32 | `SHA-256` of aggregated plaintext; filled by P3 after decryption aggregation |
| `aggregate_pk_hash` | 64 | 32 | `SHA-256(aggregated BFV public key from DKG session)` |
| `dkg_root` | 96 | 32 | Inherited from the P4 PVSS session root |
| `epoch` | 128 | 8 | Fold session epoch number (big-endian u64) |
| `participant_set_hash` | 136 | 32 | `SHA-256` of the ordered participant id list |
| `d_commitment` | 168 | 32 | Terminal `acc.statement_hash_chain` |

**Total: 6 × 32 + 8 = 200 bytes.** (Note: T5.md flags a minor discrepancy — 7 × 32 = 224 > 200 — which is resolved by encoding `epoch` as 8 bytes rather than 32.)

`d_commitment` is the terminal ordered-statement digest that links the final proof back to the entire fold history. P3 must treat it as an opaque 32-byte binding commitment.

---

## 4. Security Caveats

The following limitations are inherited by P3 and must be acknowledged in any downstream security claim.

1. **Surrogate default.** The default Cargo feature `surrogate-folding` uses a hash-chain accumulation, NOT a real LatticeFold+ accumulation. The `real-folding` feature enables the `RealFoldingScheme` implementation, which uses SHA-256-based commitment chains but still does not instantiate a lattice-algebraic commitment scheme. **P3 must not treat the current `FinalProof` as having LatticeFold+ soundness.** The gate passes for implementation completeness, not surrogate retirement.

2. **T4 norm-bound obligation (open).** P2-T4 (norm-bound preservation across fold boundary) is flagged as an open obligation requiring Phase D discharge. The current `validate_witness` function uses a surrogate integrity check (all-equal bytes) rather than a true norm-bound verification. P3 must not assume norm-bound correctness is enforced.

3. **SHA-256 non-ZK caveat.** The `statement_hash_chain` and `acc_commitment` use SHA-256, which is not ZK. The hash-chain reveals the ordered sequence of statement hashes to any party who can compute SHA-256 evaluations. Full ZK for the accumulator transcript requires the real LatticeFold+ algebraic commitment, deferred to Phase D.

4. **Surrogate status of current implementation.** `RealFoldingScheme` in `crates/pvthfhe-aggregator/src/folding/mod.rs` is a surrogate for the eventual LatticeFold+ prover. It passes adversarial rejection tests (15/15) and parametric consistency checks, but its witness validation is a structural check, not a cryptographic proof. IG-P2 certifies implementation completeness; it does not retire the surrogate.

5. **P1 HVZK inheritance.** The inner `NizkProof` (from P1) is honest-verifier zero-knowledge only. This weakness propagates into P2: the folded accumulator does not hide the inner P1 witness openings from a malicious verifier who can compute the fold transcript. Full (malicious-verifier) ZK is not claimed at any layer.

6. **Challenge-space soundness.** The P1 sigma-protocol uses a ternary challenge set `{-1, 0, 1}` with soundness error 1/3 per round. Composition into P2 folding inherits this soundness gap. Negligible soundness requires either parallel repetition or a larger challenge space, both deferred to T4/Phase D.

---

## 5. Regression Baseline

The following benchmark files constitute the frozen P2 surrogate timing baseline:

| File | n | Fold depth | Fold time (µs) | Finalize time (µs) | Proof size (bytes) | Acc size (bytes) |
|------|---|-----------|---------------|-------------------|-------------------|-----------------|
| `bench/p2/results-128.json` | 128 | 10 | (see file) | (see file) | 32 | (see file) |
| `bench/p2/results-512.json` | 512 | 10 | (see file) | (see file) | 32 | (see file) |
| `bench/p2/results-1024.json` | 1024 | 10 | ~276 µs | ~5.5 µs | 32 | 99 |

**Implementation note:** All timings are surrogate hash-chain timings, not real LatticeFold+ lattice prover timings. The real LatticeFold+ prover is expected to be orders of magnitude slower. These baselines serve as structural regression guards only.

**Regression policy:** Any change to `FoldingAccumulator`, `RealFoldingScheme`, or the `encode_accumulator`/`finalize` serialization that results in `proof_size_bytes ≠ 32` or `acc_size_bytes` growth beyond 2× baseline requires a new review before merging.

Evidence archived at `.sisyphus/evidence/p2-impl/bench.txt`.

---

## 6. Gas Projections

**Source:** `docs/security-proofs/p2/T5.md` — On-chain Verifier Compatibility.

| Scenario | Proof size | Estimated gas | Status |
|----------|-----------|--------------|--------|
| Current surrogate (SHA-256 hash, 32 bytes) | 32 bytes | ~500 gas | Trivially under 5M cap |
| Full LatticeFold+ algebraic commitment (N=1024) | ~1–4 KB (projected) | TBD — Phase D measurement | Not yet measured |
| With P3 UltraHonk wrapper | ~1–2 KB (projected) | ~300K–1M gas (estimated) | Phase D deliverable |

**Current position:** The 32-byte `FinalProof` implies near-trivial on-chain cost for the surrogate path. The single SHA-256 precompile call (`0x02`) costs ~60 + 12 gas; seven public-input equality checks add ~210 gas; total is well under 1000 gas.

**Phase D obligation:** Once the full LatticeFold+ algebraic commitment is instantiated, gas must be re-measured at `t = 1`, `t = 128`, and `t = 513`. If gas scales linearly with fold depth, the design must be revised. A P3 wrapping proof (UltraHonk over the LatticeFold+ verifier circuit) is the preferred mitigation path.

---

## 7. Recursion Path

**Fold depth and extraction cost:**

For `t = 513` parties, the fold depth is `d = ⌈log₂(513)⌉ = 10` steps. The current `RealFoldingScheme` implementation successfully folds to depth 10 and beyond (verified by `test_depth_bomb_fold_to_depth_10_exact` and `test_depth_bomb_fold_to_depth_12_exact` in adversarial tests).

| Parameter | Value |
|-----------|-------|
| Max supported fold depth | ≥ 12 (adversarial test confirmed) |
| Fold depth for t=513 | d = 10 |
| Extraction cost (surrogate) | O(2^d) = 1024 hash operations |
| Extraction cost (full LatticeFold+) | O(d) by accumulation design (Phase D target) |

**Phase D obligation:** The full LatticeFold+ path must achieve O(1) verifier work with respect to `d`. P3 must provide the final step that converts the P2 accumulated proof into a single on-chain-verifiable SNARK. The P3 final step is **not implemented** and is the primary Phase D deliverable.

**Surrogate recursion shape:** The current `RealFoldingScheme.fold()` produces a new `FoldAccumulator` by hashing the previous commitment together with the new statement bytes and witness proof bytes. This is structurally a Merkle-style hash chain, not a real IVC/PCD construction. P3 must not rely on IVC/PCD security properties for the current implementation.

**Hash-chain state at finalization (d=10, n=1024):**
- `acc_commitment`: 32-byte SHA-256 digest binding all 10 fold steps
- `fold_depth`: 10
- `statement_hash_chain`: 32-byte rolling SHA-256 over all folded statement bytes
- `FinalProof.proof_bytes`: 32-byte SHA-256 of `"pvthfhe/finalize/v1" || encode_accumulator(acc)`

---

*Bundle produced by*: C.I.6 — `gate(p2): IG-P2 passed, P2→P3 bundle published`

VERDICT: APPROVE
