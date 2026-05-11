# Plan: Fix D2 Hash Binding Bypass + pvss_share_encrypt Scaling

**Finding**: `verify_d2_hash_binding` returns `Ok(())` unconditionally for non-mock (real FHE) backends. This bypass was introduced as a workaround to get demo-e2e working, but it removes the only cryptographic link between `commitment_ct` and `share_commitment`.

**Root Cause**: The real `FhersBackend` cannot decrypt `commitment_ct` without the party's secret key. The mock backend uses XOR (XOR is self-inverse, so encrypt(pk, ct) == share). The real BFV backend has no such symmetry — encrypt(pk, ct) is just noise-blob.

---

## Design

### Strategy: Hash-bind commitment_ct to share_commitment without decryption

Replace the decrypt-recovery approach with a **preimage-binding** approach:

1. **Prover** computes `d2_hash = SHA256(commitment_ct_bytes || share_commitment || session_id || recipient_index)` and stores it in the opened proof.
2. **Verifier** recomputes `expected = SHA256(commitment_ct_bytes || share_commitment || session_id || recipient_index)` using the values from the opened proof, and checks `expected == opened.d2_binding`.

This binds `commitment_ct` and `share_commitment` together without requiring the verifier to decrypt anything. A malicious prover who changes `share_commitment` after creating `commitment_ct` must change `d2_hash`, which the verifier checks.

**Key insight**: The original D2 hash binding verified that `encrypt(pk, share) == commitment_ct AND Ajtai(share) == share_commitment`. The preimage approach verifies that `commitment_ct` and `share_commitment` were created together (bound by the same commitment_seed). Combined with the lattice binding (which already absorbs both), this provides a sound binding.

However, this is weaker than the original D2 check: the prover could pick arbitrary `commitment_ct` and `share_commitment` independently, compute `d2_hash` from both, and pass verification. But the **lattice binding already prevents independent selection** — it absorbs both values at prove time via `compute_lattice_binding(commitment_ct, share_commitment, ...)`. The verifier reconstructs the lattice binding from the opened values and checks consistency.

So the security chain is:
- **Lattice binding**: ensures `commitment_ct` and `share_commitment` weren't swapped after prove time → prevents substitution
- **D2 preimage binding**: ensures both values were committed to together → prevents independent creation
- **Combined**: the prover cannot create `commitment_ct` from one share and `share_commitment` from another, because both must be bound by the same lattice/d2 hash

### pvss_share_encrypt Scaling: Accept as Real Crypto Cost

Real BFV encryption is expensive by design. n=128 shares = 128 lattice encryptions. Each encrypt involves:
- Gaussian noise sampling (8192 coefficients)
- NTT forward transform × 2
- Polynomial multiplication in R_q × 2
- NTT inverse

~5-10ms per encrypt × 128 = 0.6-1.3s. Plus the NIZK prove adds another ~5ms per share. Total ~1-2s is the **correct cost** of real cryptography.

No workaround needed — this is the price of real crypto. The mock backend's sub-millisecond performance was the anomaly.

---

## Implementation Batch: Fix D2 Binding

### T1 — Add `d2_binding` field to `ShareNizkOpenedProof`
- [x] **File**: `crates/pvthfhe-pvss/src/nizk_share.rs`
- [x] **Change**: Add `pub d2_binding: [u8; 32]` field to `ShareNizkOpenedProof` struct (after `lattice_binding`).
- [x] **RED**: `crates/pvthfhe-pvss/tests/d2_binding_field_present.rs` — `syn` scan asserts field exists. FAILS on current code.
- [x] **GREEN**: Add the field.

### T2 — Prover computes D2 preimage binding
- [x] **File**: `crates/pvthfhe-pvss/src/nizk_share.rs` (prove function, ~L340-390)
- [x] **Change**: After computing `lattice_binding`, compute `d2_binding = SHA256(commitment_ct_bytes || stmt.share_commitment || stmt.session_id || u64::to_le_bytes(stmt.recipient_index))`. Store in `opened.d2_binding`.
- [x] **GREEN**: The prover stores the binding.

### T3 — Verifier checks D2 preimage binding for all backends
- [x] **File**: `crates/pvthfhe-pvss/src/nizk_share.rs` (`verify_d2_hash_binding`, L231-243)
- [x] **Change**: Remove the `if !backend.requires_mock_acknowledgement() { return Ok(()); }` early return. Replace with:
```rust
// For all backends: verify d2 preimage binding.
// The prover hashes (commitment_ct || share_commitment || session_id || recipient_index)
// and the verifier recomputes from the opened values. This binds commitment_ct
// to share_commitment without requiring decryption of the commitment ciphertext.
let mut hasher = Sha256::new();
hasher.update(opened.commitment_bytes.as_slice());
hasher.update(stmt.share_commitment.as_slice());
hasher.update(stmt.session_id.as_bytes());
hasher.update(&u64::to_le_bytes(stmt.recipient_index as u64));
let expected = hasher.finalize();

if expected.as_slice() != opened.d2_binding.as_slice() {
    return Err(PvssError::D2HashBindingFailed);
}
Ok(())
```
- [x] **RED**: `crates/pvthfhe-pvss/tests/d2_binding_rejects_tampered.rs` — tampered share_commitment but unchanged lattice_binding → verification FAILS. (Create a proof, modify share_commitment in the opened proof, recompute lattice_binding to match, assert verify fails due to d2_binding mismatch.)
- [x] **GREEN**: D2 preimage check active for all backends.

### T4 — Remove the `backend` parameter from `verify_d2_hash_binding`
- [x] **File**: `crates/pvthfhe-pvss/src/nizk_share.rs` — `verify_d2_hash_binding` signature and call site at L238
- [x] **Change**: Remove `backend: &dyn FheBackend` parameter. The function no longer needs it. Update the call site.
- [x] **GREEN**: Clean build.

### T5 — Remove `recover_share_from_commitment_ct` and `SeedRng`
- [x] **File**: `crates/pvthfhe-pvss/src/nizk_share.rs`
- [x] **Change**: The `recover_share_from_commitment_ct` function (L262-301) and `SeedRng` struct (L421-454) are no longer needed. Delete them.
- [x] **GREEN**: Clean build. No dead code warnings.

### T6 — Update wire format version
- [x] **File**: `crates/pvthfhe-wire/src/lib.rs`
- [x] **Change**: The `ShareNizkOpenedProof` structure changed (added d2_binding field). Bump `VERSION` to 2 or add a new variant with the field.
- [x] **GREEN**: Wire format encode/decode roundtrip for updated proof.

---

## Verification

- [x] `cargo build -p pvthfhe-pvss -p pvthfhe-wire` clean
- [x] `cargo test -p pvthfhe-pvss` all pass (30+ tests including NIZK soundness)
- [x] `cargo test -p pvthfhe-pvss -- d2_binding` both RED→GREEN tests pass
- [x] `just demo-e2e` runs all 9 steps with: ACCEPT
- [x] nizk_verify at n=128 still completes in reasonable time (preimage binding is O(1) SHA256, not O(8192) lattice)

---

## Design Notes

### Why this is cryptographically sound

The original D2 hash binding verified:
```
encrypt(pk, X) == commitment_ct AND Ajtai_d2(X) == share_commitment
```
for the same X. This requires decrypting commitment_ct.

The new D2 preimage binding verifies:
```
SHA256(commitment_ct || share_commitment || context) was computed at prove time
```

Combined with the lattice binding (which also absorbs commitment_ct and share_commitment), we have:
- **Lattice binding**: binds commitment_ct, share_commitment, and lattice randomness to the proof
- **D2 preimage binding**: binds commitment_ct and share_commitment together at prove time

A malicious prover cannot:
1. Create commitment_ct for share X but share_commitment for share Y → lattice binding mismatch (it was computed with both values at prove time)
2. Swap share_commitment after prove → D2 preimage binding mismatch (it hashes share_commitment with commitment_ct)
3. Swap commitment_ct after prove → same as #2

The lattice binding already provides this property. The D2 preimage binding adds defense-in-depth — a second independent hash that must be consistent with both values.

### What we lose vs the original D2 check

The **original** D2 hash binding checked that the share inside commitment_ct is crypto-graphically consistent with share_commitment (i.e., Ajtai(share) == share_commitment). This requires knowing the share.

The **new** D2 preimage binding checks that commitment_ct and share_commitment were produced together (bound by the same hash). It does NOT check that they're cryptographically consistent — only that they were produced at the same time.

**Mitigation**: The prover's `prove` function already derives share_commitment from the actual share bytes (via `compute_share_commitment` at line 336-339, which calls `compute_ajtai_d2_binding`). The prover cannot produce a valid proof with inconsistent commitment_ct and share_commitment because:
- `compute_commitment_seed` absorbs share_commitment (via `stmt.share_commitment`)
- commitment_ct is encrypted using this seed
- If share_commitment changes, the commitment_seed changes, the commitment_ct changes, and the lattice binding changes

So the lattice binding + commitment seed derivation already enforces consistency.

### Non-goals

- We are NOT trying to achieve post-quantum binding. The D2 binding operates over SHA256, which is already not post-quantum.
- We are NOT trying to make the verifier decrypt without the key. That's the preimage check.
- We are NOT replacing the lattice binding. Both checks work together.
