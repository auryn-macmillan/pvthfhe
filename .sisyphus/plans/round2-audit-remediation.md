# Round 2 Audit Remediation Plan

**Created**: 2026-05-12
**Trigger**: Fresh 5-dimensional post-remediation audit (soundness 13/13, demo 6/6, theory 10/10, E2E gaps, Interfold C1-C7)
**Findings**: 0 CRITICAL, 4 MEDIUM, 4 LOW, 2 TRIVIAL

## Summary

Previous remediation (Batches A-G, 7 batches) closed all CRITICAL/HIGH issues. This round finds only integration gaps and minor polish.

---

## TRIVIAL — Batch A

### A.1 — Fix threat-model header version
- [ ] **File**: `.sisyphus/design/threat-model-v1.md` line 3
- [ ] **Change**: `> **Document version**: 1.1` → `> **Document version**: 1.2`
- [ ] **Gate**: Manual review

### A.2 — Add debug_assert to scale_plaintext_to_rns
- [ ] **File**: `crates/pvthfhe-nizk/src/bfv_sigma.rs` line 163
- [ ] **Change**: Add `debug_assert_eq!(m_int.len(), RLWE_N, "scale_plaintext_to_rns: input length must equal RLWE_N");`
- [ ] **Gate**: Build passes

---

## MEDIUM — Batch B

### B.1 — Wire per-share NIZK verification into FHE partial-decrypt path (C4 gap)
- [ ] **File**: `crates/pvthfhe-cli/src/full_pipeline.rs` lines 318-335
- [ ] **Issue**: `backend.partial_decrypt()` produces `DecryptShare` but no per-share NIZK verification is performed. The PVSS path verifies decryption shares via `DecryptNizkVerifier::verify`, but the FHE threshold decryption path does not.
- [ ] **Code**: After each `partial_decrypt` call (line 325), call `DecryptNizkVerifier::verify` on the returned share. This requires constructing a `DecryptNizkStatement` from the share's metadata and the ciphertext.
- [ ] **Theory**: Add note to `interfold-equivalence.md` §C4: per-share NIZK now verified in FHE path.
- [ ] **Docs**: Update README C4 status.

### B.2 — Wire committed-smudge into primary decrypt flow (C6 gap)
- [ ] **File**: `crates/pvthfhe-fhe/src/fhers.rs` `partial_decrypt` (line 727) and `crates/pvthfhe-pvss/src/encrypt.rs` `prove_decrypted_share` (line 79)
- [ ] **Issue**: `partial_decrypt_committed_smudge` API exists with GREEN tests, but primary `partial_decrypt` samples fresh Gaussian. `DecryptNizkMode` defaults to `LegacyLocalSmudge`.
- [ ] **Code**: 
  - In `fhers.rs:727`, when backend has stored `esm_noise_poly_bytes` from DKG, call `partial_decrypt_committed_smudge` instead of `partial_decrypt`.  
  - In `encrypt.rs:79`, when `committed_esm_noise_bytes` is `Some`, construct `DecryptNizkMode::CommittedSmudge` instead of `LegacyLocalSmudge`.
- [ ] **Theory**: Update `.sisyphus/design/smudging.md` §12.2.
- [ ] **Docs**: Update README C6 status.

### B.3 — Replace derive_party_binding with DKG-committed sk in decrypt NIZK (C4 gap)
- [ ] **File**: `crates/pvthfhe-pvss/src/encrypt.rs` `prove_decrypted_share`
- [ ] **Issue**: `proof_secret_share` uses `derive_party_binding(&stmt.party_pk)` (SHA-256 over pk bytes) — not the DKG-committed Shamir share.
- [ ] **Code**: When a DKG-committed `sk_agg_share` is available (from `DkgAnchorSet`), use it as the secret share witness instead of `derive_party_binding`. Fall back to `derive_party_binding` when DKG commitment is unavailable.
- [ ] **Theory**: Document in `interfold-equivalence.md` §C4.
- [ ] **Gate**: Existing decrypt tests pass.

### B.4 — Document C5 proof gap with plan (no code change)
- [ ] **Theory**: `.sisyphus/design/interfold-equivalence.md` §C5 — add note on verification approach: "Verifier must redo Lagrange+CRT+decode from scratch. Production path requires C7 circuit."
- [ ] **Docs**: `SECURITY.md` — add C5 gap: "Aggregate decryption correctness is trusted. No verifiable proof exists for participant selection, Lagrange coefficients, or decimal decoding."

---

## LOW — Batch C

### C.1 — Keygen NIZK stubs: document gap (no code change)
- [ ] **Issue**: `KeygenSimulator` uses `nizk: vec![0x00, 0x01]` stub. `KeygenSession` has `nizk: Vec<u8>` field but no verification path.
- [ ] **Theory**: `.sisyphus/design/interfold-equivalence.md` §C1 — update to note: keygen NIZK is a protocol placeholder; real lattice NIZK for key shares requires wiring `CycloNizkAdapter` per dealer.
- [ ] **Docs**: `SECURITY.md` — add note under P1.
- [ ] **Gate**: Documentation only.

### C.2 — Encrypt step: document gap (no code change)
- [ ] **Issue**: `backend.encrypt()` at line 222 of `full_pipeline.rs` has no verifiable proof of correct encryption.
- [ ] **Theory**: `.sisyphus/design/threat-model-v1.md` — add § on encryption correctness: "Encryption is trusted; no proof that ciphertext matches plaintext under the aggregate key. Mitigation: semantic roundtrip check detects errors at aggregate level only."
- [ ] **Docs**: `SECURITY.md` — add note.

### C.3 — Remove BFVPublicKey stub components
- [ ] **File**: `crates/pvthfhe-keygen-spec/src/lib.rs` `BFVPublicKey::derive_bfv_public_key`
- [ ] **Issue**: `rlwe_dimension: 4096` hardcoded, `modulus_chain` is a fake label-string, `bfv_derivation_label` is a format-string.
- [ ] **Code**: Replace stub with actual BFV parameter derivation from `FhersBackend::load_params()`: extract `degree`, `moduli`, `plaintext_modulus` from the canonical params TOML.
- [ ] **Gate**: Build passes; BFV key provenance reflects actual parameters.

---

## Interfold Pipeline Gaps — Batch D

### D.1 — C7 final verification: update plan reference (no code change)
- [ ] **Issue**: C7 remains the largest gap — no provable aggregate decryption circuit.
- [ ] **Theory**: `.sisyphus/design/interfold-equivalence.md` §C7 — update with current state: Noir toy circuit (N=8, Poseidon) exists for experimentation; production C7 circuit deferred to separate plan.
- [ ] **Gate**: Documentation only.

---

## Execution order

| Batch | Tasks | Depends on | Effort |
|-------|-------|------------|--------|
| **A** (TRIVIAL) | 2 | None | ~5 min |
| **B** (MEDIUM) | 4 | None | ~2h |
| **C** (LOW) | 3 | None | ~30min |
| **D** (Pipeline) | 1 | None | ~10min |

All batches independent. Delegate in parallel.

## Acceptance criteria

- [ ] A.1: Threat model header reads 1.2
- [ ] A.2: debug_assert passes in debug builds
- [ ] B.1: FHE partial-decrypt path verifies per-share NIZK
- [ ] B.2: Committed smudge wired into primary decrypt flow
- [ ] B.3: Decrypt NIZK uses DKG-committed sk when available
- [ ] B.4: C5 gap documented
- [ ] C.1-C.3: Gaps documented, BFVPublicKey stub fixed
- [ ] D.1: C7 plan reference updated
- [ ] `just demo-e2e 10` passes (plaintext_roundtrip OK, verify ACCEPT)
- [ ] 15 focused PVSS tests pass
- [ ] `cargo build` passes
