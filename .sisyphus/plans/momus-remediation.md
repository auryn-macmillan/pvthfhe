# Momus Skeptical Review — Remediation Plan

**Created**: 2026-05-13
**Trigger**: Momus 3-dimensional skeptical review (paper soundness, codebase soundness, docs consistency)
**Findings**: 2 paper FAIL, 2 code HIGH, 2 code MEDIUM, 4 docs HIGH, 5 docs MEDIUM
**Problem Severity Score**: (2·10 + 2·5 + 2·3 + 4·5 + 5·2) = 10 + 10 + 6 + 20 + 10 = 56 / 72 ≈ 80th percentile

---

## 🔴 CRITICAL — Batch A (paper theorem relabeling)

### A.1 — Downgrade P2-A-T2 from PROVED to PENDING-NOVA-PROOF
- [ ] **Code**: No code change. Paper text only.
- [ ] **Theory**: `docs/security-proofs/p2/T2.md` proves LatticeFold+ ternary extractor — NOT Sonobe Nova IVC soundness. Either write a Nova IVC soundness reduction OR create a new T2-track-a.md proof file.
- [ ] **Docs**: `paper/main.tex` §P2 Track A — change `Status: PROVED (via Nova IVC soundness reduction)` to `Status: PENDING — proof file proves LatticeFold+ extractor; Nova IVC soundness reduction to be written.`
- [ ] **Docs**: `paper/claims-table.md` row 14 — change Track A from PROVED to PENDING-NOVA-PROOF
- [ ] **Gate**: Paper theorem no longer claims a proof that doesn't exist

### A.2 — Downgrade P2-A-T5 from PROVED to PARTIAL (2/6 DISCHARGED)
- [ ] **Docs**: `paper/main.tex` §P2 Track A — change `Status: PROVED` to `Status: PARTIAL (2/6 obligations discharged; Phase D deliverables remain)`
- [ ] **Docs**: `paper/claims-table.md` row 17 — Track A: PROVED → PARTIAL (2/6)
- [ ] **Gate**: Paper accurately reflects `p2/T5.md` obligation table

### A.3 — Document P1-T2/T3 tension explicitly
- [ ] **Docs**: `paper/main.tex` §P1 — add paragraph after P1-T3: "**Note on T2/T3 tension.** The extraction argument (T2) relies on witness opening in the proof payload, which is not zero-knowledge. The ZK proof (T3) is scoped to the projected SLAP core transcript excluding those openings. A proof object cannot simultaneously satisfy both theorems in their current form; simulation-extractability (P1-T4) is deferred."
- [ ] **Theory**: `docs/security-proofs/p1/T2.md` — add cross-reference to T3 scope restriction
- [ ] **Gate**: Tension is explicitly disclosed

---

## 🟠 HIGH — Batch B (code security fixes)

### B.1 — Document and mitigate BFV plaintext domain gap in bfv_sigma::verify
- [x] **Code**: `crates/pvthfhe-nizk/src/bfv_sigma.rs` — NO domain check on masked response. The `m_resp = m_mask + ch*m` has coefficients up to `B_Z_M ≈ 1.6e9`, far exceeding the plaintext domain `[-32768, 32767]`. A domain check on the masked response would reject ALL honest proofs.
- [x] **Correct approach**: The existing `B_Z_M` norm bound is the sigma protocol's soundness constraint. The plaintext domain gap — knowledge extractor recovers m* with ‖m*‖ ≤ 2·B_Z_M ≫ t_plain — is a protocol-level limitation documented in `docs/security-proofs/interfold-equivalent-pvss.md`.
- [x] **Theory**: `docs/security-proofs/interfold-equivalent-pvss.md` — add note: "The BFV sigma protocol proves knowledge of bounded (u, e0, e1, m) satisfying the encryption equations, but does not enforce the BFV plaintext domain constraint on m coefficients. A separate range-proof or encoding-level check is needed for full composability with Interfold C3."
- [x] **Gate**: `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-pvss --test nizk_share_real_verify` passes. Adversarial test `adversarial_m_resp_norm_exceeded_rejected` still passes (rejects out-of-range responses via B_Z_M).

### B.2 — Cross-check esm_agg_share against esm_noise_poly_bytes in CommittedSmudge
- [ ] **Code**: `crates/pvthfhe-pvss/src/nizk_decrypt.rs` line 325-355 — in `validate_witness`, add after the esm_agg_commit check:
  ```
  if let Some(ref esm_bytes) = esm_noise_poly_bytes {
      let derived_esm_share = derive_party_binding(esm_bytes);
      if derived_esm_share != *esm_agg_share {
          return Err(PvssError::InvalidShare);
      }
  }
  ```
- [ ] **Theory**: `.sisyphus/design/smudging.md` — add § on binding verification: "esm_agg_share (committed) is derived from the same bytes as esm_noise_poly_bytes (used in decryption); cross-check enforced by validate_witness."
- [ ] **Gate**: `cargo test -p pvthfhe-fhe --test committed_smudge_requires_esm` passes. Manual adversarial test: provide mismatched esm_agg_share and esm_noise_poly_bytes in witness → verify returns InvalidShare.

---

## 🟡 MEDIUM — Batch C (code hygiene + docs)

### C.1 — Qualify sigma soundness claim in sigma.rs
- [ ] **Code**: `crates/pvthfhe-nizk/src/sigma.rs` line 14 — change:
  ```
  //! Binary challenges give negligible special-soundness error (2^{-N}) for the sigma layer. The composed NIZK soundness is conditional — see crate-level docs.
  ```
  to:
  ```
  //! Binary-challenge special-soundness is conditional on an unproven joint extractor
  //! (P1 OPEN). The 2^{-N} figure is the challenge-space size, not a proven knowledge error.
  ```
- [ ] **Gate**: Build passes.

### C.2 — Verify adapter proof-bytes participant/session IDs
- [ ] **Code**: `crates/pvthfhe-nizk/src/adapter.rs` lines 161-163 — replace `let _ =` with explicit checks:
  ```
  if session_id_encoded != stmt.session_id.as_bytes() {
      return Err(NizkError::VerificationFailed("session_id mismatch"));
  }
  if encoded_pid != stmt.participant_id {
      return Err(NizkError::VerificationFailed("participant_id mismatch"));
  }
  ```
- [ ] **Gate**: Build passes. Adapter tests pass.

### C.3 — Fix ARCHITECTURE.md header self-contradiction
- [ ] **Docs**: `ARCHITECTURE.md` lines 5-8 — replace the contradictory "critical cryptographic surrogates that provide no real security" + "real UltraHonk verifier" with:
  ```
  - on-chain cryptographic verification: UltraHonk verifier (Track A: Sonobe attestation surrogate; Track B: MicroNova target — see paper)
  - Noir circuits: real aggregation and wrapping logic (not tautological surrogates)
  ```
- [ ] **Docs**: `WARNING.md` — same fix (identical text)
- [ ] **Gate**: No self-contradiction between "surrogate" and "real" in same paragraph.

### C.4 — Fix SECURITY.md internal contradiction (line 17 vs 48)
- [ ] **Docs**: `SECURITY.md` line 17 — qualify the "Implemented" status:
  ```
  Greco / well-formedness ZK proofs: **Implemented** (code exists: CycloNizkAdapter + bfv_sigma.rs). Formal joint-extractor proof is OPEN (P1, line 48).
  ```
- [ ] **Docs**: `SECURITY.md` line 48 — add cross-reference to line 17
- [ ] **Gate**: No contradiction between "Implemented" (code) and "OPEN" (proof).

### C.5 — Fix paper/submission/README.md "All 19 proved" claim
- [ ] **Docs**: `paper/submission/README.md` line 20 — change:
  ```
  - [x] All 19 theorems proved
  ```
  to:
  ```
  - [x] 17 theorems proved, 2 pending (P2-A-T2 pending Nova IVC proof, P2-A-T5 2/6 discharged)
  - [x] 9 claims in paper text are contradicted by code (see .sisyphus/evidence/paper-claims.md)
  ```
- [ ] **Gate**: Submission README matches claims-table state after A.1/A.2.

---

## 🔵 LOW — Batch D (minor cleanup)

### D.1 — Add P4-T4 proof block to paper
- [ ] **Docs**: `paper/main.tex` §P4-T4 — add `\begin{proof}...\end{proof}` referencing `p4/t4-abort-with-blame-robustness.md`
- [ ] **Gate**: Paper formatting consistent for all theorems.

### D.2 — Document aggregate key assertion weakness
- [ ] **Docs**: `SECURITY.md` — add note: "Aggregate key consistency is verified by runtime assertion comparing DKG and backend paths. No adversarial test validates that active tampering with keygen shares is detected."
- [ ] **Code**: `crates/pvthfhe-cli/tests/full_pipeline.rs` — optionally add test that injects malformed Round1Message and confirms assertion fires.

---

## Execution order

| Batch | Priority | Depends on | Effort |
|-------|----------|------------|--------|
| **A** (paper relabeling) | P0 | None | ~1h |
| **B** (code security) | P0 | None | ~1h |
| **C** (code hygiene + docs) | P1 | A+B complete | ~1h |
| **D** (minor cleanup) | P2 | A complete | ~30min |

Batches A and B are independent and can execute in parallel. Batch C follows B (C.1-C.2 modify same files as B.1-B.2). Batch D is independent of all.

## Acceptance criteria

- [ ] P2-A-T2 status changed from PROVED to PENDING-NOVA-PROOF
- [ ] P2-A-T5 status changed from PROVED to PARTIAL (2/6)
- [ ] P1-T2/T3 tension paragraph in paper
- [ ] BFV plaintext domain constraint enforced in bfv_sigma::verify
- [ ] esm_agg_share cross-checked against esm_noise_poly_bytes
- [ ] sigma.rs 2^{-N} claim qualified
- [ ] adapter.rs proof-bytes IDs verified
- [ ] ARCHITECTURE.md/WARNING.md self-contradiction resolved
- [ ] SECURITY.md internal contradiction resolved
- [ ] paper/submission/README.md "19 proved" corrected
- [ ] P4-T4 proof block added
- [ ] 15 focused PVSS tests pass
- [ ] `cargo build` passes
- [ ] Demo-e2e passes
