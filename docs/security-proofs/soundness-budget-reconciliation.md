# Soundness Budget Reconciliation

> **Document version**: 1.0  
> **Date**: 2026-05-12  
> **Status**: DRAFT — reflects post-deep-audit-remediation state (Batches A–F applied, P1/P2/P3 still OPEN)  

This document reconciles aspirational soundness claims from `README.md` against the
actual conditional status of each proof system. No aspirational bound should be
presented as achieved in any public-facing document without reference to this
reconciliation.

---

## 1. Executive Summary

| Bound | Claimed (README) | Actual Status | Gap |
|-------|-----------------|---------------|-----|
| **ε_fold** | 2⁻¹⁶⁰ (exponential, T=10, \|C\|=2¹⁶) | Conditional on Lemma 9 invertibility heuristic (A-LATTICE-4, κ_nu ≈ 2⁻⁹⁴) and M-SIS binding (A-LATTICE-1, assumed) | P2 OPEN |
| **Composed soundness** | ≥ 2⁻¹²⁸ (joint P1+P2+P3) | Aspirational — P1, P2, P3 all unresolved | Full composition unproven |
| **DKG secrecy** | ≤ 2⁻¹²⁸ | Plausible under RLWE hardness (A-LATTICE-2, assumed) | No formal proof; DKG assumes honest majority |
| **On-chain verifier** | O(polylog n) gas | Real UltraHonk verifier on-chain; KZG binding (A-DLOG-1, assumed) | KZG trusted setup; PQ: NO |

**Bottom line**: All soundness bounds labeled "aspirational" in README remain
aspirational. The folding exponential bound 2⁻¹⁶⁰ is arithmetically correct given
|C|=2¹⁶ and T=10 **if** the underlying Cyclo protocol (Theorem 3, ePrint 2026/359)
is sound, but Cyclo's soundness proof itself assumes Lemma 9 (invertibility
heuristic), which is **unproven** for the power-of-two cyclotomic X²⁵⁶+1.

---

## 2. Per-Proof-System Reconciliation

### 2.1 Sigma — Cyclo-Companion Ajtai D2 (P1 NIZK)

| Aspect | Value |
|--------|-------|
| **Claimed soundness** | ≥ 2⁻¹²⁸ (P1 in composed bound) |
| **Actual status** | **CONDITIONAL** — P1 OPEN |
| **What's proven** | Special soundness of the underlying sigma protocol (preimage binding); SHA-256 collision resistance for the D2 commitment domain (T5, PROVED) |
| **What's unproven** | Joint extractor (T2) not formally constructed; no unified extraction argument for Cyclo folding + Ajtai + RLWE composition |
| **Assumptions relied upon** | A-LATTICE-1 (M-SIS, ASSUMED), A-LATTICE-3 (Ajtai binding, REDUCED → A-LATTICE-1), A-HASH-1 (SHA-256 CR, PROVED), A-MODEL-1 (ROM, ASSUMED) |
| **Recent fixes applied** | Masking seeds now fresh per proof (OsRng, Batch A.1); D.1 fail-closed containment; CRS-bound Ajtai matrix |
| **Residual risk** | Knowledge soundness gap means NIZK may not extract a witness from a malicious prover, even though special soundness holds for the sigma sub-protocol |
| **References** | `lemma9.md`, `p1/theorem-inventory.md`, `spec-real-p2p3.md §3` |

### 2.2 BFV Sigma — BFV Encryption Proof (P1 Share Encryption)

| Aspect | Value |
|--------|-------|
| **Claimed soundness** | ≥ 2⁻¹²⁸ (implicit in P1 composed bound) |
| **Actual status** | **CONDITIONAL with structural gap** — D.1 blocker |
| **What's proven** | Prover validates BFV encryption relation using private witness; algebraic sigma proves hash-preimage (SHA-256 of committed share) |
| **What's unproven** | Verifier does **not** check that the ciphertext is a valid BFV encryption of the committed share under the recipient's public key — the C3 structural gap (see `interfold-equivalence.md §C3`) |
| **Assumptions relied upon** | A-HASH-1 (SHA-256 CR, PROVED), A-LATTICE-1 (M-SIS, ASSUMED) |
| **Residual risk** | Adversary can compute SHA-256 preimage of arbitrary bytes and wrap them as a "ciphertext"; verifier accepts the hash binding but cannot confirm the BFV encryption structure |
| **Resolution path** | Requires a non-leaking verifier-checkable BFV encryption relation (public quotient/reduction terms from FHE backend or Noir BFV ring arithmetic circuit) |
| **References** | `interfold-equivalent-pvss.md §4.1`, `interfold-equivalence.md §C3`, `nizk_share.rs` |

### 2.3 Cyclo Lemma 9 — Folding Soundness (P2)

| Aspect | Value |
|--------|-------|
| **Claimed ε_fold (exponential)** | 2⁻¹⁶⁰ = \|C\|⁻ᵀ = (2¹⁶)⁻¹⁰ |
| **Claimed ε_fold (linear, conservative)** | 1.5 × 10⁻⁴ = T · \|C\|⁻¹ = 10 · 2⁻¹⁶ |
| **Actual status** | **CONDITIONAL** — Lemma 9 is a heuristic (downgraded to Conjecture 9); P2 OPEN |
| **What's proven** | Arithmetic of exponential bound is correct given the model (|C|⁻ᵀ); challenge space locked at 2¹⁶ with T=10 |
| **What's unproven** | Lemma 9 invertibility heuristic: "biased ternary challenge differences are always invertible in X²⁵⁶+1 except with probability κ_nu ≈ 2⁻⁹⁴". The general cyclotomic case is unproven; the power-of-two case relies on a heuristic. |
| **Assumptions relied upon** | A-LATTICE-4 (Lemma 9 heuristic, CONDITIONAL), A-LATTICE-1 (M-SIS, ASSUMED), A-MODEL-1 (ROM for FS challenges, ASSUMED) |
| **Residual risk** | If Lemma 9 fails (non-invertible challenges occur more frequently), the soundness error could exceed 2⁻¹²⁸. The linear bound (1.5×10⁻⁴) is already above target, so the entire folding soundness rests on the exponential model being valid in practice — which depends on Lemma 9. |
| **Sonobe substitution note** | Current prototype uses Sonobe Nova (over BN254+Grumpkin) in place of Cyclo lattice-native folding. Sonobe Nova has its own soundness assumptions (see §2.4). |
| **References** | `fold-soundness-budget.md`, `lemma9.md`, `assumptions-ledger.md §A-LATTICE-4`, Cyclo ePrint 2026/359 Theorem 3 |

### 2.4 Sonobe Nova — IVC Compression (P3)

| Aspect | Value |
|--------|-------|
| **Claimed soundness** | ≥ 2⁻¹²⁸ (P3 in composed bound) |
| **Actual status** | **CONDITIONAL** — P3 OPEN (documented limitation) |
| **What's proven** | Sonobe Nova IVC soundness over BN254+Grumpkin cycle (standard Nova security reduction under DLOG and ROM); external verifier wired (F.1) |
| **What's unproven** | CycloFoldStepCircuit folds 3 hashed field elements (commitment_hash, norm, fold_count) — **not** full Ajtai commitment folding. Compressed proof verifies hash-state consistency, not the raw Cyclo accumulator relation (Ajtai commitment check, norm-bound range checks for β_T=1344, sum-check over ~60 KB of F_{q^e} elements). This is the P2/P3 structural gap. |
| **Assumptions relied upon** | A-DLOG-1 (KZG binding, ASSUMED), A-DLOG-2 (DLOG on BN254, ASSUMED), A-DLOG-3 (DLOG on Grumpkin, ASSUMED), A-MODEL-1 (ROM, ASSUMED) |
| **Residual risk** | Malicious prover who can find SHA-256 preimage of accumulator commitment (but not valid Cyclo accumulator) could produce a passing compressing proof. Mitigated by off-chain Cyclo `verify_fold` check before compression. |
| **NOTE** | All DLOG/pairing assumptions are **broken by quantum adversaries**. The on-chain verifier layer is NOT post-quantum secure, even though the FHE and lattice-NIZK layers are. |
| **References** | `interfold-equivalent-pvss.md §4.5`, `spec-real-p2p3.md §5.1`, `micronova-digest.md` |

### 2.5 Aggregate Decrypt — Threshold Reconstruction (C6/C7)

| Aspect | Value |
|--------|-------|
| **Claimed soundness** | Implicit in composed bound; SEC-4/5 target ≥ 2⁻¹²⁸ |
| **Actual status** | **UNPROVEN** — no formal proof; relies on internal ShareManager |
| **What's proven** | BFV threshold decryption correctness validated empirically (roundtrip tests); `committed_smudge_pvss` mode implemented (E.1; committed e_sm from DKG transcript) |
| **What's unproven** | No verifiable proof that pk_agg = Σ pk_i for the accepted participant set (C5 gap); no verifiable proof of Lagrange+CRT+decode for the final aggregation (C7 gap — Noir toy circuit, N=8, no Cyclo/MicroNova verification) |
| **Assumptions relied upon** | RLWE secrecy (A-LATTICE-2), honest majority (≥ t parties), smudging noise bounds |
| **Residual risk** | Aggregator can select arbitrary participant subset; plaintext reconstruction depends on Rust `recover` without proof; committed smudge mode requires on-chain `SessionRegistry` for one-time-use enforcement (Batch H, pending) |
| **References** | `interfold-equivalence.md §C5, §C7`, `SECURITY.md §Smudging Modes`, `interfold-equivalent-pvss.md §2` |

---

## 3. Aspirational Bound → Actual Status Mapping

| Aspirational Bound (README) | Claimed Value | Actual Status | Conditional On | Gating Problem |
|---|---|---|---|---|
| ε_fold (Cyclo exponential) | 2⁻¹⁶⁰ | **CONDITIONAL** | Lemma 9 heuristic (κ_nu ≈ 2⁻⁹⁴), M-SIS (A-LATTICE-1) | P2 |
| ε_fold (linear, conservative) | 1.5 × 10⁻⁴ | **Above target** (>> 2⁻¹²⁸) | Acceptable only if exponential model holds | P2 |
| P1 NIZK well-formedness | 2⁻¹²⁸ | **CONDITIONAL** | Joint extractor (T2), M-SIS (A-LATTICE-1) | P1 |
| P2 Folding soundness | 2⁻¹⁶⁰ | **CONDITIONAL** | Cyclo Theorem 3, Lemma 9, M-SIS | P2 |
| P3 IVC compression | 2⁻¹²⁸ | **CONDITIONAL** | DLOG (classical), hash-state consistency | P3; PQ: NO |
| Composed (P1+P2+P3) | ≥ 2⁻¹²⁸ | **Aspirational** | P1 AND P2 AND P3 resolved | All three |
| DKG secrecy | ≤ 2⁻¹²⁸ | **Plausible** (ASSUMED) | RLWE (A-LATTICE-2), honest majority | Unproven composition |
| On-chain verification | O(polylog n) | **Real** (UltraHonk) | KZG binding (A-DLOG-1), trusted setup | PQ: NO |

---

## 4. Assumption Dependency Graph

```
Composed Soundness (≥ 2⁻¹²⁸, aspirational)
  ├── P1 NIZK soundness (CONDITIONAL)
  │     ├── A-LATTICE-1 (M-SIS, ASSUMED)
  │     ├── A-LATTICE-3 (Ajtai binding, REDUCED → A-LATTICE-1)
  │     ├── A-HASH-1 (SHA-256 CR, PROVED — T5)
  │     └── A-MODEL-1 (ROM, ASSUMED)
  ├── P2 Folding soundness (CONDITIONAL)
  │     ├── A-LATTICE-4 (Lemma 9 heuristic, CONDITIONAL) ← UNPROVEN
  │     ├── A-LATTICE-1 (M-SIS, ASSUMED)
  │     └── A-MODEL-1 (ROM, ASSUMED)
  └── P3 Compression soundness (CONDITIONAL, PQ: NO)
        ├── A-DLOG-1 (KZG binding, ASSUMED)
        ├── A-DLOG-2 (DLOG BN254, ASSUMED)
        ├── A-DLOG-3 (DLOG Grumpkin, ASSUMED)
        ├── A-DLOG-4 (pairing hardness, ASSUMED)
        └── A-MODEL-1 (ROM, ASSUMED)
```

**Key**: ASSUMED = taken as hard without reduction; REDUCED = explicitly reduced to another assumption here; PROVED = formally proved; CONDITIONAL = caveat must be resolved before deployment.

---

## 5. Recommendations

1. **Do not present ε_fold = 2⁻¹⁶⁰ as achieved.** The exponential bound is conditional
   on Lemma 9 (invertibility heuristic) and M-SIS (A-LATTICE-1). Both are
   cryptographically plausible but neither is formally proven at these exact
   parameters.

2. **Do not present composed soundness ≥ 2⁻¹²⁸ as achieved.** P1, P2, and P3 remain
   open. The composed bound is aspirational and should be labeled as such.

3. **Prioritize Lemma 9 resolution.** The entire folding soundness budget rests on
   the exponential |C|⁻ᵀ bound. If Lemma 9 fails, the linear bound (1.5×10⁻⁴)
   would apply, making the folding layer unsound at any reasonable security level.

4. **Explicitly note the post-quantum boundary.** The DLOG/pairing assumptions in P3
   (Sonobe Nova, on-chain UltraHonk) are NOT post-quantum secure. An attacker with
   a quantum computer could forge on-chain proofs even if the underlying FHE
   ciphertexts remain secure.

5. **Track C3/C5/C7 gaps separately.** These are structural gaps (missing verifier
   relations) rather than assumptions. They do not affect the soundness budget
   directly but prevent full verifiability.

---

## 6. References

| Document | Path |
|----------|------|
| Soundness budget (folding) | `.sisyphus/design/fold-soundness-budget.md` |
| Assumptions ledger | `.sisyphus/design/assumptions-ledger.md` |
| Lemma 9 / Conjecture 9 | `docs/security-proofs/lemma9.md` |
| P1 theorem inventory | `docs/security-proofs/p1/theorem-inventory.md` |
| P3 advisor verdict | `docs/security-proofs/p3/advisor-verdict.md` |
| Interfold equivalence | `.sisyphus/design/interfold-equivalence.md` |
| Interfold-equivalent PVSS | `docs/security-proofs/interfold-equivalent-pvss.md` |
| Spec real P2P3 | `.sisyphus/design/spec-real-p2p3.md` |
| Threat model | `.sisyphus/design/threat-model-v1.md` |
| README soundness section | `README.md` |

---

*Document version*: 1.0  
*Last updated*: 2026-05-12  
*Next review*: After P1/P2/P3 resolution gates
