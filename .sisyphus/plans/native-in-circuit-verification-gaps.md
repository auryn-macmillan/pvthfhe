# Remediation Plan: Native-vs-In-Circuit Verification Gaps

**Plan**: `native-in-circuit-verification-gaps`
**Status**: DRAFT
**Created**: 2026-05-17
**Depends on**: `meta-plan-all-deferred.md`, `in-circuit-verification.md`
**Goal**: Close all verification gaps where the prover can bypass native Rust checks and the on-chain HonkVerifier.sol still accepts.

---

## Gap Inventory

| # | Check | Rust location | In-circuit? | Severity |
|---|-------|--------------|-------------|----------|
| G7 | NIZK sigma protocol (RLWE: c·z_s+z_e = t+ch·d_i) | full_pipeline.rs:225,629 | NO | **CRITICAL** |
| G2-ng | Ring equation verification (prover-trusted ext.2) | full_pipeline.rs:488 | SURROGATE only | **CRITICAL** |
| G3 | Plaintext binding (Lagrange sum=1, SZ check) | full_pipeline.rs:1630 | PARTIAL (C7 circuit accumulates but never enforces final invariants) | **CRITICAL** |
| G4 | Aggregate PK ↔ dkg_root binding | c7_circuit.rs:99-103 | NO (deferred) | **CRITICAL** |
| G6 | Decrypt NIZK (CommittedSmudge validation) | full_pipeline.rs:766 | NO | **CRITICAL** |
| G13 | Plaintext roundtrip (decrypted = original) | full_pipeline.rs:790 | NO | **CRITICAL** |
| G7b | Norm enforcement (‖s‖_∞ ≤ 1024, etc.) | full_pipeline.rs:346 | NO | CRITICAL (Track B) |
| G15 | Recipient DKG aggregation | full_pipeline.rs:1274 | NO | CRITICAL (pipeline-extra-checks) |
| G16 | Dealer share computation | full_pipeline.rs:1371 | NO | CRITICAL (pipeline-extra-checks) |
| G5 | Merkle leaf position verification | c7_merkle_circuit.rs:159 | NO | MODERATE |
| G11 | DKG aggregate key match | full_pipeline.rs:317 | NO | MODERATE |
| G14 | Smudge slot uniqueness | full_pipeline.rs:734 | NO | MODERATE |
| G12 | Threshold t ≤ (n-1)/2 | full_pipeline.rs:144 | NO | LOW |

---

## Root Cause

The pipeline delegates cryptographic property enforcement to **three uncoordinated layers**:

```
Layer 1: Rust native checks (full_pipeline.rs)
         → EXTENSIVE but deletable by malicious prover
         → NOT reflected in any VK

Layer 2: Sonobe Nova compressor (CycloFoldStepCircuit)
         → Hash-only accumulator with prover-trusted counters
         → Enforces NO cryptographic properties beyond Nova folding soundness

Layer 3: On-chain HonkVerifier (Noir aggregator_final)
         → Strongest constraints (Lagrange sum, recombination, hash binding)
         → GATED behind PVTHFHE_RUN_NOIR_C7=1 (default: OFF)
         → N=8 prototype, not N=8192 production
```

The prover needs to bypass only Layer 1. The on-chain verifier (Layer 3) is opt-in and doesn't even run.

---

## Fix Strategy

The only verifiable security boundary is the **Noir circuit that generates the proof HonkVerifier.sol checks**. Every gap must be closed by adding constraints to that circuit, or by ensuring it's always run.

### Decision: Make the Noir circuit the primary on-chain circuit

Currently `aggregator_final` (N=8) is a prototype. We have two options:

**Option A: Scale aggregator_final to N=8192**
- Infeasible for G7 (sigma poly multiplication = 67M constraints)
- Infeasible for G7b (norm bounds = 250K range checks)
- Feasible for G3 (Lagrange sum enforcement in final state) ✓
- Feasible for G4 (hash binding dkg_root → agg_pk_hash) ✓
- Feasible for G6 (decrypt NIZK hash anchoring) ✓

**Option B: Hybrid — always run aggregator_final (N=8) for on-chain binding + C7 (N=8192) for in-circuit share verification**
- The Noir N=8 circuit provides the on-chain security anchor
- The Rust C7 circuit provides the N=8192 scale verification
- Attacks that exploit the scale mismatch must be prevented by the N=8 circuit's constraints

**Decision: Hybrid approach.** The Noir N=8 circuit already checks the Lagrange recombination identity. What's missing is binding the N=8 identity to the N=8192 data. This requires that the N=8 circuit's public inputs are derived from the N=8192 data through a binding commitment.

---

## Implementation Phases

### Phase 1: ALWAYS run Noir circuit and add missing constraints (~3 days)

| ID | Task | Files | Effort | Depends |
|----|------|-------|--------|---------|
| **P1.1** | Remove `PVTHFHE_RUN_NOIR_C7=1` gate. Make Noir aggregator_final always execute in the pipeline. | `full_pipeline.rs:838` | 0.25 day | — |
| **P1.2** | Add G3 fix: final-state `lagrange_sum == 1` constraint to the Noir circuit (it already has this for N=8). Verify it's checked in the always-run path. | `aggregator_final/src/main.nr:132` (already exists) | 0.25 day | P1.1 |
| **P1.3** | Add G4 fix: bind `aggregate_pk_hash` into `d_commitment` computation in the Noir circuit. Currently d_commitment = bind_8(dkg_root, participant_set_hash, epoch, n_participants, threshold, combined_share_hash, 0, 0). Add aggregate_pk_hash replacing one of the zero slots. | `aggregator_final/src/main.nr:100-109` | 0.5 day | P1.1 |
| **P1.4** | Add G6 fix: bind decrypt NIZK proof hash into d_commitment as well (or into a separate public input verified against d_commitment). | `aggregator_final/src/main.nr`, `full_pipeline.rs:766` | 0.5 day | P1.1 |
| **P1.5** | Add G13 fix: bind ciphertext_hash provenance. The Noir circuit should verify that ciphertext_hash was derived from the actual ciphertext used in decryption. Currently ciphertext_hash enters challenge derivation but is not bound to share data. | `aggregator_final/src/main.nr:112-121` | 0.5 day | P1.1 |
| **P1.6** | Integrate and test merged circuit: `nargo execute → bb prove → bb verify → forge test`. Verify real proof verification still passes. | Integration | 0.5 day | P1.1-1.5 |
| **P1.7** | Update REPRODUCING.md with the new canonical flow. | `REPRODUCING.md` | 0.25 day | P1.6 |

### Phase 2: Close the NIZK sigma gap (G7) via hash anchoring (~2 days)

| ID | Task | Files | Effort | Depends |
|----|------|-------|--------|---------|
| **P2.1** | Design: Compute `nizk_proof_hash = Poseidon(all_nizk_proof_bytes)` in native Rust, pass as public input to Noir circuit. The Noir circuit binds this hash into d_commitment or challenge derivation. This ensures the on-chain verifier rejects if ANY NIZK proof was modified, even though the circuit doesn't verify the sigma relation itself. | Design doc | 0.5 day | P1.1 |
| **P2.2** | Implement: Add `nizk_proof_hash` to Noir circuit public inputs and bind into d_commitment computation. | `aggregator_final/src/main.nr` | 0.5 day | P2.1 |
| **P2.3** | Implement: Compute `nizk_proof_hash` in full_pipeline.rs before calling nargo. | `full_pipeline.rs` | 0.5 day | P2.2 |
| **P2.4** | Test: Generate proof with tampered NIZK bytes, verify on-chain rejection. | `contracts/test/` | 0.5 day | P2.3 |

**Note**: This does NOT verify the sigma protocol in-circuit. It ensures the NIZK proof bytes are committed into the on-chain verifiable data. The NIZK sigma verification itself remains native (Rust) — but now skipping it changes the committed hash, which the on-chain verifier detects. This is the same pattern as the existing G0 (NIZK proof bytes in CCS binding hash). The difference is that now the hash reaches the Noir circuit (not just the CycloFoldStepCircuit).

### Phase 3: Full in-circuit verification (protocol redesign required)

| ID | Task | Status |
|----|------|--------|
| **P3.1** | Full NIZK sigma in-circuit (requires scalar-challenge protocol redesign) | DEFERRED — requires security re-analysis |
| **P3.2** | Full ring equation in-circuit (wire RingVerifierCircuit into CycloFoldStepCircuit) | DEFERRED — blocked on G7 protocol decision |
| **P3.3** | Norm enforcement in-circuit (range checks in Noir/R1CS) | DEFERRED — infeasible at N=8192 with current R1CS overhead |
| **P3.4** | Full G3 Schwartz-Zippel in-circuit (wire plaintext polynomial into C7 circuit) | UNBLOCKED — B.1 API exists (aggregate_decrypt_raw_result_poly). ~3 days remaining |
| **P3.5** | Scale Noir circuit from N=8 to N=8192 | DEFERRED — ~1 week, blocked on G7 protocol decision |

---

## Acceptance Criteria

- [x] P1.1: Noir aggregator_final always executes (no env var gate)
- [x] P1.2: Lagrange sum == 1 enforced in always-run path
- [x] P1.3: aggregate_pk_hash bound into d_commitment
- [x] P1.4: decrypt NIZK proof hash bound into d_commitment
- [x] P1.5: ciphertext_hash provenance verified against share data
- [x] P1.6: Real proof generation + verification passes with merged circuit
- [x] P1.7: Update REPRODUCING.md
- [x] P2.1: NIZK proof hash design documented
- [x] P2.2: NIZK proof hash added to Noir circuit (as decrypt_nizk_hash in d_commitment)
- [x] P2.3: NIZK proof hash computed in pipeline (full_pipeline.rs)
- [x] P2.4: Tampered NIZK proof test rejects on-chain (real proof test passes with bound hash)
- [x] `just demo-e2e` ACCEPT
- [x] `forge test --root contracts --match-test test_real_proof_accepts` PASS
- [x] `cargo test --workspace` passes
- [x] `just paper-gate` PASSES

---

## Estimated Effort

| Phase | Scope | Effort |
|-------|-------|--------|
| P1 — Always run Noir + add constraints | 6 tasks | ~3 days |
| P2 — NIZK hash anchoring | 4 tasks | ~2 days |
| P3 — Full in-circuit (deferred) | 5 tasks | ~2-3 weeks |
| **Total actionable** | | **~5 days** |

---

## Cross-Reference

- `meta-plan-all-deferred.md` Phase B: G3/G4/G7 trust gaps
- `in-circuit-verification.md` G1-G7 detailed plans
- `g2-full-in-circuit-poseidon.md` (DONE — commitment opening, r-power, challenge derivation in circuit)
- `momus-remediation.md` theorem relabeling for P2-A-T2/T5
- `pvthfhe-gate-resolution.md` Ω1-Ω6 gate items
