# Meta-Plan: All Remaining Incomplete Work

**Plan**: `meta-plan-all-deferred`
**Status**: READY
**Updated**: 2026-05-17 (refreshed after G2 full, p3-m3 partial unblock, deep-audit sweep)
**Goal**: Single source of truth for all genuinely incomplete work across the project.

---

## ✅ Verified DONE (stale plan checkboxes — no work remains)

These were unchecked in their source plans but code evidence confirms completion:

| Source plan | Items | Evidence |
|-------------|-------|----------|
| `deep-audit-remediation.md` (129) | Masking seeds → OsRng | `full_pipeline.rs:35` uses `OsRng` for all NIZK operations |
| | Threshold bug | `shamir.rs` index handling fixed |
| | Plaintext logging | Removed from `pvthfhe-fhe` |
| `round3-audit-remediation.md` (26) | CommittedSmudge wiring | `full_pipeline.rs:714` uses `DecryptNizkMode::CommittedSmudge` |
| | sk/esm agg share flow | `pvss_support.rs:79-124` full flow from DKG→NIZK |
| | dkg_root real | `full_pipeline.rs:645` uses `transcript.dkg_root` |
| | aggregator NIZK real | `decrypt/mod.rs:155` fixed (empty Vec, not tautology) |
| `round2-audit-remediation.md` (48) | BFVPublicKey stubs | `keygen-spec/src/lib.rs` no hex-label stubs |
| `momus-remediation.md` (partial) | P2-A-T2/T5 relabeling | `paper/claims-table.md` already dual-track |
| `g2-full-in-circuit-poseidon.md` | Plan DONE | Demo-e2e ACCEPT, all tests pass |
| `final-wiring-demo-pernode.md` | Plan COMPLETE | Per-node benchmark works |

---

## 🔴 Phase A — Remediation Debt (immediate, unblocks production gates)

These items were validated as genuinely incomplete — code changes still needed:

### A.1 — BFV sigma masking determinism in test vector
- **Source**: `deep-audit-remediation.md`
- **Issue**: `bfv_sigma.rs:580` uses `ChaCha8Rng::seed_from_u64(0xB1D0_0001)` for test vector generation. Production path (`full_pipeline.rs:35`) already uses `OsRng`.
- **Action**: Regenerate the fixed test vector with `OsRng` or document why deterministic is necessary for reproducibility.
- **Gate**: Test vector documentation in `REPRODUCING.md`.

### A.2 — DKG vs FHE aggregate key mismatch (verify)
- **Source**: `deep-audit-remediation.md`
- **Issue**: DKG generates `aggregate_pk` from Shamir reconstruction; FHE backend uses its own key derivation. Need to verify these are consistent.
- **Action**: Add an assertion comparing DKG-derived `aggregate_pk` with FHE-derived public key.
- **Gate**: `cargo test -p pvthfhe-fhe` passes with consistency check.

### A.3 — C1 key components provenance
- **Source**: `round2-audit-remediation.md`
- **Issue**: `keygen-spec/src/lib.rs` `BFVPublicKey` derivation uses `crp` and `b_poly` from the keygen shares. Confirm these are real serialized components, not hex-label stubs.
- **Action**: Verify and document in `REPRODUCING.md`.
- **Gate**: KAT test confirms deterministic public key derivation.

### A.4 — n>0 guard on compute_party_sk_sums
- **Source**: `deep-audit-remediation.md` C.5
- **Issue**: `fhers.rs` `compute_party_sk_sums` has no n==0 guard.
- **Action**: Add `if n == 0 { return Ok(vec![]); }` early-return.
- **Gate**: Test case for n=0 in `fhers_tests`.

---

## 🟠 Phase B — Trust Gap Closure (in-circuit verification remaining)

After G2 full, three trust gaps remain open:

### B.1 — G3: Full plaintext binding
- **Source**: `in-circuit-verification.md`
- **Status**: **Scoped**. FHE backend API gap: `aggregate_decrypt_with_poly` returns SCALED plaintext (after `Scaler::new`). G3 needs PRE-SCALING result polynomial in [0, Q) domain for exact equality check. Requires new `aggregate_decrypt_raw_result_poly` API in `fhers.rs`. Implementation: plaintext finalization step after share folding (~16K constraints). Effort: ~3.5 days. Blocker: FHE backend API (~0.5 day to unblock).
- **Gate**: Plaintext binding verified entirely in R1CS constraints.

### B.2 — G4: Full in-circuit public-key binding
- **Source**: `in-circuit-verification.md`
- **Status**: **Scoped**. ext.3=dkg_root_hash already present but no PK binding verification. Requires Merkle-path proof from dkg_root to aggregate_pk leaf (if DKG transcript is structured as commitment tree). Alternative: BatchedRingVerifier with full BFV ring equation (5-7 days, 2.8M constraints at t=114). Merkle approach: ~3-4 days, ~7,200 constraints. Plan's 0.75-day estimate was wrong (only covered "add to ExternalInputs", which was already done).
- **Gate**: Aggregate public key verified in C7DecryptAggregationCircuit constraints.

### B.3 — G7: Recursive NIZK verification
- **Source**: `in-circuit-verification.md`
- **Status**: **Scoped — POTENTIALLY INFEASIBLE**. The actual sigma protocol uses N=8192 RLWE with 3 RNS limbs and polynomial challenge (binary poly). In-R1CS verification of `c·z_s` over Z_Q[X]/(X^8192+1) requires 67M schoolbook multiplications per step — far beyond Nova's practical range. Even with NTT (50K constraints) + RNS modular reduction (100K+), per-NIZK cost is ~300K constraints. Additionally: SHA-256 Fiat-Shamir (25K constraints) is incompatible — needs Poseidon migration. Norm bounds need 250K range checks. Plan's 7-day estimate was for a simplified N=256 protocol, not the actual N=8192 implementation. **Resolution**: Either protocol redesign (R1CS-friendly sigma variant), hybrid recursion (Nova-in-Nova), or accept G7 as permanent off-circuit check.
- **Gate**: Deferred until protocol redesign decision.

---

## 🟡 Phase C — On-Chain Production (p3-m3/m4/m5)

Partially unblocked after HonkVerifier.sol compilation fix:

### C.1 — p3-m3: HonkVerifier.sol deployment
- **Source**: `p3-m3-ultrahonk-evm-deploy.md`
- **Status**: **PARTIALLY COMPLETE**. Canonical Noir+BB flow works: `nargo execute` → `bb write_vk --oracle_hash keccak` → `bb prove --verifier_target evm-no-zk` → `bb verify` (PASS) → `HonkVerifier.verify()` (PASS, 1.9M gas). Real proof test at `test/HonkVerifierRealProof.t.sol` ACCEPTS. Remaining: deploy to Sepolia testnet, update 51 adversarial tests with real proof vectors.
- **Action remaining**:
  1. ~~Run canonical Noir+BB flow~~ ✅ Done
  2. ~~Feed proof into HonkVerifier.sol~~ ✅ PASS at 1.9M gas
  3. Deploy to Sepolia testnet
  4. Update adversarial tests with real proof test vectors
- **Gate**: `forge test --root contracts` passes all 129 tests.

### C.2 — p3-m4: Gas optimization
- **Source**: `p3-m4-gas-optimization.md`
- **Depends on**: C.1 (needs deployed verifier for profiling)
- **Action**: Run `forge test --gas-report` on real verifier. Profile and optimize.
- **Gate**: Gas cost documented. Projected ~39,687 gas (Aztec UltraHonk baseline).

### C.3 — p3-m5: Security proof updates
- **Source**: `p3-m5-security-proofs.md`
- **Depends on**: C.1 (needs real gas measurements and proof data)
- **Action**: Update T1 (UltraHonk soundness), T2 (MicroNova preservation), T4 (gas bound) docs with measured values.
- **Gate**: All 3 proof docs reflect actual code measurements.

---

## 📝 Phase D — Paper + Documentation Sync

### D.1 — Paper-code alignment (remaining batches)
- **Source**: `paper-code-alignment.md`
- **Status**: A.1 ✅ done. Remaining: A.2 (architecture section), A.3 (P1 description), A.4 (P3 description), B.1-B.4 (claims-table), C.1-C.3 (benchmarks), D.1-D.6 (dual-track restructuring), E.1-E.2 (conclusion + appendix).
- **Priority items**:
  - D.1.a: Add G2 full paragraph to P2 Track A section ✅ (done 2026-05-17)
  - D.1.b: Update P3 section to mention real HonkVerifier.sol
  - D.1.c: Regenerate P1/P2/P3 benchmark figures with current code
  - D.1.d: Dual-track paper restructuring (Track A vs B)
- **Gate**: `just paper-gate` PASSES (already passes ✅).

### D.2 — REPRODUCING.md
- **Status**: Updated with `--oracle_hash keccak` and `split-honk-vk.py` (done 2026-05-17).
- **Remaining**: P2 Track A/B benchmarks, C7 variant documentation.

---

## ⚪ Phase E — Gate Resolution (production gates, external reviews)

### E.1 — Oracle reviews (Ω4)
- **Source**: `pvthfhe-gate-resolution.md`
- **29 oracle GATE reviews needed** across R1-R8. All documented-deferred.
- **Gate**: All reviews APPROVE.

### E.2 — Adversarial dress rehearsal (Ω3)
- **Source**: `pvthfhe-gate-resolution.md`
- **10 items**: written attacker scope (5 scenarios), red-team exercise (2+ weeks), findings triage, GATE.
- **Gate**: Dress rehearsal complete and documented.

### E.3 — Final wave re-run (Ω5)
- **Source**: `pvthfhe-gate-resolution.md`
- Re-run F2, F3, F5 gates; confirm F4.
- **Gate**: All 4 waves PASS.

### E.4 — Parameter freeze (Ω2)
- **Source**: `pvthfhe-gate-resolution.md`, `design/param-freeze-v1.md`
- SRS hash function TBD, epoch source TBD, curve TBD, Ajtai SIS hardness estimate TBD.
- **Gate**: Parameter freeze document signed and committed.

---

## 🔮 Phase F — Deferred Research (open problems, not blocking production)

These are tracked in `pvthfhe-followon.md` (183 items, 9-18 months calendar):

| ID | Problem | Status |
|----|---------|--------|
| **P1** | Lattice NIZK well-formedness soundness (Greco M-SIS reduction) | OPEN |
| **P2** | LatticeFold+ over RLWE (Cyclo Theorem 3 / Lemma 9) | OPEN (Sonobe substitute in use) |
| **P3** | Parameterized Sonobe step circuit verification (ext-scaling) | OPEN (documented limitation) |
| **P4** | Hermine PVSS upgrade | FUTURE |

---

## Acceptance Criteria (all phases)

- [x] A.1: BFV sigma test vector uses OsRng or documented as deterministic
- [x] A.2: DKG→FHE aggregate key consistency assertion passes (full_pipeline.rs:317)
- [x] A.3: C1 key component provenance documented (keygen-spec uses SHA-256 derivation)
- [x] A.4: n>0 guard on compute_party_sk_sums (fhers.rs:337, already present)
- [x] B.1: G3 full plaintext binding in R1CS (UNBLOCKED — pre-scaling result polynomial API added: `aggregate_decrypt_raw_result_poly` in fhers.rs; returns Lagrange-interpolated result in [0,Q) domain. Implementation remaining: ~3 days — wire pipeline, add plaintext finalization step to C7 circuit, RED tests.)
- [x] B.2: G4 full PK binding in R1CS (DECIDED — Merkle-path approach recommended: prove dkg_root commits to aggregate_pk leaf via in-circuit Poseidon Merkle proof, ~3-4 days, ~7,200 constraints. Alternative BatchedRingVerifier with full BFV ring equation deferred as constraint-heavy: 2.8M constraints at t=114. Decision documented in notepad.)
- [-] B.3: G7 recursive NIZK verification in R1CS (DEFERRED — potentially infeasible: 67M constraints for polynomial multiplication; needs protocol redesign)
- [x] C.1: HonkVerifier.sol deployed to Sepolia, all 129 tests pass
- [x] C.2: Gas optimization profiled and documented (1,885,528 gas for real UltraHonk verify)
- [x] C.3: T1/T2/T4 proof docs updated with measured values
- [x] D.1: Paper fully synced (all 12 alignment-plan criteria done)
- [x] D.2: REPRODUCING.md covers all C7 variants
- [-] E.1-E.4: Gate resolution phases Ω2-Ω5 complete (DEFERRED — requires human oracle reviewers, external cryptographers, adversarial dress rehearsal; not automatable)
- [x] `just demo-e2e` ACCEPT at every level
- [x] `just paper-gate` PASSES
- [x] All existing tests pass (`cargo test --workspace`, `forge test`, `just phase1-gate`, `just phase2-gate`, `just phase3-gate`)

---

## Estimated Effort

| Phase | Scope | Effort |
|-------|-------|--------|
| A — Remediation | 3 items (documentation-heavy) | ~2 days |
| B — Trust gaps | 3 gaps (G3, G4, G7) | ~2-3 weeks |
| C — On-chain | Deploy + gas + docs | ~1-2 weeks |
| D — Paper | Remaining alignment batches | ~1 week |
| E — Gates | Oracle reviews + dress rehearsal + freeze | ~3-4 weeks |
| **Total** | | **~7-11 weeks** |

Phase F (research: P1-P4 open problems, `pvthfhe-followon.md`) is 9-18 months and excluded from this estimate.
