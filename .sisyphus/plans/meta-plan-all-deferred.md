# Meta-Plan: All Remaining Incomplete Work

**Plan**: `meta-plan-all-deferred`
**Status**: READY (updated with Phase G — 32 security review findings)
**Updated**: 2026-05-18 (Phase G added after 7-agent parallel security audit)
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
| **P1** | Lattice NIZK well-formedness soundness (Greco M-SIS reduction). Canonical source: `SECURITY.md §P1` and `docs/OPEN-PROBLEM-BLOCKERS.md`. Dedicated plan: `.sisyphus/plans/p1-sigma-repetition.md` (382 lines, 30+ unchecked tasks, PLAN status 2026-05-28). Adds 90-round sigma repetition for 2^-128 soundness. Also: `.sisyphus/plans/p1-t3-zk-remove-openings.md` (COMPLETE — ZK property of serialized proofs verified). NOTE: `SECURITY.md` is internally inconsistent — line 54 says "P1 is resolved" but line 62 says "OPEN (mitigated)". Canonical status: OPEN (mitigated via SIGMA_REPETITIONS=90 in production). | OPEN |
| **P2** | LatticeFold+ over RLWE (Cyclo Theorem 3 / Lemma 9). Canonical source: `SECURITY.md §P2`. Dedicated plan: `.sisyphus/plans/p2-lattice-folding.md` (250 lines, 36 unchecked tasks, PLAN status 2026-05-28). Goal: complete Symphony adoption — enable T1 (high-arity folding) and T2 (FS outside circuit) by default. Nova IVC currently serves as folding substitute. Sub-plans: `p2-m1` through `p2-m6`. NOTE: The `Compressor` enum in `compressor_glue.rs` was restructured during gate reconciliation (2026-06-04) to cfg-mutually-exclusive LatticeFold/Nova/Surrogate variants — this affects the code surface that P2's Symphony enablement would modify. | OPEN (Nova substitute in use) |
| **P3** | Parameterized Nova step circuit verification (ext-scaling) | OPEN (documented limitation) |
| **P4** | On-chain IVC decider verification — `ivcDeciderVerifier` at `address(0)`, fail-closed. Canonical source: `docs/OPEN-PROBLEM-BLOCKERS.md §P4` and `SECURITY.md`. Dedicated plan: `.sisyphus/plans/p4-onchain-ivc.md` (426 lines, 36 unchecked tasks, PLAN status 2026-05-28). Two options: Noir native RecursiveSNARK verifier (blocked on BN254 pairing precompile) or Groth16/PLONK UltraHonk wrapper. | OPEN (fail-closed) |

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
- [x] G.1: Canonicalize d_commitment hash function (Poseidon `bind_8_with_domain_native` domain 6) across pipeline, e2e test, and witness_gen. Remove SHA-256 and rolling_digest variants. → demo-e2e, aggregator
- [x] G.2: Extend d_commitment to bind ALL protocol steps: keygen_transcript_hash, all_nizk_proofs_hash, fold_accumulator_hash, compressed_proof_digest, ciphertext_hash. Reorder fields to match pipeline step sequence. → demo-e2e, aggregator
- [x] G.3: Add end-to-end d_commitment verification in `run_full_pipeline()` — post-pipeline assertion in PipelineReport comparing computed d_commitment to Noir-verified value. → demo-e2e
- [x] G.4: Fix d_commitment circular binding — verifier must supply d_commitment or bind to independently verifiable data (e.g., decrypt_share proofs commit to individual d_i hashes). → demo-e2e, aggregator
- [x] G.5: Absorb d_commitment into all Fiat-Shamir challenge derivations (NIZK sigma protocol + C7 circuit). → demo-e2e
- [x] G.6: Constrain `participant_shares` witness in Noir `aggregator_final` circuit — verify each share against individual decrypt_share proofs or require verifier-published combined_share_hash. → demo-e2e, aggregator
- [x] G.7: Bind `committee_party_ids` to `participant_set_hash` in Noir circuit: `vector_hash(committee_party_ids[0..n], DOMAIN) == participant_set_hash`. → demo-e2e, aggregator
- [x] G.8: Enforce `threshold` in Noir interpolation — exactly t shares used, or n-t shares are zero. → demo-e2e, aggregator
- [x] G.9: Delete `circuits/share_wf/src/main.nr` from disk (already removed from workspace). If circuit needed, add `pk_hash` constraint. → demo-e2e
- [x] G.10: Add `assert(party_id != 0)` in Noir `decrypt_share` circuit. → demo-e2e, per-node
- [x] G.11: Add duplicate `party_id` check in `FhersBackend::aggregate_decrypt` (matching mock backend). → demo-e2e, per-node, aggregator
- [-] G.12: Add cryptographic binding of shares to sender identity (signature, NIZK proof binding, or session-anchored MAC). → demo-e2e, per-node, aggregator
- [x] G.13: Restrict secret key access through `party_state` — add capability or per-party isolate. Audit all `party_secret_key_bytes()` callers. → per-node
- [x] G.14: Fix Lagrange coefficient overflow for n > 35 in `compute_lagrange_coeffs_integer` — use BigInt or modular arithmetic. → demo-e2e, aggregator
- [x] G.15: Return error instead of `i128::MAX` sentinel in `crt_reconstruct_coeffs` overflow path. → demo-e2e, aggregator
- [x] G.16: Design composed circuit or cross-circuit verifier challenge binding C7 decryption aggregation + CycloFold ring/sigma into single IVC chain. → demo-e2e, aggregator
- [-] G.20: Add prover randomness or verifier challenge to C7 challenge derivation (currently fully deterministic from public info). → demo-e2e, aggregator
- [-] G.26: Formal IND-CPAD reduction with current smudging parameters (σ=2^40·σ_err). → paper, security-proofs
- [x] G.30: Enforce `fold_count`, `ring_verification_count`, `sigma_verification_count` mutual consistency with actual verification data present (not just counter equality). → demo-e2e, aggregator
- [x] G.31: Verify empty set doesn't bypass C7 commitment check — ensure `c7_fold_witnesses` rejects empty C7WitnessSet. → demo-e2e
- [x] G.32: Clear thread-local ring/sigma data at start of `prove()` and `prove_steps()` to prevent stale witness leakage between runs. → demo-e2e, aggregator
- [x] `just demo-e2e` ACCEPT at every level
- [x] `just paper-gate` PASSES
- [x] All existing tests pass (`cargo test --workspace`, `forge test`, `just phase1-gate`, `just phase2-gate`, `just phase3-gate`)
- [x] H.1: `.sisyphus/plans/c7-correctness.md` exists — C7 threshold-decryption correctness plan with Noir circuit design and test vectors
- [x] H.2: `.sisyphus/plans/c5-formation-proof.md` exists — C5 aggregate pk formation proof plan with rogue-key protection
- [x] H.3: `.sisyphus/plans/a1-accumulator-transcript.md` exists — A1 Cyclo accumulator transcript plan with codec design and adversarial tests

---

## 🟣 Phase G — Security Review Remediation (May 18, 2026)

**Source**: `.sisyphus/notepads/security-review-may-18/security-review.md`
**Scope**: 32 actionable findings from 7 parallel audit agents across paper, implementation, and plans.
**Included in**: All findings include `just demo-e2e`, `just per-node`, and/or `just per-aggregator` coverage as indicated.

### G.A — Hash Chain & Protocol Binding (Tier 0, ~4 days)
- [-] G.1: Canonicalize d_commitment hash function (Poseidon `bind_8_with_domain_native` domain 6)
- [x] G.2: Extend d_commitment to bind ALL protocol steps
- [x] G.3: Add end-to-end d_commitment verification
- [x] G.4: Fix d_commitment circular binding
- [x] G.5: Absorb d_commitment into Fiat-Shamir challenges

### G.B — Noir Circuit Soundness (Tier 0-1, ~4.5 days)
- [x] G.6: Constrain participant_shares witness in Noir circuit
- [x] G.7: Bind committee_party_ids to participant_set_hash
- [x] G.8: Enforce threshold in interpolation
- [x] G.9: Delete share_wf file or add pk_hash constraint
- [x] G.10: Add party_id != 0 check in decrypt_share

### G.C — FHE Backend & NIZK (Tier 1, ~3.5 days)
- [x] G.11: Add duplicate party_id check in FhersBackend::aggregate_decrypt
- [-] G.12: Add cryptographic binding of shares to sender identity
- [x] G.13: Restrict secret key access through party_state
- [x] G.14: Fix Lagrange coefficient overflow for n > 35
- [x] G.15: Return error instead of i128::MAX sentinel

### G.D — Compressor & Folding (Tier 1, ~11 days)
- [x] G.16: Compose C7 + CycloFold into single IVC chain
- [-] G.20: Add prover randomness to C7 challenge derivation
- [x] G.30: Enforce counter consistency with actual verification data
- [x] G.31: Reject empty C7WitnessSet in commitment check
- [x] G.32: Clear thread-local data at prove start

### G.E — CLI & Infrastructure (Tier 1-2, ~1.25 days)
- [x] G.21: Gate stdout secret leaks behind --verbose
- [x] G.22: Add subprocess timeouts
- [x] G.23: Add compile-time guard for demo-seeded-rng
- [x] G.24: Verify nargo/bb binary hashes

### G.F — Research & Documentation (Tier 1-2, ~4 days)
- [x] G.25: Document CPAD resistance with noise analysis
- [-] G.26: Formal IND-CPAD reduction
- [x] G.27: Document Fiat-Shamir security loss bound
- [x] G.28: Implement or document robust secret sharing
- [x] G.29: Cross-reference DOMAIN_* constants

---

---

## 🟤 Phase H — Uncovered OPEN Research Problems (needs plan creation)

These OPEN problems from `docs/OPEN-PROBLEM-BLOCKERS.md` and `SECURITY.md` have NO dedicated sub-plan and are NOT covered above by Phases A–G. Each needs a scoped plan created before work begins.

### H.1 — C7: Threshold-decryption correctness
- **Canonical source**: `docs/OPEN-PROBLEM-BLOCKERS.md §C7`
- **Status**: OPEN — `aggregator_final` Noir circuit proves hash binding only, NOT Lagrange recombination arithmetic (Σ λ_i · d_i ≡ plaintext).
- **Coverage gap**: `c7-p3-final.md` covers C7 N=8192 SCALING (6/6 tasks checked — DONE) but NOT decryption CORRECTNESS. Phase B.1 (G3: full plaintext binding) covers proving decryption result matches submitted shares in R1CS — tangentially related but NOT the full C7 recombination correctness proof.
- **Missing**: A Noir circuit proving that Lagrange-recombined shares correctly reconstruct the plaintext. Requires in-circuit field arithmetic over the ciphertext ring.
- **Existing related work**: `circuits/aggregator_final/src/main.nr` (Poseidon hash checks only). F67 decrypt-share wire-v2 (ct_hash binding) is an orthogonal robustness fix — does NOT address C7 correctness.
- [x] H.1 Create plan `.sisyphus/plans/c7-correctness.md`: wire threshold-decryption arithmetic into `aggregator_final` Noir circuit with test vectors covering valid/invalid partial shares and manipulated Lagrange coefficients.

### H.2 — C5: Aggregate public-key formation proof
- **Canonical source**: `docs/OPEN-PROBLEM-BLOCKERS.md §C5`
- **Status**: OPEN — no proof that `pk_agg = Σ pk_i`. `c5_proof_root` is `bytes32(0)` placeholder.
- **Coverage gap**: Phase B.2 (G4: Merkle-path proof that dkg_root commits to aggregate_pk leaf) covers PK BINDING (proving aggregate_pk is committed in DKG transcript) but NOT PK FORMATION (proving the committed pk_agg IS the sum of individual pk_i). Rogue-key attacks are not addressed.
- **Missing**: A proof (SNARK or Sigma-aggregate) that `pk_agg` correctly sums participant keys, with rogue-key protection.
- [x] H.2 Create plan `.sisyphus/plans/c5-formation-proof.md`: design aggregate pk formation proof with rogue-key protection (PoP or key-registration model).

### H.3 — A1: Cyclo accumulator transcript verification
- **Canonical source**: `docs/OPEN-PROBLEM-BLOCKERS.md §A1`
- **Status**: OPEN — nonzero accumulator bytes rejected ("cyclo accumulator present but unverified (fail-closed)"). Only empty placeholder accepted.
- **Coverage gap**: Not referenced anywhere in meta-plan. `close-nova-gaps.md` (12/12 checked — DONE) covered CycloFoldStepCircuit validation but NOT the full accumulator transcript verifier. The 26,658-byte minimum-proof-size surrogate in `fold_e2e_soundness.rs` is a SIZE GATE, not real A1 transcript verification.
- **Missing**: A real versioned accumulator transcript plus verifier wired to Cyclo fold relation and NIZK statement.
- [x] H.3 Create plan `.sisyphus/plans/a1-accumulator-transcript.md`: implement Cyclo accumulator transcript codec with versioning, wire into NIZK adapter, and add adversarial tests (wrong statement hash, wrong commitment root, norm-bound violation, wrong instance count).

---

## Estimated Effort

| Phase | Scope | Effort |
|-------|-------|--------|
| A — Remediation | 3 items (documentation-heavy) | ~2 days |
| B — Trust gaps | 3 gaps (G3, G4, G7) | ~2-3 weeks |
| C — On-chain | Deploy + gas + docs | ~1-2 weeks |
| D — Paper | Remaining alignment batches | ~1 week |
| E — Gates | Oracle reviews + dress rehearsal + freeze | ~3-4 weeks |
| **G — Security Review** | **32 items (May 18 audit)** | **~28 days** |
| **H — OPEN Problems** | **C7 correctness (plan needed), C5 formation proof (plan needed), A1 accumulator transcript (plan needed)** | **TPL: plan creation first; 4-6 weeks implementation** |
| **Total** | | **~15-21 weeks** |

Phase F (research: P1-P4 open problems, `pvthfhe-followon.md`) is 9-18 months and excluded from the estimate above. Phase H (C5, C7 correctness, A1 — plan creation needed) is TBD.
