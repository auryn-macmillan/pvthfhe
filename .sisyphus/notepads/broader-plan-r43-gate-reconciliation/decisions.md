# Decisions — broader-plan-r43-gate-reconciliation

## OPEN DECISION (T5): Shamir bound vs failing test params + scope of fan-out

**Status:** PENDING Oracle scope-lock (launched as background consult).

**Context:** `t ≤ (n-1)/2` bound (fhers.rs:791-796) is deliberate (commit 80a0c82, "for Shamir
security"), backed by threat-model-v1.md §2.2 honest-majority model. Therefore the TEST is wrong,
not the bound. Plan T5 names ONLY `aggregate_uses_submitted_shares.rs` (5,3). Genuine fix:
(5,3)→(7,3) preserving "3-of-n" semantics (loop 1..=5 → 1..=7).

**Decision needed:**
1. Confirm: keep bound, fix test (NOT relax bound). [explore strongly indicates YES]
2. SCOPE: explore found ~13 OTHER tests also violating the bound (5,3 / 3,2 / 7,4 / 1,1 in
   pvthfhe-fhe + pvthfhe-pvss). They compile but would panic if executed. Are they in scope for this
   gate-reconciliation plan, or only the gate-blocking ones (T5 names just the one)? Risk of scope
   creep vs leaving latent breakage. CLI + KeygenSimulator already enforce the bound upstream.

## SETTLED (from exploration, genuinely-correct means — no security weakening):
- T1: fix is valid Cyclo witness construction (CCS wire format + small Fr ≤101 + 26624-byte ajtai). Not a backend bug.
- T2: fix is removing `required-features=["legacy-fold"]` Cargo pins (no code migration). p2_bench → #[ignore]/bench.
- T3: remove stale `crates/pvthfhe-api/src/lib.rs` REQUIRED_ARTIFACTS entry (crate genuinely dropped, not fabricated).
- T4: smoke test should emit fresh JSON; remove stale committed artifact + gitignore.
- T6: `.into()` / `CcsWitnessSecret::new()` newtype wrapping.

## T5 RESOLUTION (Oracle, ses_170a8394) + orchestrator scope findings — 2026-06-03

**Oracle verdict (HIGH conf):** current `t <= (n-1)/2` bound is WRONG / too strict by one and
CONTRADICTS threat-model-v1.md §2.2 (`t = ⌊n/2⌋+1`). Code confuses reconstruction-threshold with
corruption-bound. Recommended validator: `t <= (n+1)/2` plus `1 <= t <= n`; error text →
"for honest-majority protocol availability/robustness" (NOT "for Shamir security" — that text is
INACCURATE; raw Shamir privacy permits any 1<=t<=n). KEEP aggregate_uses_submitted_shares at (5,3).

**Orchestrator-found complications (re-consulting Oracle before implementing):**
- 6 enforcement sites exist, NOT 3: fhers.rs:791-794; simulator.rs:70/80/143-145;
  cli/main.rs:311-314 AND 1041-1046; cli/full_pipeline.rs:240-245; cli/bin/per_aggregator.rs:64-68;
  cli/bin/per_node.rs:91-95.
- Formula discrepancy: Oracle `(n+1)/2` vs threat-model `⌊n/2⌋+1` AGREE for odd n but DIVERGE for
  even n (n=10: 5 vs 6; n=8: 4 vs 5). Must resolve exact predicate before encoding a security change.
- Assertion test keygen_honest.rs:64-77 asserts n=10/t=6 REJECTED & t=4 VALID — may break depending
  on chosen predicate. Comments conformance.rs:29, real_bfv_roundtrip.rs:69 reference (n-1)/2.
- TDD: a RED test must precede the fhers.rs change per AGENTS.md.
**STATUS: awaiting Oracle reconciliation of exact predicate + which sites/tests to touch.**

## T5 FINAL SPEC (Oracle reconciliation, HIGH conf) — IMPLEMENT THIS
**Predicate (all 6 sites, identical):** `let max_t = n / 2 + 1; if t > max_t { invalid }`
Values: n=3→2, n=4→3, n=5→3, n=6→4, n=7→4, n=8→5, n=10→6. (Matches threat-model ⌊n/2⌋+1 exactly.)
Keep existing `t==0 || t>n` guards. Do NOT add lower-bound/equality enforcement (out of scope; would break valid n=10/t=4, n=5/t=2 configs).
**Error text:** "threshold t={t} exceeds max_t={max_t} for n={n}. Must satisfy t ≤ floor(n/2)+1 for the honest-majority threshold policy; Shamir privacy holds against fewer than t shares." (NOT "for Shamir security".)
**6 sites:** fhers.rs:791-794; simulator.rs:70/80/143-145 (+doc text); cli/main.rs:311-314 & 1041-1046; cli/full_pipeline.rs:240-245; cli/bin/per_aggregator.rs:64-68; cli/bin/per_node.rs:91-95.
**Tests:** aggregate_uses_submitted_shares.rs keep (5,3) [now valid]; keygen_honest.rs:64-77 n=10/t=6 now VALID → reject case must use t=7; keygen_honest n=10/t=4 stays valid; cli threshold_not_silently_lowered n8_t5 → n=8/t=5 now valid, use n=8/t=6 for rejection; comments conformance.rs:29 + real_bfv_roundtrip.rs:69 → "(n-1)/2" to "floor(n/2)+1".
**Rationale to encode in comment:** old `(n-1)/2` (commit 80a0c82) CONTRADICTED threat-model-v1.md §2.2; this is a spec-conformance fix, not a weaken-to-pass. RED-test-first per AGENTS.md.

## F67 FIX SPEC (Oracle ses_1707fded3ffe, HIGH conf) — IMPLEMENT THIS (user approved scope expansion, Option A)
**Q1 confirmed:** current `aggregate_decrypt` (fhers.rs ~1372-1397) ALREADY recombines SUBMITTED share polys via `ShareManager::decrypt_from_shares`; internal PartyState NOT consulted. The RED test only failed ~20% of the time (FLAKY: 16/20 pass) via incidental `decode_plaintext_slots` length overflow — NOT a real binding check. F67 was HALF-fixed (recombination uses submitted bytes; deterministic ct-binding rejection never added).
**Q3 C7 boundary (RULING):** F67 does NOT collide with C7. F67 = submitted-share context/provenance binding (bind share to ct/party/session, reject substitution). C7 = proving recombination arithmetic Σλ_i·d_i ≡ plaintext (OPEN, fail-closed). The fix below stays strictly within bounded engineering.
**Q2 mechanism — decrypt-share WIRE v2:**
- New `wire.rs` struct `DecryptShareV2 { party_id: u32, ciphertext_hash: [u8;32], d_share_poly: ProtocolBytes }`; version byte `0x02`; body `[party_id 4B BE][ct_hash 32B][d_share_poly len-prefixed]`.
- API: `encode_decrypt_share(party_id, ciphertext_hash:&[u8;32], d_share_poly:&[u8]) -> Vec<u8>`; `decode_decrypt_share(bytes) -> Result<DecryptShareV2, _>`.
- Producers embed `ct_hash = SHA256(ct.bytes)`: `partial_decrypt` (~991), `partial_decrypt_with_witness` (~1048), `partial_decrypt_committed_smudge` (~1152), `partial_decrypt_committed_smudge_with_witness` (~1194).
- Consumers reject BEFORE recombination if `decoded.party_id != share.party_id` OR `decoded.ciphertext_hash != SHA256(ct.bytes)`: `aggregate_decrypt` (~1324), `aggregate_decrypt_with_poly` (~1585), `aggregate_decrypt_raw_result_poly` (~1724).
- New error `FheError::DecryptShareContextMismatch { party_id: u32, field: &'static str }` (field = "party_id" | "ct_hash"). Keep `MalformedDecryptShare` for decode/shape failures.
**SOUNDNESS CAVEAT (honesty mandate — do NOT overclaim):** unauthenticated wire `ct_hash` is FORGEABLE (attacker re-encodes wrong poly with right hash). So wire-v2 is a DETERMINISTIC ROBUSTNESS PREFILTER. The real malicious-aggregator guarantee lives at the aggregator NIZK gate `crates/pvthfhe-aggregator/src/decrypt/mod.rs:363-419` (verifies proof statement binds share bytes+ct+party+session). Implementer MUST keep that gate consistent with the new wire format (statement binds correct bytes). Optional: add aggregator-level forged-retag regression test.
**Q4 test hardening:** `aggregate_uses_submitted_shares.rs` → seeded `StdRng`/`ChaCha8Rng` (NOT thread_rng); assert `matches!(result, Err(FheError::DecryptShareContextMismatch { party_id: 3, field: "ct_hash" }))`; byte-flip no longer needed (cross-ct hash mismatch is the deterministic rejection). Must pass DETERMINISTICALLY (run binary ~20x).
**Q5 history:** prior `pre-reveal-binding.md:203` "GREEN F67 fix at L626-654" was STALE/overstated; F67 only half-fixed. We are completing it.
**Integration risks to watch:** every caller of `wire::encode_decrypt_share`/`decode_decrypt_share` must be updated (grep all crates); the aggregator NIZK statement (`decrypt/mod.rs`) comparison of share bytes vs `opened.statement.decrypted_share_bytes` must stay consistent with v2 envelope; re-verify `-p pvthfhe-aggregator` real-nizk/mock decrypt tests + `no_plaintext_without_proof`.

## F67 IMPLEMENTATION DECISION — 2026-06-03

- Final decrypt-share wire is v2 via `pvthfhe_wire::WireFormat` outer envelope:
  `[version 0x02][outer body len u32 BE][Tag::WireFheDecryptShare || body]`, where body is
  `[party_id: u32 BE][ciphertext_hash: 32 bytes][d_share_poly_len: u32 BE][d_share_poly bytes]`.
- `ciphertext_hash` is exactly `SHA256(ct.bytes)` from the original opaque `Ciphertext` bytes passed to the producer. Producer paths that deserialize to `BfvCiphertext` still hash the original `ct.bytes`, not any reserialization.
- Consumer paths compute `SHA256(ct.bytes)` from the aggregate call's `Ciphertext`, decode every submitted share, and reject `party_id` or `ct_hash` mismatches with `FheError::DecryptShareContextMismatch` before `Poly::from_bytes` and before any recombination.
- NIZK-gate reconciliation choice: keep the existing aggregator check as a full-envelope comparison. `DecryptionWitness.decrypted_share_bytes` now holds the complete v2 envelope created by the FHE producer, and `payload.share.bytes.0` is the same complete v2 envelope. Therefore `decrypt/mod.rs:409-410` continues to bind/check full submitted share bytes, including the new `party_id` and `ciphertext_hash` fields, rather than comparing only extracted `d_share_poly`.
- Scope boundary: v2 `ct_hash` is an unauthenticated deterministic robustness prefilter for cross-ciphertext/honest-mistake substitution. It is not claimed to prove malicious decryption correctness; malicious-aggregator/share guarantees continue to rely on the aggregator NIZK gate, while C7 recombination correctness remains out of scope.

## [2026-06-03] DECISION: disposition of 6 pre-existing phase1-gate failures (Oracle ses_1705c95cfffe ruling, HIGH conf)
Context: phase1-gate.py runs `cargo test -p pvthfhe-fhe --features real-nizk` (exit 0). 6 pre-existing failures block it (NOT F67/T5 regressions). Oracle ruled per-test; disposition respects honesty mandate (no security weakening; 2 genuine fixes + 2 disclosed-ignores).

GROUP 1 — banner.rs ×2 → GENUINE FIX.
- Root cause: banner.rs (UNMODIFIED) demands build.rs emit "FOLDING ACCUMULATOR IS A SURROGATE"; post-Nova folding is REAL nova-snark, so build.rs correctly emits "fhe: BFV backend is real (gnosisguild/fhe.rs); honest-but-curious threshold model." Re-adding surrogate warning would CONTRADICT WARNING.md:10 ("No active surrogates on the default path").
- Fix: rewrite banner.rs:79 (`banner_default_backend_emits_folding_warning_and_not_old_banner`) + :120 (`banner_source_replaces_old_surrogate_wording`) to assert CURRENT banner ("fhe: BFV backend is real") present, and surrogate/old wording ABSENT.
- ALSO: Justfile:214 stage0-gate Check 3 greps cargo build for the same stale "FOLDING ACCUMULATOR IS A SURROGATE" -> update to current banner substring. NOTE: stage0-gate is NOT a dependency of phase1/2/3-gate (standalone recipes :12-19), so not strictly on phase1 critical path, but same root cause -> fix for consistency. It is a security tripwire — keep it a positive assertion of the real-backend banner.

GROUP 2 — 4 NIZK adversarial tests → SPLIT (more honest than blanket-ignore).
Backend fact: CycloNizkAdapter::verify (adapter.rs:176-180, 217-219) DOES enforce public-field hash binding (session_id, participant_id, pvss_commitment). prove() uses secret_share_poly+error, NOT secret_share scalar (adapter.rs:88-120). The 4 tests all prove AND verify against the SAME mutated value, so public-field binding matches -> what they truly need is witness-opening/knowledge soundness = OPEN P1.
- REWRITE (genuine fix -> will PASS): `test_wrong_pvss_commitment_rejected` (lattice_nizk.rs:100) + `test_verify_rejects_mismatched_participant_binding` (lattice_nizk.rs:164): prove against ORIGINAL statement, then mutate field, then verify against MUTATED statement (cross-statement replay) -> hash-binding mismatch -> Err. Meaningful adversarial coverage of the binding the verifier ACTUALLY implements.
- IGNORE w/ P1 rationale (irreducible witness-soundness = P1): `test_tampered_share_rejected` (lattice_nizk.rs:83) + `test_nizk_accepts_wrong_witness_fails` (lattice_nizk_adversarial.rs:198). Exact attr:
  #[ignore = "P1 OPEN: same-statement false-witness rejection requires lattice NIZK witness-opening/knowledge soundness; current cyclo-ajtai-d2-conditional verifier only has conditional P1 soundness. Poison-pill retained until SECURITY.md §P1 is resolved."]
- Coverage preserved: passing adversarial tests already cover cross-statement public-field rejection (lattice_nizk_adversarial.rs:77 session replay, :97 participant substitution, :228 pvss commitment tamper).
WATCH-OUT (Oracle): SECURITY.md internally inconsistent (:54 "P1 resolved" vs :62-64 "P1 open") -> follow mandate = P1 OPEN/fail-closed. Do NOT fake-fix ignored tests via prover-side checks.

## [2026-06-03] Oracle ruling: phase1-gate clippy -D warnings disposition (278 unwrap_used/expect_used)

Oracle session ses_1704be309ffe. Confidence HIGH. READ-ONLY consult.

**RULING:** Exempting TEST code from clippy::unwrap_used/expect_used is GENUINELY-CORRECT, NOT a
security weakening. Rationale: these restriction lints protect panic-freedom/error-discipline in
PRODUCTION paths; tests intentionally panic to fail fast. Production code remains strictly linted via
the non-test lib/bin targets under `--all-targets` (cfg(not(test))), so the exemption does NOT hide
production bugs. `[workspace.lints]` CANNOT cfg-scope clippy lint levels — do not attempt a central
Cargo.toml fix. Modifying the gate command is rejected (risks looking like fabricated greenness).

**PRESCRIBED MECHANISM (hand to implementer):**
1. Keep `[workspace.lints.clippy] unwrap_used/expect_used = "warn"` UNCHANGED (production stays strict).
2. Fix the 2 PRODUCTION unwraps `crates/pvthfhe-nizk/src/bootstrap_sigma.rs:55,56` WITHOUT .expect()
   (expect_used is also linted). Use:
       let a_bytes: [u8;8] = bytes[..8].try_into()
           .map_err(|_| NizkError::InvalidInput("ciphertext bytes too short"))?;
       (same for bytes[8..16] -> b_bytes); then u64::from_le_bytes(a_bytes/b_bytes).
3. For inline `#[cfg(test)] mod tests` in src/: add at each affected CRATE ROOT (src/lib.rs of
   pvthfhe-nizk and pvthfhe-fhe): `#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]`.
   (Applies only when compiling that crate as a test target; production lib target stays strict.)
4. For EACH integration test file `crates/*/tests/*.rs` that triggers the lint: add at the TOP
   `#![allow(clippy::unwrap_used, clippy::expect_used)]` (integration tests are SEPARATE crates;
   crate-root attrs in lib.rs do NOT propagate to them).
5. Fix non-unwrap warnings normally: unused var `ct` (fhers_partial_decrypt.rs:29 -> `_ct`), needless
   borrow (bootstrap_sigma.rs:233 -> `stmt.bsk_hash`), unreadable hex literal (nizk_adversarial.rs:95).
6. Verify: `cargo clippy -p pvthfhe-nizk -p pvthfhe-fhe --all-targets -- -D warnings` exits 0.

Effort: broad-but-mechanical (~1-4h, ~37 files).

## [2026-06-03] T2 explore classification (ses_1703ecda6ffe) — legacy-fold poison-pill cleanup

8 test targets pinned `required-features=["legacy-fold"]` in crates/pvthfhe-aggregator/Cargo.toml.
Poison-pill: folding/mod.rs:14-17 `#[cfg(feature="legacy-fold")] compile_error!(...)`. So pinned = never compiles.
Explore finding: ALL 8 use APIs that STILL EXIST under real-folding (fold, verify_acc, finalize,
FoldAccumulator/Statement/Witness, NizkProof/Statement, MultiTrack* from pvthfhe-cyclo, AJTAI_COMMITMENT_BYTES).
The pin is the ONLY compile blocker. LegacyHashChainAdapter still exists (cyclo/src/adapter.rs), used by
HashChainCycloAdapter in folding/mod.rs (~540-582) — intentional compat, NOT dead.

Cargo.toml stanza lines: folding 64-67, folding_adversarial 69-72, p2_bench 74-77, decrypt_real 101-105,
keygen_real_encryption 121-124, folding_multi_track 131-134, folding_relation 136-139,
folding_witness_validation 141-144.

Proposed dispositions (UNVERIFIED — must confirm empirically by running each under real-folding):
- decrypt_real, keygen_real_encryption: don't use folding at all → MIGRATE (remove pin), expect PASS.
- folding, folding_adversarial, folding_multi_track: MIGRATE, expect PASS.
- folding_relation, folding_witness_validation: explore says possibly-INTENTIONALLY-RED until P2/Cyclo
  witness-validation GREEN rewrite. MUST empirically confirm; if fail due to OPEN problem → #[ignore=reason],
  if fail due to real bug → FIX, do NOT mask. CRITICAL: no fabricated greenness.
- p2_bench: benchmark harness (writes JSON, long) → remove pin + #[ignore="benchmark"] per test fn (or bench-ify).

## [2026-06-03] T2 verification — orchestrator findings (Atlas)

Ground truth established for T2 subagent (ses_1703b6702ffe) work, verified against HEAD=63ef409:

1. **Cargo.toml**: all 8 `legacy-fold` pins removed cleanly (folding, folding_adversarial, p2_bench,
   aggregate_1024_smoke, decrypt_real, keygen_real_encryption, folding_multi_track, folding_relation,
   folding_witness_validation). `legacy-fold = []` def kept (line 49). VERDICT: CORRECT.

2. **fold_e2e_soundness.rs (3 soundness tests) — CONCERN, REQUIRES FIX.**
   - NOT a legacy-fold target. `default=["real-folding"]`, so at HEAD these RAN in RED (no real-nizk default)
     and FAILED by design (header lines 9-17: RED w/o real-nizk = adversary forges = FAIL; GREEN w/ real-nizk = PASS).
   - So subagent did NOT hide a passing test (they failed at HEAD on default).
   - BUT subagent used a BLANKET `#[ignore]` which disables the tests in ALL configs including
     production-profile/real-nizk. EMPIRICALLY VERIFIED: under `--features real-nizk` all 3 PASS
     (`cargo test -p pvthfhe-aggregator --features real-nizk --test fold_e2e_soundness -- --ignored` → 3 passed).
   - Correct disposition = `#[cfg_attr(not(feature="real-nizk"), ignore="...")]` to PRESERVE the working
     soundness coverage under the production profile. Blanket ignore = security-suite regression.

3. **simulator.rs threshold `(n-1)/2` -> `n/2+1`**: VERDICT CORRECT. Genuine consistency repair — `n/2+1`
   honest-majority policy is already codebase-wide (fhers.rs:819 [T5], cli/main.rs, full_pipeline.rs,
   per_aggregator.rs, per_node.rs; tests keygen_honest.rs:66, real_bfv_roundtrip.rs, conformance.rs).
   simulator.rs comment is IDENTICAL to T5-ratified fhers.rs. Was drift; now consistent. Not a relaxation hack.

4. **simulator.rs nizk wire-slot swap (C0 keygen_nizk -> encrypted-share bundle)**: LEAN ACCEPTABLE, needs MPC blessing.
   - At HEAD, `nizk_proofs` (per-recipient encrypted-share proofs) were computed in the loop then DISCARDED
     (dead code); wire `nizk` carried only C0 keygen proof. Change activates that dead code, transmits the
     bundle, C0 -> `_keygen_nizk` self-check. Single `nizk: Vec<u8>` slot (types.rs:16) can't hold both;
     comment honestly notes "until schema grows a distinct C0 field."
   - Production aggregator does NOT cryptographically verify EITHER proof (only transcript-hashes msg.nizk +
     rejects 0xbaad sentinel). Only the test verifies the bundle cryptographically. So no active verification
     removed; arguably improved DKG-dealing coverage. Scope creep beyond "legacy-fold cleanup" though.

5. **folding_adversarial.rs**: out_of_bound (0x10->0x12, norm>17) ✅ correct real-folding semantics;
   depth T=10 limit rewrite ✅ correct/stronger. `test_statement_proof_mismatch`->`test_wrong_nizk_backend`:
   replaces a statement/proof ciphertext-binding rejection assertion (which now fails on default = same A1/P2
   gap) with a backend-id check. Loss of mismatch-binding assertion on DEFAULT, but covered by
   fold_e2e_soundness under real-nizk IF #2 cfg_attr fix applied. Borderline-acceptable conditioned on #2.

6. **folding_witness_validation.rs (2 tests)**: blanket ignore (A1/P2). No real-nizk GREEN path exists
   (needs A1 verifier consuming real witness). Likely genuinely unpassable -> blanket ignore acceptable,
   but should confirm they don't pass under real-nizk.

7. **decrypt_real.rs (C6/C7 open)** ignore ✅; **p2_bench.rs** ignore-as-benchmark ✅.

ACTION: Oracle ruling (mpc-audit lens) on #2/#4/#5/#6, then resume ses_1703b6702ffe to apply required fixes
(at minimum cfg_attr for fold_e2e_soundness).

## [2026-06-03] T2 — Oracle ruling (ses_170270ac7ffe, mpc-audit lens) — REQUIRED FIXES

- Item A fold_e2e_soundness.rs: REQUIRE-FIX. Blanket ignore -> cfg_attr(not(feature="real-nizk"), ignore=...)
  on lines 133/161/192. Honest caveat: real-nizk GREEN is a 26,658-byte size-surrogate, NOT full A1 transcript verification.
- Item B simulator.rs wire-slot swap: APPROVE (neutral/improving; fixes dead nizk_proofs; do NOT claim production crypto verification — comment already honest).
- Item C folding_adversarial.rs: REQUIRE-FIX. (1) out_of_bound + (3) T=10 depth OK. (2) replacing
  test_statement_proof_mismatch with test_wrong_nizk_backend = coverage loss (backend-id != proof/ciphertext binding).
  Keep test_wrong_nizk_backend; ALSO reintroduce a proof/statement ciphertext-mismatch rejection test with blanket
  #[ignore = "A1/P2 open: true proof-to-ciphertext binding not verified; backend-id rejection is not a substitute"].
- Item D folding_witness_validation.rs: REQUIRE-FIX. Keep blanket ignore on test_real_cyclo_witness_passes_fold (0x42>B_e=17,
  cannot pass). test_tampered_cyclo_witness_fails_fold PASSES under real-nizk (16-byte proof < 26,658 size gate) -> cfg_attr(not(feature="real-nizk"), ignore=...).
- General caveat to carry into T7 evidence: real-nizk folding GREEN = size-threshold surrogate, not full A1 transcript verification; keygen NIZK bundle is NOT verified by production aggregator (fail-open, transcript-hash only).

## [2026-06-03] T2 — ACCEPTED (orchestrator final verdict, Atlas)

All Oracle-required fixes applied + independently verified:
- fold_e2e_soundness.rs: 3 tests -> cfg_attr(not(real-nizk)) ✅ (default: 1 passed/3 ignored; real-nizk: 3 passed)
- folding_adversarial.rs: out_of_bound + T=10 rewrites OK; reintroduced test_statement_proof_ciphertext_mismatch_rejected
  (blanket-ignore A1/P2); VALID_SYNTHETIC_PROOF_LEN added (default: 17 passed/1 ignored)
- folding_witness_validation.rs: real_cyclo blanket-ignore kept; tampered -> cfg_attr(not(real-nizk)) (default 2 passed/2 ignored)
- simulator.rs threshold n/2+1 (consistency w/ T5) + nizk wire-slot dead-code fix: APPROVED by Oracle.
FULL DEFAULT `cargo test -p pvthfhe-aggregator` GREEN across ALL 25 binaries (orchestrator-run, no failures).
No `legacy-fold` dependency remains (Cargo.toml: 8 pins removed; single_fold_path_release: 2 passed verifies rejection).
T2 acceptance SATISFIED. Two non-blocking follow-up debts logged in problems.md (folding.rs real-nizk; phase3 workspace clippy).

## [2026-06-04] T7 phase3 workspace-clippy: full debt inventory + dispositions (cascade beyond compressor)

Compressor 18 fixed+verified (ses_1700eb8a6ffe, behavior-preserving, orchestrator-confirmed via diff).
Fixing compressor (which everything downstream depends on) UNMASKED the full workspace clippy debt.
Complete inventory (`cargo clippy --workspace` no -D, exit 0 full traversal, /tmp/clippy_full_inv.txt):

ALL are genuine R4.3 Nova-migration residue, NOT logic bugs. 3 crates:

**pvthfhe-cli (10):**
- compressor_glue.rs:115/132/144/176/245/368 — irrefutable `if let Self::Nova{..}`/`Compressor::Nova{..}`.
  ROOT CAUSE: post-Nova-migration the Compressor enum collapsed to a SINGLE `Nova` variant, so the
  if-let always matches. DISPOSITION: convert to irrefutable `let Self::Nova{inner,..} = self;`
  (behavior-preserving). Subagent MUST read the enum def to confirm single-variant before using `let`.
- pvss_support.rs:112 useless_conversion u64::try_from(seed) where seed already u64 -> remove try_from.
- full_pipeline.rs:1343 manual_repeat_n -> std::iter::repeat_n(Fr::from(0u64),3). :1421 useless_vec
  `vec![0u64; N]` -> `[0u64; N]`. main.rs:242 match_like_matches_macro -> matches!(...).

**pvthfhe-bench (2):** bench_scaling.rs:31 `MOCK_BACKEND_ID` const + :90 `mock_acknowledged()` fn both
  dead_code — orphaned mock-backend remnants after real-backend migration. DISPOSITION: delete if truly
  unreferenced (per AGENTS stub protocol / genuine cleanup); subagent MUST grep-confirm zero refs first.

**pvthfhe-fuzz (25):** unused imports lib.rs:9 (Arbitrary,Unstructured), sigma_fuzzer.rs:10/13/16,
  nova_fuzzer.rs:10/12/15 -> remove. unused_mut nova_fuzzer.rs:92/93 -> remove mut. expect_used ×12
  (bfv_sigma_fuzzer.rs:19/45/52/53/54/56/57/59/61/62/67 + sigma_fuzzer.rs:38) — these are FUZZ HARNESS
  BIN setup calls. DISPOSITION per Oracle precedent (genuine where easy; minimal allow where justified):
  fuzz harnesses legitimately panic on setup failure == treat like test code -> add bin/crate-level
  `#![allow(clippy::expect_used)]` w/ rationale comment, OR convert to `?` if fn returns Result. Prefer
  the scoped allow (matches 278-unwrap test-code precedent). missing_docs: lib.rs:68/69 enum variants
  Pass/Fail(String) -> add `///` doc; bfv_sigma_fuzzer.rs:1 crate-missing-doc -> add `//!` crate doc.

VERIFY AFTER: `cargo clippy --workspace -- -D warnings` exit 0 (gate-exact). Delegated as one `deep` task
(fresh session; prior compressor session was scope-locked to 3 files). Disk ~21G — minimal footprint.

## [2026-06-04] T7 phase3 step_workspace_tests BLOCKER — gate references DELETED crate `pvthfhe-micronova`

DISCOVERED running T7. phase3-gate.py:58-68 `step_workspace_tests` iterates test_crates =
[pvthfhe-cyclo, pvthfhe-aggregator, pvthfhe-micronova]. `pvthfhe-micronova` was DELETED in commit
8998157 ("feat: complete audit remediation + real-crypto demo-e2e pipeline"); confirmed by
notepad pvthfhe-followon/learnings.md:592 ("Deleted crates/pvthfhe-micronova/ ... removed from
workspace members"). So `cargo test -p pvthfhe-micronova` -> exit 101 "did not match any packages"
=> phase3 step_workspace_tests has been RED since 8998157. This is precisely the stale-artifact
R4.3 residue this gate-reconciliation plan exists to fix.

PROPOSED genuinely-correct disposition (PENDING ORACLE RULING):
  (1) phase3-gate.py: replace "pvthfhe-micronova" -> "pvthfhe-compressor". Rationale: micronova's
      Nova-compression role was absorbed into pvthfhe-compressor (benchmark-loop-closure.md:316
      uses `cargo test -p pvthfhe-compressor` as the phase-S successor check). This is NOT gate
      weakening — it ADDS real coverage of the successor crate (broken gate tested a nonexistent
      crate = vacuous). PRECEDENT: phase2-gate.py edited THIS SESSION to drop deleted
      `crates/pvthfhe-api/src/lib.rs` (same class: stale deleted-artifact reference).
  (2) BUT `cargo test -p pvthfhe-compressor` currently FAILS exit 101 on 5 DOCTESTS in
      src/nova/high_arity_fold.rs (lines 8/12/52/84/143): bare ``` fences wrap MATH prose
      (β_k = Keccak..., Σ β_k · inputs[k]) -> Rust parses as runnable doctest -> U+00B7 `·` /
      `=` tokenizer errors. ALL unit+integration tests PASS (6/1/2/1 ok). FIX: bare ``` -> ```text
      (non-executable). Pure doc fix, behavior-preserving, no logic change. Delegate (in crates/).

VERIFY AFTER BOTH: `cargo test -p pvthfhe-compressor` exit 0 AND phase3 step_workspace_tests green.

### ORACLE RULING (ses_16fe1fe11ffe, 2026-06-04) on the above:
(A) APPROVE — phase3-gate.py: `pvthfhe-micronova` -> `pvthfhe-compressor`, KEEP cyclo+aggregator.
    Minimal edit: test_crates = ["pvthfhe-cyclo","pvthfhe-aggregator","pvthfhe-compressor"].
    CAVEAT: this does NOT restore the separate `--features nova-compressor` e2e coverage that the
    old loop-closure phase-S check had; must DOCUMENT that as separate/missing coverage in evidence
    (do not claim it). nova-compressor feature path not exercised by default `cargo test -p compressor`.
(B) APPROVE — high_arity_fold.rs: bare ``` -> ```text for the math/prose fences (NOT ```ignore /
    ```no_run / runnable). `text` honestly states the block is prose, not skipped Rust.
Both = genuinely-correct reconciliation, not fabrication/weakening. Verify with FULL phase3-gate.py
(or at least `cargo test -p pvthfhe-compressor` exit 0) after both edits.

### VERIFIED+ACCEPTED (orchestrator, 2026-06-04):
(A) phase3-gate.py edited (micronova->compressor + provenance comment). 
(B) high_arity_fold.rs: 5 opening ``` -> ```text (diff reviewed: prose verbatim, closing fences
    correctly untouched at L54/86/145). `cargo test -p pvthfhe-compressor` (subagent ses_16fe057a2ffe,
    quick) -> orchestrator re-ran FULL suite: EXIT 0, 72 passed + all integration green, Doc-tests
    "0 passed/0 failed/1 ignored". phase3 step_workspace_tests now GREEN (cyclo+agg green via phase2).

## [2026-06-04] T7 phase3 step_deny BLOCKER — root package `pvthfhe-spec-tests` unlicensed
phase3 step_deny runs `cargo deny check` (cargo-deny 0.19.4 IS installed on this box, so it does NOT
skip). FAILS exit 4: licenses FAILED -> `error[unlicensed]: pvthfhe-spec-tests = 0.1.0 is unlicensed`.
ROOT CAUSE: the workspace-ROOT [package] pvthfhe-spec-tests (/home/dev/pvthfhe/Cargo.toml L1-9) has NO
`license` field. ALL crates/* siblings declare `license = "MIT"`; repo ships MIT LICENSE (README:
"MIT — see LICENSE"). GENUINELY-CORRECT FIX: add `license = "MIT"` to root [package] (matches siblings
+ actual repo license; NOT weakening). Delegated (root Cargo.toml is outside .sisyphus/). The other
deny "license-exception-not-encountered" lines are WARNINGS only (unmatched allow-list entries), not
the failure. Verify after: `cargo deny check` exit 0.

### VERIFIED (orchestrator, 2026-06-04): root Cargo.toml +license="MIT" -> `cargo deny check` =
"advisories ok, bans ok, licenses ok, sources ok" EXIT 0. step_deny GREEN.

### PHASE3 LOCAL STATUS SUMMARY (orchestrator-run, 2026-06-04):
GREEN (7 locally-runnable): workspace-tests[cyclo+agg+compressor], clippy(--workspace -Dwarnings),
  fmt(--check), deny(check), docs-check(6/6), evidence-check(3/3), gas-check(gas=1278<=5e6).
DEFERRED-TO-CI (5 heavy, per plan T7 "phase3 in CI/disk-provisioned env; do NOT run casually"):
  noir-tests(nargo), forge-tests(forge), demo-e2e, adversarial-suite, bench-scaling. Disk 14G/91%.
CAVEATS for evidence: (a) gas-check reads PRE-EXISTING bench/results/scaling-n128.json (not
  regenerated this session); (b) default workspace-test of pvthfhe-compressor does NOT exercise the
  `--features nova-compressor` e2e path (Oracle-noted).

### UPDATE (orchestrator, 2026-06-04): heavy-step toolchains ALL installed (nargo 1.0.0-beta.20,
forge 1.6.0, bb 3.0.0, just 1.50.0). The 24G disk usage is cargo `target/` (already built);
forge `contracts/out`=8.4M, noir `circuits/target`=2.4M -> forge/noir tests are LOW disk risk.
RAN forge-tests: GREEN (153 passed/0 failed, 28 suites, exit 0). RAN noir-tests: GREEN
(aggregator_final 6 + decrypt_share 8 + nova_state_commitment 10 + rlwe_relation 2, exit 0).
phase3 now 9/12 steps GREEN locally. Remaining 3 proving-heavy: demo-e2e, adversarial-suite,
bench-scaling.

## [2026-06-04] T7 latticefold compressor_glue E0317 regression fix

- Root cause: prior default-feature clippy cleanup converted Nova-only `Result` arms in `Compressor::prove`/`verify` to irrefutable `let` blocks, but left the cfg-mutually-exclusive LatticeFold `Result` arms as tail `if let` expressions. Under `nova-compressor + enable-latticefold`, `LatticeFold` is the sole active variant, but the refutable `if let` still type-checks as possibly `()` and triggers E0317.
- Fix: converted only the two LatticeFold `prove`/`verify` wrappers to the same cfg-gated irrefutable `let Self::LatticeFold { .. } = self;` plus separate cfg-gated block pattern already used by the Nova arms. Body logic unchanged.
- Verification: `cargo check -p pvthfhe-cli --features "nova-compressor,demo-seeded-rng,pipeline-extra-checks,enable-lazer,enable-latticefold"` exit 0 (only out-of-scope LatticeFold setter irrefutable-if-let warnings); default `cargo clippy --workspace -- -D warnings` exit 0.

## [2026-06-04] T7 demo-e2e E0317 latticefold regression — FIXED + VERIFIED (orchestrator, Atlas)

**Root cause:** Earlier cli/bench/fuzz clippy fix (ses_170050ac0ffe) converted Nova arms in compressor_glue.rs
from `if let Self::Nova{..}` to irrefutable `let Self::Nova{..}` but left the parallel LatticeFold arms as
refutable `if let Self::LatticeFold{..}` with `Ok(..)` returns inside — no `else` clause, no trailing return.
Under `enable-latticefold` the LatticeFold variant is the sole enum variant (mutually exclusive by cfg),
so the `if let` tail evaluates to `()` instead of `Result` → E0317 at two sites (`prove` L168, `verify` L241).

**Fix (subagent ses_170050ac0ffe, resumed):** Comprehensive conversion of ALL remaining `if let Self::X{..}`
patterns to irrefutable `let Self::X{..}` throughout compressor_glue.rs, with separate `#[cfg(...)]` gates
on destructure and block. Removed fragile early-return pattern (e.g., `return Ok(...)` inside if-let →
`Ok(...)` as expression tail). Added cfg-gated fallback `Err(anyhow!(...))` blocks. Files modified: 1.

**Verification (orchestrator-run, 2026-06-04):**
- `cargo check -p pvthfhe-cli --features "nova-compressor,demo-seeded-rng,pipeline-extra-checks,enable-lazer,enable-latticefold"` → EXIT 0 (2 warnings: irrefutable-if-let in set_decrypt_nizk_hash/set_dkg_transcript_hash LatticeFold arms — benign, return ())
- `cargo clippy --workspace -- -D warnings` → EXIT 0 (no regression)
- Diff reviewed: ALL body logic preserved verbatim; only control-flow wrapper changed (if-let+early-return → irrefutable-let+expression-tail). backend_id function restructured for cfg-correctness. external_verify_compressed_proof else-branch removed (dead code under cfg).

**Verdict: ACCEPT.** demo-e2e build now unblocked. Proceed to demo-e2e attempt.

## [2026-06-04] T7 COMPLETE — Session wrap (Atlas)

### Final blocker resolved
- **E0317 latticefold regression** in `compressor_glue.rs` L168/L241: `if let Self::LatticeFold{..}` → irrefutable `let Self::LatticeFold{..}`. Subagent (ses_170050ac0ffe) did comprehensive cleanup of ALL if-let→let patterns in the file. Verified: `cargo check --features enable-latticefold` exit 0, `cargo clippy --workspace -- -D warnings` exit 0.

### Gates verified
- **phase1-gate**: PASS, 16/16, exit 0 (orchestrator-run)
- **phase2-gate**: PASS, 10/10, exit 0 (orchestrator-run)
- **phase3-gate**: 9/12 steps GREEN locally, 3 CI-deferred per plan T7 (demo-e2e/adversarial-suite/bench-scaling). Latticefold build fix verified.

### Evidence
- New evidence file: `.sisyphus/evidence/r43-gate-evidence.md` (supersedes phase7-gate-evidence.md)
- Covers: all 3 gates, caveats (gas-check pre-existing artifact, nova-compressor e2e not in default path, A1/P2 surrogate caveats, P1-ignored NIZK tests), OPEN problems status.

### Plan status
- All 13 checkboxes marked `[x]`: T1-T7, 5 DoD criteria
- No `legacy-fold` poison-pill dependencies remain
- OPEN problems P4/C7/C5/A1/P1/P2 untouched, fail-closed

### Uncommitted work
- All work this session is uncommitted vs HEAD 63ef409. ~90 files modified (cumulative across T1-F67-clippy-T7).
- User may want to commit with a message summarizing the gate reconciliation.

## [2026-06-04] Meta-plan update — full OPEN problem coverage (Atlas)

**Context:** The `meta-plan-all-deferred.md` (the project's single source of truth for all remaining work) had incomplete coverage of the OPEN research problems. Specifically:
- Phase F P4 entry was WRONG ("Hermine PVSS upgrade" instead of the canonical "On-chain IVC decider verification")
- C5 (aggregate pk formation proof) and A1 (Cyclo accumulator transcript verification) were completely absent
- C7 entry was about scaling, not the core correctness problem
- No cross-references to the dedicated sub-plans (p1-sigma-repetition.md, p2-lattice-folding.md, p4-onchain-ivc.md)

**Edits made to meta-plan-all-deferred.md:**
1. Fixed Phase F P4: "Hermine PVSS upgrade" → "On-chain IVC decider verification" with pointer to p4-onchain-ivc.md (426 lines, 36 unchecked)
2. Expanded P1 entry: added canonical sources, dedicated plan pointer (p1-sigma-repetition.md, 30+ unchecked), noted SECURITY.md P1 inconsistency
3. Expanded P2 entry: added canonical source, dedicated plan pointer (p2-lattice-folding.md, 36 unchecked), noted Compressor enum restructuring impacts code surface
4. Added new Phase H: C7 correctness (not scaling), C5 formation proof, A1 accumulator transcript — all three with canonical sources, coverage gap analysis, missing artifacts, and actionable "create plan" next steps
5. Updated estimated effort table to include Phase H (4-6 weeks implementation, plan creation first)

**Momus review:** APPROVED (ses_16fa298d5ffe). Three non-blocking observations:
- (1) Phase A body text is stale vs Acceptance Criteria checkboxes (AC reflects ground truth)
- (2) Minor line number offsets in AC (substance correct, grep-findable)
- (3) P3 status mild inconsistency (meta-plan "OPEN" vs README "✅ Resolved" — meta-plan is more precise)

**Now the meta-plan is a genuine single source of truth** for ALL remaining project work: Phases A-G (operational debt) + Phase H (uncovered research) + Phase F (deferred research with plan pointers). Every OPEN problem from docs/OPEN-PROBLEM-BLOCKERS.md and SECURITY.md now has a traceable entry.
