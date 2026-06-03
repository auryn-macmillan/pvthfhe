# Decisions — remediate-soundness-completeness-audit

## [2026-06-03] Phase 0 fail-closed mechanism (Atlas, orchestrator decision)

Momus non-blocking suggestion was to clarify the Phase 0 fail-closed mechanism. Decision:

### Mechanism: configured-decider gate, default address(0) = fail-closed
1. Add immutable/storage `address public ivcDeciderVerifier;` to `PvtFheVerifier`, default `address(0)`.
2. Add a timelock-guarded setter `setIvcDeciderVerifier(address)` (guard: `msg.sender == timelock`),
   mirroring the existing `addAttestor`/`removeAttestor` pattern. This AVOIDS changing the constructor
   signature (no ripple to existing `new PvtFheVerifier(registry, timelock)` call sites / deploy scripts).
3. In `verifyWithIvc` and `verifyAndConsumeWithIvc`: if `ivcDeciderVerifier == address(0)`,
   `revert("PVTHFHE: IVC decider not configured")` BEFORE any HonkVerifier call.
   => In Phase 0 (no decider deployed) ALL IVC-mode calls fail closed.
4. STOP trusting `ivcBinding.ivcVerifyResult == 1` as a verification signal. Keep the struct field for
   ABI stability but do NOT let it gate acceptance. The real decider call lands in Phase 2.
5. Non-IVC `verify()` / `verifyAndConsume()` are OUT OF SCOPE for Phase 0 (F1 is IVC-only). Leave them.
   (This means stage0-gate Check 5 will still fail; that is an older, stricter plan — not our gate.)

### Why a setter, not a constructor param
- Constructor change ripples to every `new PvtFheVerifier(...)` test/script site -> large blast radius,
  higher risk of breaking unrelated tests. A timelock-gated setter is minimal and matches existing style.

### RED test for F1 (Solidity, write BEFORE the change)
- `testIvcRequiresDecider`: with `ivcDeciderVerifier == address(0)`, a call to `verifyWithIvc` /
  `verifyAndConsumeWithIvc` carrying an otherwise-well-formed `IvcBinding{ ivcVerifyResult: 1, ...all nonzero }`
  MUST revert with "IVC decider not configured" (currently it would proceed -> RED before, GREEN after).
- `testRejectsForgedIvcBinding`: forged binding with `ivcVerifyResult = 1` must NOT yield acceptance.

## [2026-06-03] Honest scoping of later phases (Atlas)
Phases 2 (real on-chain IVC decider), 3 (production C7), 4 (C5 pk-aggregation) correspond to the
project's DOCUMENTED OPEN research problems (P1/P2 OPEN per README; C5/C7 unimplemented). They are NOT
trivially completable by delegation. Per plan guardrail #4: if a real decider/relation does not exist,
leave production DISABLED (fail-closed) and DOCUMENT the blocker rather than ship a shortcut.
Phase 0 (fail-closed + docs honesty) is the genuinely shippable, high-value freeze. Surface blockers
honestly at Phases 2-4 instead of fabricating crypto.

## [2026-06-03] Phase 1 canonical statement hash — DESIGN LOCKED (Oracle ses_1722c8c8bffeMn2HFn4ccdM4Wr)

### DECISION: VerificationStatementV1 hash = Poseidon BN254, NO mod-P reduction
- Canonical hash primitive: **Poseidon over BN254 scalar field**, matching `noir-lang/poseidon v0.3.0` bn254 sponge EXACTLY (same params/padding/rate/capacity/ordering). Output is Fr < P → directly usable as an UltraHonk public input.
- REJECTED: `keccak256(...) mod P` (expensive in-circuit; non-injective reduction). REJECTED: hybrid keccak-id + Poseidon-binding (two authorities, no real equivalence).
- **Over-P field rule (soundness-critical): split every 32-byte value into `(hi128, lo128)` from BIG-ENDIAN bytes: `hi = int_be(x[0..16])`, `lo = int_be(x[16..32])`. Both < 2^128 < P → injective. NEVER reduce a 256-bit root mod P (x and x+P would collide).**

### Canonical Poseidon preimage = 76 field elements, in this exact order:
`[DOMAIN_FIELD, 1 (schema ver), 19 (field count),` then per field `(field_id, byte_len, value...)`:
1:protocol_version(u32), 2:context_id(32→hi,lo), 3:dkg_root(32), 4:epoch(u64), 5:participant_set_hash(32), 6:aggregate_pk_hash(32), 7:ciphertext_hash(32), 8:plaintext_hash(32), 9:d_commitment(32), 10:c5_proof_root(32), 11:c6_proof_set_root(32), 12:cyclo_accumulator_root(32), 13:ivc_vk_hash(32), 14:ivc_pp_hash(32), 15:ivc_proof_hash(32), 16:z0_commitment(32), 17:zi_commitment(32), 18:ivc_steps(u64), 19:bootstrap_result_hash(32)`]`
- DOMAIN_BYTES = `"pvthfhe-verification-stmt-v1"` → DOMAIN_FIELD = int_be(ascii) = `0x707674686668652d766572696669636174696f6e2d73746d742d7631`.
- 32-byte fields contribute 2 limbs each; u32/u64 fields contribute 1 element (the numeric value). Tags (field_id, byte_len) are themselves field elements.

### Canonical TLV byte encoding (for fixtures/storage/Rust+Solidity parsers):
`u32_be(len(DOMAIN_BYTES)) || DOMAIN_BYTES || u32_be(schema_version=1) || u32_be(field_count=19) ||` then per field `u16_be(field_id) || u32_be(field_len) || value_bytes`.
Widths: protocol_version=u32_be, epoch=u64_be, ivc_steps=u64_be, all roots/hashes/commitments=exactly 32 bytes.
Parsers MUST reject: wrong field count, wrong id, wrong order, wrong length, duplicate fields, trailing bytes.

### Range checks (Noir + verifiers): hi128 < 2^128, lo128 < 2^128; numeric fields within declared width.

### Soundness traps to AVOID: (1) never mod-P reduce 256-bit fields; (2) do NOT use Solidity abi.encode as canonical bytes (word padding/dynamic encoding ≠ protocol format); (3) do NOT use a random Poseidon impl — must match Noir bn254 exactly.

### Test-vector strategy: ONE Rust-generated golden vector { canonical_bytes_hex, poseidon_preimage_decimal[76], poseidon_preimage_hex[76], statement_hash_decimal, statement_hash_hex }. Require Rust + Solidity `computeStatementHash` + Noir all reproduce it. Negative vectors: swapped fields, omitted fields, swapped hi/lo, little-endian split, mod-P reduction → all must fail/differ.

### OPEN FEASIBILITY RISK (Atlas): the entire design hinges on a Rust (and Solidity) Poseidon impl that BIT-MATCHES noir-lang/poseidon v0.3.0 bn254 sponge. Must confirm such a Rust impl already exists/usable in-repo (Nova circuits use Poseidon) BEFORE committing to full 3-language impl. Probing now. If no parity-proven Rust Poseidon exists, the anchor/ground-truth must be Noir (compute hash in a nargo test, dump, match in Rust).

## [2026-06-03] Phase 1 Poseidon-parity feasibility VERDICT (Atlas, probe ses_1722809f6ffexDpcglDbgM38DA)
- **Noir ground truth**: `noir-lang/poseidon` pinned `tag = "v0.3.0"` in `circuits/aggregator_final/Nargo.toml`. BN254 config = `x5_5_config`: t=5, rate=4, capacity=1, full_rounds=8, partial_rounds=60, alpha=5. ARK/MDS constants are the iden3/circomlib BN254 set.
- **Rust**: `light-poseidon 0.4.0` (in Cargo.lock) is ALREADY USED via `Poseidon::<Fr>::new_circom(...)` in `crates/pvthfhe-nizk/src/sigma.rs`. light-poseidon `new_circom` targets circomlib constants → STRONG likelihood of parity with noir v0.3.0. **USE THIS PATH.**
- **LANDMINE — do NOT use**: `crates/pvthfhe-compressor/src/nova/poseidon_gadget.rs::PoseidonParams::canonical()` ZEROES the ARK round constants in non-`legacy-nova` builds → produces WRONG permutation. Avoid entirely for statement hashing.
- **Solidity**: NO Poseidon library exists in `contracts/`. This is the genuinely new build. HonkVerifier.sol is not reusable as a Poseidon API.
- **VERDICT**: Rust↔Noir parity = HIGH feasibility via light-poseidon, BUT must be PROVEN EMPIRICALLY (compute the 76-element preimage hash in a nargo test, dump decimal, assert Rust light-poseidon produces identical value). Key unknown to resolve in-impl: does light-poseidon variable-length `hash()` match noir `sponge()` padding, OR must we use fixed-arity to guarantee match? Resolution: pin a FIXED 76-element arity and compare; if `sponge` padding differs, use noir `sponge` ground-truth and replicate its exact padding in Rust.
- **DECOMPOSITION**: Phase 1 split into (1a) Rust+Noir parity anchor [coupled, deep, do FIRST — produces golden vector] → (1b) Solidity computeStatementHash + Poseidon port [follow-up, depends on golden vector].


## [2026-06-03] Phase 1a padding/parity resolution (Sisyphus Junior)
- Attempting the obvious Rust precedent `Poseidon::<Fr>::new_circom(76).hash(&preimage)` failed: `light-poseidon 0.4.0` rejects arity 76 (`Invalid width: 77. Choose a width between 2 and 16 for 1 to 15 inputs.`). Therefore light-poseidon variable/fixed arity hashing is NOT usable directly for the 76-element statement preimage.
- Noir `poseidon::poseidon::bn254::sponge` is ground truth for Phase 1a. Rust now replicates Noir v0.3.0 BN254 sponge exactly for this anchor: `x5_5` parameters from `light-poseidon::parameters::bn254_x5` (t=5, rate=4, capacity=1, full=8, partial=60), initial zero state, absorb into positions `[1..4]`, permute after each full rate block and after a partial final block, output `state[1]`.
- For the 76-element preimage, 76 is divisible by rate 4, so the sponge performs exactly 19 permutations and no extra final partial permutation. Noir parity test confirms the Rust replica matches bit-for-bit for the golden vector.


## [2026-06-03] Phase 1b Solidity Poseidon constants source (Sisyphus Junior)
- Ported the Solidity ARK/MDS constants from `light-poseidon 0.4.0` `bn254_x5::get_poseidon_parameters(5)`, the exact Rust parameter source used in Phase 1a. This is the same circomlib/iden3 BN254 x5 family cross-checked against `/tmp/noir_poseidon/src/poseidon/bn254/consts.nr` `x5_5_config` round constants.
- Chose a byte-table constant representation (`bytes` containing 32-byte big-endian field elements) instead of hundreds of Solidity functions/constants. This keeps contract bytecode/source manageable while preserving exact bit values; `_fieldAt` loads each 32-byte field element and all arithmetic uses `addmod`/`mulmod` under BN254 Fr.
- Kept Phase 1b standalone: no wiring into `PvtFheVerifier` yet. On-chain binding to verifier public inputs remains Phase 2/3 scope.

## [2026-06-03] Phases 2/3/4 honest-completion scope — LOCKED by Oracle (ses_17209e297ffePi2sS1X1165Y4U)

**Framing:** Phases 2/3/4 are BLOCKED-OPEN security phases, NOT crypto-completion phases. They map to OPEN problems P4/C7/C5. Honest deliverable = fail-closed production behavior + narrow integration scaffolding + tests proving shortcuts DON'T pass + a structured blocker document. Do NOT count mock verifiers, hash-only circuits, Merkle roots without a relation, local recomputation, or caller success bits as completion — those are fabrication traps Momus will reject.

**LOCKED ORDERING (turn into delegated tasks in this order):**
1. **Phase 2 fail-closed interface + tests** (SAFE engineering, build now):
   - Define `IIvcDeciderVerifier.verify(bytes proof, bytes32 statementHash, bytes32 vkHash, bytes32 ppHash, bytes32 z0, bytes32 zi, uint64 steps) returns (bool)`.
   - Wire `PvtFheVerifier.verifyWithIvc`/`verifyAndConsumeWithIvc`: (a) revert FIRST when `ivcDeciderVerifier == address(0)` (already in place from Phase 0); (b) reject empty proof bytes; (c) compute/validate canonical `VerificationStatementV1` hash ON-CHAIN from the binding fields; (d) call configured decider; (e) accept ONLY if decider returns true.
   - Keep `ivcVerifyResult` as deprecated/ignored ABI baggage; remove ALL reads; never expose as trusted public input. Do NOT churn ABI now.
   - Tests REQUIRED (honest): unconfigured reverts before reading ivcVerifyResult; `ivcVerifyResult==1` + unconfigured still reverts; configured mock returning FALSE rejects; empty proof rejects; wrong vk/pp/z0/zi/steps rejects (param-checking mock); caller result ignored; mock receives EXACT statement hash+fields.
   - Mock returning TRUE allowed ONLY to test call plumbing/success control flow — name it `MockIvcDeciderVerifierForPlumbing`, and DO NOT list it as a soundness/Phase-2-completion test.
   - FABRICATION TRAP: treating a mock or a Noir hash-binding circuit as IVC soundness; letting ivcVerifyResult influence acceptance.
2. **Blocker document** (P4/C7/C5/C6) — 10-point standard per entry: (1) stable ID; (2) status `OPEN - production disabled`; (3) one-sentence security claim withheld; (4) affected code paths (contracts/circuits/crates); (5) current fail-closed behavior = exact revert/reject condition + test names; (6) missing artifact (audited on-chain Nova/LatticeFold verifier / full C7 Noir relation / public C5 aggregation proof); (7) forbidden shortcuts; (8) future acceptance criteria (required positive-proof test + tamper-failure tests); (9) deployment rule (keep disabled until acceptance passes); (10) verification commands (forge/nargo/cargo/just).
3. **Statement-hash public-input wiring as a SEPARATE "binding invariant" task** — bind canonical `VerificationStatementV1` hash into Noir/Solidity public-input path; test that changing the statement hash rejects; DOCUMENT it proves only statement binding, NOT threshold-decryption/IVC/PK-aggregation correctness.
4. **Phase 4-C6 committed-smudge enforcement** (REAL honest work): reject `LegacyLocalSmudge` in production (Phase 0d partially did source-level); require `CommittedSmudge` + DKG-committed `sk_agg_share`+`esm_agg_share` commitments; bind smudge slot id, decrypt round, ciphertext hash, context/session id, participant identity into C6 statement/root; ensure `SessionRegistry` consumption keys include those bindings (no replay across ciphertext/round/session).
5. **Leave real P4/C7/C5 completion BLOCKED** — research-scale, not honestly completable from current repo state.

**Phase 3 (C7) fail-closed MUST mean:** no production verifier path treats current hash-only `aggregator_final` as sufficient decryption correctness; if a C7 proof is required for production and the full relation is absent, verification reverts/returns false; docs+tests mark local/dev proof generation as non-production.
**Phase 4-C5 fail-closed MUST mean:** missing/zero/malformed/unverifiable C5 proof/root prevents production acceptance; `c5_proof_root` may be CARRIED+bound as a field but NOT treated as proof that pk_agg = Σ contributions.
**Confidence:** High. Follows directly from guardrails + absence of real on-chain IVC decider, full C7 relation, and public C5 aggregation proof.

## [2026-06-03] Binding-invariant task scope LOCKED by Oracle (ses_171f53870ffeVncc9ZPxESQpW0)

**RULING: seam-level statement-binding invariant ONLY. Do NOT change aggregator_final main(), do NOT regenerate VK/HonkVerifier.sol.** Rationale: honestly binding the statement hash inside main() needs all 19 fields sourced + public-arity change + VK/Honk regen + reconciling the KNOWN surrogate (verify() builds 7 inputs while HonkVerifier.sol declares 15). That is out of scope and high-risk; deployed Noir/Honk faithful public-input binding stays OPEN.

**Deliverable (short, ~1-4h):**
1. Freeze deployed interfaces: NO edits to aggregator_final main(), NO VK regen, NO edits to generated/HonkVerifier.sol.
2. Noir (tests/helpers only in circuits/aggregator_final/src/main.nr): add `test_verification_statement_v1_each_field_mutation_changes_hash` (every canonical field change flips the hash) and `#[test(should_fail)] test_verification_statement_v1_hash_mismatch_rejects_mutated_statement`.
3. Solidity: keep _computeIvcStatementHash behavior UNCHANGED (Phase 2 already computes+passes canonical hash). NO runtime "consistency assertion" (recomputing same hash twice = tautological).
4. Add Solidity tests: `testVerificationStatementEachFieldMutationChangesHash` (in VerificationStatementVector.t.sol) and `testStatementHashMismatchAloneRejected` (in IvcDeciderWiring.t.sol — only expectedStatementHash wrong while vk/pp/z0/zi/steps correct => verifyWithIvc returns false; existing testWrongIvcParamsRejected conflates hash with the separately-passed params).
5. Optional comment-only correction in PvtFheVerifier.sol if wording implies full field sourcing completes here.
6. Update docs/OPEN-PROBLEM-BLOCKERS.md: clarify full deployed Noir/Honk public-input binding remains OPEN/out-of-scope.

**FABRICATION TRAPS to forbid:** (a) claiming main() binds the statement hash without actually changing its signature+constraints AND regenerating VK/Honk; (b) treating zero placeholders (contextId/c5/c6/cyclo roots) as sourced bindings; (c) counting mock-decider success / hash-only Noir tests / Poseidon parity as IVC/decryption/PK-agg verification.

**Verify:** `forge test --root contracts --match-contract VerificationStatementVectorTest`; `forge test --root contracts --match-contract IvcDeciderWiringTest`; `(cd circuits && nargo test --package aggregator_final)`.

## [2026-06-03] Phase 4-C6 scope LOCKED by Oracle (ses_171de5dbbffe02fzobMOmj7Woe)

**Context:** committed-smudge infra largely PRE-EXISTS (see issues.md). Oracle ruled on 3 residual gaps.

**RULINGS:**
- **GAP A = REAL SOUNDNESS BUG, the C6 deliverable.** `prove_decrypted_share` (encrypt.rs:86) hardcodes `slot_id=1`, `decrypt_round=0` (lines 119-134), making the existing per-slot/per-round committed-smudge binding unreachable for real caller-selected slots/rounds. Must thread caller-supplied values through.
- **GAP B = OUT-OF-SCOPE/ACCEPTABLE.** `_smudgeSlots` omitting epoch is STRICTER, not weaker (one-time per (dkgRoot,runId,partyId,slot)). Adding epoch would WEAKEN the one-time-smudge invariant. DO NOT change SessionRegistry for B. Document only.
- **GAP C = NOT C6; belongs to P4/IVC replay.** `_ivcProofConsumed` (PvtFheVerifier.sol:188) not runId-scoped + `_computeIvcStatementHash` doesn't bind runId. Record as separate IVC follow-up, do NOT fold into C6.

**MINIMAL C6 ACTION PLAN (RED test first per AGENTS.md):**
1. RED Rust test against PRODUCTION ADAPTER path: call `LatticePvssBfvAdapter::prove_decrypted_share` with non-default slot_id (e.g. 7) and decrypt_round (e.g. 42), decode returned `DecryptNizkProof`, assert those exact values appear in `opened.statement.mode`. Must FAIL on current hardcoded 1/0.
2. Replace hardcoded fields in encrypt.rs:119-134: BOTH `compute_esm_aggregate_commitment` (slot arg, currently `1`) AND `DecryptNizkMode::CommittedSmudge { slot_id, decrypt_round }` must use caller-supplied values. No `unwrap_or(1)`/`unwrap_or(0)` in committed mode.
3. Explicit production API: add struct e.g. `CommittedSmudgeUse { slot_id: u16, decrypt_round: u64 }`; require `slot_id != 0`.
4. Update callers: `pvss_support.rs:110` and `encrypt_decrypt_roundtrip.rs:91` (legacy/None path stays). C6/demo path must NOT silently fall back to LegacyLocalSmudge when committed material expected.
5. Keep LegacyLocalSmudge variant + its negative/legacy tests intact. Do NOT delete enum variant.
6. DO NOT change SessionRegistry for Gap B.
7. Record Gap C separately as IVC follow-up (problems.md).

**FABRICATION TRAPS (Momus/orchestrator will check):** (a) adding slot_id param but defaulting committed mode back to 1, or decrypt_round back to 0; (b) updating DecryptNizkMode tests only while prove_decrypted_share still emits hardcoded values; (c) using caller slot_id in statement but still computing esm_agg_commit with slot 1; (d) cosmetic threading without an adversarial RED test that FAILS on old 1/0 behavior; (e) widening SessionRegistry key for B (weakens invariant); (f) claiming IVC/mock-decider tests prove C6.

**Cross-language risk:** Do NOT change `compute_esm_aggregate_commitment` domain separator/encoding (dkg_aggregation.rs:192), do NOT bump PROOF_VERSION/WIRE_VERSION unless serialization changes. Existing 5 committed_smudge tests must keep passing.

**Types confirmed:** `CommittedSmudge.slot_id: u16`, `decrypt_round: u64`; `compute_esm_aggregate_commitment` slot_index param is `u16`. `prove_decrypted_share` signature (encrypt.rs:86-96) currently: (ciphertext_u, party_pk, party_index, decrypted_share_bytes, witness, ctx, committed_esm_noise_bytes: Option<Vec<u8>>, sk_agg_share: Option<u64>).

**Verify:** `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-pvss --test nizk_decrypt_committed_smudge`; `... --test encrypt_decrypt_roundtrip`; `cargo check -p pvthfhe-cli`; `forge test --root contracts --match-contract SessionRegistryTest` (regression, must stay green).

## [2026-06-03] Phase 5 (A1 Cyclo accumulator / F4) scope LOCKED by Oracle (ses_171ccb61bffenxxAipSHpLYKCl)

**RULING = option (a): fail-closed is ALREADY correct at the NIZK seam; honest deliverable = blocker-doc + docs/comment/naming + light test hardening. NO protocol implementation.** Building a "versioned transcript parser / FS-challenge / final-commitment / norm-bound checker" WITHOUT the real Cyclo fold relation = security theater / fabrication. A1 stays BLOCKED-OPEN like P4/C7/C5.

**Current state (already done, DO NOT regress):** `adapter.rs::verify` rejects any nonzero `acc_len` with `VerificationFailed("cyclo accumulator present but unverified (fail-closed)")` (lines 184-190); encoder always writes `acc_len=0` placeholder (596-597). Tests `accumulator_fail_closed.rs`: `accumulator_nonzero_transcript_bytes_fail_closed`, `accumulator_empty_placeholder_honest_proof_still_verifies`.

**Action mapping:** Action 1 (replace `cur.skip`) = ALREADY honestly complete. Action 2 (verify fold equations/FS/commitment/norm/instance-count) = RESEARCH-BLOCKED (needs real Cyclo relation). Action 3 (reject zero-len in production folded mode) = principle already satisfied for nonzero; any FUTURE folded-production entrypoint must reject BOTH zero-len and nonzero-unverified. Action 4 (named non-folded test mode) = do NOT build a fake unit-test verifier; just DOCUMENT the accepted `acc_len=0` path as an explicit non-folded A1 placeholder.

**ZERO-LENGTH RULING (important):** Do NOT globally change `CycloNizkAdapter::verify` to reject `acc_len=0` — that would disable ALL current P1 proofs. Instead make the accepted zero-length path explicitly named/documented "non-folded placeholder; A1 not verified." Production/deployment stays blocked by A1.

**MINIMAL DELIVERABLE (sub-tasks):**
1. Keep fail-closed logic unchanged (nonzero acc_len => same reject string).
2. Add `A1` to `docs/OPEN-PROBLEM-BLOCKERS.md` at the SAME 10-point standard as P4/C7/C5/C6 (mirror the existing C6 entry format). 10 points: ID=A1; status `OPEN — production disabled`; claim withheld = Cyclo accumulator transcript verification not implemented; affected paths = `crates/pvthfhe-nizk/src/adapter.rs` + Cyclo fold modules + downstream folded paths; current fail-closed behavior + test names; missing artifact = real versioned transcript + verifier wired to Cyclo fold relation & NIZK statement; forbidden shortcuts = hash-only binding / fake Merkle roots / parser-only validation / dummy instances / treating `verify_fold` unit tests as adapter integration; acceptance criteria = honest accumulator passes, random/wrong-stmt-hash/wrong-challenge/wrong-final-commitment/norm-violation/wrong-instance-count reject; deployment rule = no production mode may treat `acc_len=0` as folded verification; verification commands (below).
3. Fix stale wording in `SECURITY.md` + `WARNING.md`: stop saying accumulator bytes are "skipped"; say nonzero accumulator bytes are REJECTED fail-closed, and the empty placeholder is NOT fold verification.
4. Tighten comments/naming in `adapter.rs` around `cyclo_accumulator_bytes` (header doc lines 23/33-34) and the encoder `0u32` write (596-597): explicitly "non-folded A1 placeholder", not "Phase 2 placeholder"/"honest accumulator".
5. Add 1-2 hardening tests in `accumulator_fail_closed.rs`: especially a nonzero `acc_len` declared with NO appended transcript bytes (truncated) — prove the verifier fails (truncation OR fail-closed) BEFORE any parse/skip semantics.
6. Do NOT implement transcript parser / stmt-hash / challenge / root / norm-bound checker.
7. Keep `crates/pvthfhe-cyclo` fold tests separate — NOT A1 integration evidence.

**FABRICATION TRAPS:** versioned-transcript parser that validates framing/domain/hash but not fold equations; recomputed SHA/Merkle/final-commitment presented as fold verification; stmt-hash/FS-challenge binding without the folded witness relation; calling `pvthfhe-cyclo::fold::verify_fold` on dummy/verifier-supplied instances not bound to the NIZK proof; norm-bound over claimed metadata not actual folded witness; treating `fold_verify_accepts_honest` as adapter integration; describing `acc_len=0` as an "honest accumulator".

**Verify:** `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-nizk accumulator -- --nocapture`; `PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo test -p pvthfhe-cyclo fold_verify -- --nocapture`; `rg "A1|cyclo accumulator|non-folded|fail-closed" docs/OPEN-PROBLEM-BLOCKERS.md SECURITY.md WARNING.md crates/pvthfhe-nizk/src/adapter.rs`. Effort: Quick-Short (docs/comments/tests, no protocol). Confidence: High.

## [2026-06-03] Phase 6 (Legacy & Mock Quarantine) scope LOCKED by Oracle (ses_171ba102bffeMueGuShz7lXBKp)

**GOAL:** Introduce a `production-profile` feature that builds a workspace graph PROVABLY free of every legacy/mock/surrogate/stub feature, and assert it with layered checks. This is a QUARANTINE profile — NOT a claim of cryptographic production-readiness. A1/P4/C7/C5 stay BLOCKED-OPEN.

**1. production-profile placement (per-crate, NOT root/meta = theater):**
- `pvthfhe-fhe`: `production-profile=["real-nizk"]`
- `pvthfhe-aggregator`: `=["real-folding","real-verifier","real-pvss","real-nizk","pvthfhe-fhe/production-profile"]`
- `pvthfhe-compressor`: `=["transparent-decider","pvthfhe-aggregator/production-profile"]`
- `pvthfhe-cli`: `=["with-fhe","nova-compressor","pipeline-extra-checks", + transitive production-profile of deps]`
- `pvthfhe-keygen` / `pvthfhe-pvss` / `pvthfhe-enclave-adapter`: propagate → `pvthfhe-fhe/production-profile`
- `pvthfhe-offchain-verifier`: → `pvthfhe-compressor/production-profile` (NOT legacy-nova)
- `pvthfhe-bench`: only enough to compile WITHOUT mock/surrogate
- NEVER include: mock, surrogate-compressor, surrogate-decrypt-share, trace-decrypt, demo-seeded-rng, legacy-nova, stub, production-stub-allowed.

**2. Layered assertion (use ALL, ranked strongest first):**
1. Compile-time mutual-exclusion: `#[cfg(all(feature="production-profile", feature="<forbidden>"))] compile_error!(...)` guards in each owning crate's lib.rs.
2. Exact build: `cargo test --workspace --no-default-features --features production-profile` compiles & passes.
3. Resolved feature-tree audit: `cargo tree -e features --features production-profile` that FAILS (CI grep -v) if any forbidden feature name appears in the graph.
4. Manifest default-feature policy test (mirror `crates/pvthfhe-pvss/tests/gate_noop_absent_by_default.rs`).

**3. Mutual-exclusion guard pairs:** pvthfhe-fhe×{mock,surrogate-decrypt-share,trace-decrypt}; pvthfhe-cli×{mock,surrogate-compressor,demo-seeded-rng}; pvthfhe-aggregator×mock; pvthfhe-compressor×legacy-nova; pvthfhe-offchain-verifier×legacy-nova; pvthfhe-pvss×production-stub-allowed; pvthfhe-enclave-adapter×stub; (pvthfhe-keygen×hermine already compile_error — redundant, leave).

**4. enc_randomness:** diagnose+fix the BackendError on 2nd deal() (bounded). Do NOT weaken the ciphertext-difference assertion. `#[ignore]` with narrow documentation ONLY as last resort if proven a mock-only state bug.

**5. placeholder/attestation mapping (quarantine targets):** mock/surrogate proof paths, legacy-nova, production-stub-allowed, enclave-adapter stub (`verify_proof` Ok(false)), offchain attestation.rs placeholder signer/sig. A1 accumulator placeholder is OPEN RESEARCH — NOT a Phase 6 target; do NOT claim Phase 6 makes the repo production-secure.

**6. Deployment:** Foundry regression asserting default `ivcDeciderVerifier==address(0)` + both IVC paths revert. Existing IvcFailClosed.t.sol / IvcDeciderWiring.t.sol already cover it — add a lock, do NOT rewrite the already-fail-closed deploy.

**7. FABRICATION TRAPS (Momus/orchestrator will check):** production-profile=[] on root/meta only; building WITHOUT `--no-default-features`; tree check that prints but never FAILS on forbidden features; checking only `[features].default` while ignoring transitive; leaving hard `features=["mock"]` deps while claiming clean; guarding only alias crate (pvthfhe-cli) not owner (pvthfhe-fhe); renaming features to hide mock; ignoring/weakening enc_randomness without diagnosis; claiming "placeholder proof solved" while A1 OPEN; rewriting already-fail-closed deploy.

**8. ORDERING (Oracle-locked, RED-test-first per AGENTS.md):**
1. RED policy tests (manifest default-feature test + build target that currently FAILS because production-profile absent).
2. production-profile features per-crate + mutual-exclusion compile_error! guards.
3. Refactor hard mock deps (esp. pvthfhe-bench non-dev `features=["real-nizk","mock"]`) so `--no-default-features --features production-profile` workspace build passes.
4. CI command + resolved feature-tree audit (`cargo tree -e features`).
5. Foundry fail-closed deploy regression.
6. Diagnose enc_randomness BackendError.
7. Docs: describe as "legacy/mock quarantine profile", NOT "cryptographically production-ready".

**Effort:** Medium (1-2 days). **Confidence:** High (except enc_randomness diagnosis = Medium).

**Verify:** `CI=true GIT_PAGER=cat PAGER=cat PVTHFHE_ALLOW_RESEARCH_BUILD=1 RUSTFLAGS="-Awarnings" cargo test --workspace --no-default-features --features production-profile`; `cargo tree -e features --features production-profile` (forbidden feature names ABSENT from graph); `forge test --root contracts --match-contract IvcFailClosed`; `cargo test -p pvthfhe-pvss --test enc_randomness`.

## [2026-06-03] Phase 7 (End-To-End Gates + Forged-Proof Harness) scope LOCKED by Oracle (ses_1712acdeaffekVY6Voz0wUFHnl)

**BOTTOM LINE = option (b) + EVIDENCE semantics.** Phase 7 is honest, NOT a forced-green crypto claim. Phases 0-6 already fail-close every OPEN problem (P4/C7/C5/A1 BLOCKED-OPEN). Phase 7 proves "system does NOT ACCEPT forged proofs" at the level the implementation actually supports, and records the rest as OPEN.

**GATES (action 1):**
- `phase1-gate` = locally runnable (file/substring checks + `cargo test -p pvthfhe-nizk --release` + `-p pvthfhe-fhe --features real-nizk` + clippy). NOTE it requires `crates/pvthfhe-nizk/tests/nizk_adversarial.rs` to EXIST + SECURITY.md "P1 (CRITICAL)" + theorem-inventory "Cyclo T3" + BACKEND_ID string — these are BROADER-plan artifacts, may already pass/fail independent of this remediation.
- `phase2-gate` = locally runnable but STOP on timeout/ENOSPC and record exact failure (~13 design-doc existence + parameters.toml + cargo check --workspace + cyclo + aggregate_1024_smoke).
- `phase3-gate` = **DO NOT run locally.** Hours-scale (`just demo-e2e`/`adversarial-suite`/`bench-scaling`), high disk/ENOSPC risk, covers broader-plan artifacts (gas/bench/evidence JSON). Record the exact CI command + reason; delegate to CI.
- ACCEPTABLE + MORE HONEST to record gate outcomes as EVIDENCE (pass/fail/timeout/ENOSPC verbatim) rather than force green phase3 that may fail on unrelated pre-existing docs/gas/bench issues. A broader-plan gate failure is NOT a remediation failure — but MUST be explained with scope, never hidden.

**FORGED-PROOF HARNESS (action 2):**
- ONE consolidated orchestrator script: `.sisyphus/scripts/phase7-forged-proof-harness.py`. Invokes the existing named tests across Rust+Foundry (cases span both langs, so a Python orchestrator beats a single Rust test file). MUST FAIL if any command runs ZERO tests (no vacuous pass).
- Honest E2E entrypoint to reuse: `crates/pvthfhe-aggregator/tests/e2e_real.rs::test_e2e_real_pipeline_p4_p1_p2_p3()` — LABEL it surrogate/research E2E (its `verify_proof` is NOT a real Honk verifier; does NOT resolve IVC/C5/C7/A1).
- The 6 cases map to existing tests: plaintext hash → e2e_real.rs:275; forged IVC → contracts/test/IvcFailClosed.t.sol testRejectsForgedIvcVerifyResult (reverts "IVC decider not configured"); tampered C5 → pvthfhe-compressor/tests/bfv_encryption_adversarial.rs tampered_pk0_rejected; C6 smudge → pvthfhe-fhe committed_smudge_requires_esm + pvthfhe-pvss nizk_decrypt_committed_smudge; legacy smudge → nizk_decrypt_committed_smudge.rs committed_smudge_rejects_local_smudge_proof; Cyclo → pvthfhe-nizk/tests/accumulator_fail_closed.rs.
- Harness emits EVIDENCE JSON: per case = command, exit status, observed test count, and REJECTION CLASS ∈ {`cryptographic_reject`, `input_validation_reject`, `fail_closed_blocked_open`}.

**ASSERTION SEMANTICS (the IVC/C5/C7/A1 honesty rule):** For OPEN paths assert **NON-ACCEPTANCE**, NOT cryptographic rejection. Valid: "reverts IVC decider not configured", "returns disabled/blocker error", "does not emit accepted proof/state". INVALID: "soundness proven" / "well-formed-but-false proof cryptographically rejected" (that capability is OPEN).

**ORDERED SUB-TASKS (RED-first per AGENTS.md):**
1. RED: add harness entrypoint with the 6 required case names; FAIL initially if any case missing/skipped/zero-tests.
2. Implement harness as orchestrator over existing tests (mapping above).
3. Emit evidence JSON (command, exit, test count, rejection class) — from real tool output, NOT hand-written.
4. lsp_diagnostics on changed files, then run targeted harness command.
5. Run `phase1-gate`; run `phase2-gate` if resources remain. Record pass/fail/timeout/ENOSPC verbatim.
6. Do NOT run `phase3-gate` locally — record exact CI command + reason.
7. Append findings to learnings.md / blockers to issues.md; never touch read-only plan.

**VERIFY:** `CI=true GIT_PAGER=cat PAGER=cat PVTHFHE_ALLOW_RESEARCH_BUILD=1 python3 .sisyphus/scripts/phase7-forged-proof-harness.py`. Internal filtered cmds (each must match >0 tests): e2e_real test_e2e_real_pipeline_p4_p1_p2_p3; `forge test --root contracts --match-path contracts/test/IvcFailClosed.t.sol --match-test testRejectsForgedIvcVerifyResult -vv`; pvthfhe-compressor bfv_encryption_adversarial tampered_pk0_rejected; pvthfhe-fhe committed_smudge_requires_esm; pvthfhe-pvss nizk_decrypt_committed_smudge committed_smudge_rejects_local_smudge_proof; pvthfhe-nizk accumulator_fail_closed. Gate evidence: `just phase1-gate`, `just phase2-gate`. CI-only: `just phase3-gate`.

**FABRICATION TRAPS (Momus/orchestrator will check — 15):** (1) claiming phase3-gate green without running in CI; (2) treating phase3 broader-plan failure as remediation failure without scope explanation; (3) doctoring/hand-writing gate JSON instead of tool output; (4) filtered cargo/forge matching ZERO tests but exit 0 = "success"; (5) assert!(true)/broad should_panic/ignored tests/not inspecting returned error/revert; (6) asserting against a mock verifier / caller-supplied native result / hash-binding circuit and calling it IVC verification; (7) calling e2e_real surrogate verify_proof a "production Honk verifier"; (8) tampering fields the verifier never reads; (9) claiming fail-closed reject proves cryptographic soundness for IVC/C5/C7/A1; (10) marking IVC/C5/C7/A1 "resolved" without real-impl acceptance tests; (11) enabling mock/test-only features and calling it production-profile evidence; (12) accepting stale bench/results/*.json or prior evidence as fresh Phase 7 results; (13) mutating the 200-byte public-input blob at wrong offset; (14) empty proof list / missing case passing vacuously; (15) hiding "RESEARCH PROTOTYPE — DO NOT DEPLOY" or weakening BLOCKED-OPEN docs.

**Effort:** Short (harness + evidence); Medium if missing case coverage needs reusable helpers. **Confidence:** High.

## [2026-06-03] Phase 7 mapping REVISION — Oracle follow-up ruling (ses_17108dbbeffeVEL9h3aZFDvRKS)

Implementation surfaced facts that invalidated one scope-lock assumption. Oracle verdict = REVISE. FINAL LOCKED 6-case mapping (corrections in **bold**):

1. **`folding_witness_tamper`** (REPLACES the dropped `plaintext_hash_tamper`) → `cargo test -p pvthfhe-aggregator --test folding_tamper real_folding_gaps::test_fold_tampered_witness_rejected -- --exact` → **`input_validation_reject`** (NOT cryptographic_reject — Oracle: tamper sets a proof byte to 0xff; `validate_witness` at `crates/pvthfhe-aggregator/src/folding/mod.rs:291` rejects on the NORM-BOUND check BEFORE any NIZK/Cyclo verification. Calling it cryptographic = fabrication trap). CONFIRMED PASS (1 passed). NOTE full module path `real_folding_gaps::` REQUIRED — cargo `--exact` filters need the module path.
2. `forged_ivc_decider` → `forge test --root contracts --match-path test/IvcFailClosed.t.sol --match-test testRejectsForgedIvcVerifyResult -vv` (path RELATIVE to --root; earlier `contracts/test/...` matched ZERO) → `fail_closed_blocked_open`.
3. `tampered_c5_pk` → `cargo test -p pvthfhe-compressor --test bfv_encryption_adversarial tampered_pk0_rejected` → `input_validation_reject`.
4. `committed_smudge_requires_esm` → `cargo test -p pvthfhe-pvss --features mock --test nizk_decrypt_committed_smudge committed_smudge_requires_explicit_esm_witness` (**`--features mock` REQUIRED** or 0 tests) → `cryptographic_reject`.
5. `legacy_smudge_fallback_rejected` → same binary `committed_smudge_rejects_local_smudge_proof` (needs `--features mock`) → `cryptographic_reject`.
6. `cyclo_accumulator_fail_closed` → `cargo test -p pvthfhe-nizk --test accumulator_fail_closed accumulator_nonzero_transcript_bytes_fail_closed` → `fail_closed_blocked_open`.

**DROPPED:** surrogate `e2e_real::test_e2e_real_pipeline_p4_p1_p2_p3` — BROKEN in its only buildable config (`required-features=["mock"]` + body needs `real-verifier`; with mock, simulator.rs:526 `decode_pk_polys` hits the unimplemented mock stub `crates/pvthfhe-fhe/src/lib.rs:215` → "decode_pk_polys not implemented"). Oracle: dropping is cleaner than fixing mock decode_pk_polys inside Phase 7; 6 non-surrogate cases acceptable (Phase 7 = forged-proof evidence harness, not an E2E coverage gate). e2e_real breakage = record in problems.md as out-of-scope remediation debt, NOT a Final-Wave blocker (unless Final Wave explicitly requires the e2e demo target to pass).

**Harness env per cmd:** `CI=true GIT_PAGER=cat PAGER=cat`; cargo cmds add `PVTHFHE_ALLOW_RESEARCH_BUILD=1 RUSTFLAGS=-Awarnings`; forge from repo root w/ `--root contracts`. MUST FAIL on observed_test_count==0.

## [2026-06-03] DECISION — phase2-gate aggregate_1024_smoke disposition (Oracle scope-lock ses_170e53d4dffe + orchestrator refinement)
- ATTRIBUTION (final, git-verified): `legacy-fold` poison-pill (`folding/mod.rs:14-17 compile_error!`) is COMMITTED in `8998157` (predates my work). My UNCOMMITTED Phase 6 added an explicit `[[test]] aggregate_1024_smoke` entry pinned to `required-features=["legacy-fold"]`. At HEAD the test was AUTO-DISCOVERED (no explicit entry) and ran under default `real-folding`; my Phase-6 explicit pin to the poisoned feature broke it. => SELF-INFLICTED, in-scope to fix.
- The smoke test (`tests/aggregate_1024_smoke.rs`) uses `HashChainCycloAdapter` (real Cyclo backend, real-folding) — it is a REAL test, never legacy. grep confirms it NEVER wrote `bench/results/aggregate_1024.json` (not at HEAD, not in working tree). That JSON is a COMMITTED stale artifact from F9 bench (`3f6e920`, 93 bytes, May 27). `phase2-gate.py:167` runs the test then checks the JSON exists — so the JSON sub-check has ALWAYS trusted the committed artifact (pre-existing broader-plan gate design).
- FIX (minimal restore-to-HEAD): remove ONLY the `required-features = ["legacy-fold"]` line from the `aggregate_1024_smoke` [[test]] target in `crates/pvthfhe-aggregator/Cargo.toml`. Verify compiles+passes under default `real-folding`. Do NOT touch the other 8 legacy-fold-pinned targets (genuine legacy quarantine; skipped in normal runs; poison only fires if feature enabled).
- ORCHESTRATOR REFINEMENT of Oracle step 3: I will NOT expand the smoke test to emit the JSON. Rationale: (a) the test never emitted it — pre-existing broader-plan gate design, not my breakage; (b) making it emit JSON alters broader-plan gate-contract semantics = scope creep; (c) phase2-gate stays RED on the irreducible `pvthfhe-api` artifact regardless, so "greening" the smoke check does not green the gate. Instead TRANSPARENTLY DOCUMENT that the JSON sub-check trusts the committed F9 artifact. Honors Oracle's PRIMARY principle (never fabricate greenness; document) better than scope-expansion.
- Issues 2 (`pvthfhe-api` phantom crate) & 3 (`setup_threshold(5,3)` vs `t≤(n-1)/2`): Oracle CONFIRMED — both committed broader-plan debt; document with scope, do NOT fabricate the crate, do NOT alter test/constraint. Leave gates honestly partially-RED.
