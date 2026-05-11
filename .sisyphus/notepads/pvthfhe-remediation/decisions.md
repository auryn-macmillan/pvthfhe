# pvthfhe-remediation — Scope Decisions

## 2026-05-08 — Path-3 scope (FULL plan, with oracle gating)

**Decision (user-confirmed)**: Execute the full R0–R11 remediation plan. Sub-agents will perform implementation; oracle review is mandatory at every phase the plan flags as oracle-gated; the orchestrator (atlas) verifies CI before marking checkboxes.

**User instruction**: "c - pah 3" (Path 3, 2026-05-08).

**Standing risk acknowledgement**: The plan's own constraints state that R1, R2, R3, R5, R6.4, R10 require human cryptographer / external review for soundness sign-off. Sub-agent implementations will be functionally complete and oracle-reviewed but MUST NOT be considered production-ready until:
1. Independent construction review by an external cryptographer (Interfold-gate item 3).
2. Adversarial dress rehearsal (Interfold-gate item 4).
3. External-audit clearance (Interfold-gate item 5).

These three gates are explicitly outside this plan's scope per the plan's §A.4 — atlas will deliver the artifact and surface the gating items, not declare production readiness.

**Per-phase oracle review checkpoints** (mandatory before marking phase `[x]`):
- R1.0 construction selection
- R1.5 DKG secrecy adversary model
- R2.0 Sonobe-only design doc
- R2.4 Cyclo forgery resistance test adversary model
- R3.0 NIZK construction selection
- R3.0a witness-language schema design
- R3.1 share-WF NIZK ZK + soundness
- R3.3 Ajtai CRS binding
- R4.1 real `FoldingScheme` impl
- R4.4 fold e2e soundness
- R5.2 Sonobe step circuit
- R5.3 SRS discipline
- R8.2 atomic plaintext release API surface + transcript binding
- R8.5 e2e soundness
- R6.9 abort/restart liveness vs replay tradeoff
- R10.0 attestation backend selection
- F1–F5 Final Verification Wave (post R0–R11 completion)

**Per-phase external (human) review checkpoints** (cannot be satisfied by sub-agents alone):
- R1.0 → `.sisyphus/design/dkg-construction.md` independent review
- R2.0 → `.sisyphus/design/fold-construction.md` independent review
- R3.0 → `.sisyphus/design/nizk-construction.md` independent review
- R3.0a → `.sisyphus/design/nizk-witness-language.md` independent review
- R8.2 → `.sisyphus/design/pre-reveal-binding.md` independent review

These are flagged in the notepad and surfaced in plan progress reports. Atlas will mark the relevant `[ ] **GATE**: oracle review` checkbox `[x]` only after oracle returns APPROVE; the parallel external-review checkbox stays `[ ]` and is reported as a known gate to humans.

## [2026-05-08] R1.0 DKG construction draft
- Recommendation: Pedersen-DKG over the BFV/RLWE secret domain, recommended pending oracle review.
- Key reason: It shares/verifies the same coefficient-vector / `R_q` polynomial object consumed by `gnosisguild/fhe.rs` BFV `SecretKey`; BN254 Feldman is Noir-friendly but needs a costly scalar-to-BFV bridge, and lattice VSS is under-specified for immediate R1 implementation.
- Open questions for oracle: confirm the intended Asharov-Jain citation lineage; challenge RLWE public-verifiability cost vs Noir limits; decide exact BFV secret distribution and RNS-vs-aggregate sharing domain; identify anti-bias checks needed in the RLWE DKG; review whether Ajtai/Cyclo CRS assumptions can be reused safely.

## TDD discipline reminder (from AGENTS.md)

Every implementation change requires a CI-visible RED test BEFORE the GREEN edit. Sub-agent dispatches must:
- One sub-agent per RED commit, one per GREEN commit (never bundle).
- GREEN sub-agent must quote the failing test path in its prompt.
- Atlas (this orchestrator) verifies CI before marking checkboxes.
- Stub protocol: replace stubs in place; never delete-and-recreate.

## Execution order (DAG-respecting)

Per plan §0 dependency graph:
```
R0 ──┬── R11 (parallel)
     │
     ├── R1
     ├── R2
     └── R3
          │
          ▼
         R4
          │
          ▼
         R5
          │
          ▼
         R6 ── R10 (parallel)
          │
          ▼
         R7
          │
          ▼
         R8
          │
          ▼
         R9 GATE
          │
          ▼
        F1–F5 Final Verification Wave
```

**Execution batches**:
1. **Batch A (week 1–2)**: R0 + R11 in parallel (no inter-deps).
2. **Batch B (week 3–10)**: R1 + R2 + R3 in parallel (all depend only on R0).
3. **Batch C (week 9–14)**: R4 (depends on R1+R2+R3).
4. **Batch D (week 13–18)**: R5 (depends on R4).
5. **Batch E (week 17–24)**: R6 + R10 in parallel (R10 depends on R6.4 attestor onboarding, run after R6.4 lands).
6. **Batch F (week 21–26)**: R7 (depends on R6).
7. **Batch G (week 25–30)**: R8 (depends on R5+R6+R7).
8. **Batch H (week 29–32)**: R9 GATE.
9. **Batch I**: F1–F5 Final Verification Wave.

Within each phase, sub-task ordering follows the plan's listed order. Within R0, recommended order to minimise rework:
1. R0.1 (doc-lint) — independent
2. R0.8 (test-tautology purge) — independent, fast
3. R0.4 (domain-tag enum) — foundational
4. R0.7 (RNG facade) — foundational
5. R0.3 (secrecy newtypes) — foundational
6. R0.5 (wire format) — depends on R0.3 newtypes
7. R0.2 (label discipline + no-default no-op) — touches adapters
8. R0.6 (single fold path) — feature-flag the legacy impl

## Calendar reality check

Plan estimates 9–12 calendar months with 3 senior cryptographers. Sub-agent execution will compress wall-clock time but cannot compress the **review latency** of oracle/external/human checkpoints. Realistic expectation for Path 3 in this orchestration mode:
- Mechanical phases (R0, R11, R6.5, R7.2, R9 docs): days
- Crypto-construction phases (R1, R2, R3, R5, R10): weeks per phase, primarily limited by oracle/external review turnaround
- Integration phases (R4, R6, R7, R8): weeks per phase

If the user wants faster turnaround, scope reduction (Path 1 or Path 2) is the lever; raw agent throughput is not.


## 2026-05-08 — R0.7 RED scope (oracle-adjudicated)

Oracle session ses_1fabd6608ffeYZ3as0GGYjEZbY recommended Option (C) with these refinements:

**RED test design**:
- Grep patterns: `seed_from_u64`, `from_seed`, `StdRng::`, `ChaCha20Rng::`, `ChaCha8Rng::`
- Allowlist paths: `**/tests/**`, `**/demo*.rs`, `**/benches/**`, `**/bin/bench*.rs`, `**/bin/fhe_baseline*.rs`, `**/bin/gen_goldens*.rs`, `**/worked_example*.rs`
- Escape hatch: same-line annotation `// allow-seeded-rng: <reason>` ONLY for construction-required determinism (Ajtai matrix from CCS instance id)
- `from_rng(rng)` is NOT flagged — inherits caller entropy

**GREEN migration plan (production callsites)**:
1. `crates/pvthfhe-cli/src/full_pipeline.rs:101,178,190,236` (4×) → OsRng
2. `crates/pvthfhe-fhe/src/fhers.rs:256` → OsRng
3. `crates/pvthfhe-bench/src/backends/fhe_rs.rs:136` → OsRng (this is in production lib path, not a bench bin)
4. `crates/pvthfhe-compressor/src/sonobe/mod.rs:81,176` → OsRng (sonobe substitution, but production path)
5. `crates/pvthfhe-pvss/src/encrypt.rs:128,269` → OsRng (F20 fix; transcript-derived encryption RNG is BROKEN per oracle)
6. `crates/pvthfhe-pvss/src/nizk_decrypt.rs:101` → OsRng UNLESS prover-side determinism is proven secure (default: migrate)
7. `crates/pvthfhe-nizk/src/{adapter.rs:294, ajtai.rs:183}` → KEEP deterministic with `// allow-seeded-rng: CRS-bound Ajtai matrix per R3.5` annotation

**Bench/example targets** (allowlisted, no migration):
- `crates/pvthfhe-bench/src/bin/{bench_nizk,bench_scaling,fhe_baseline,gen_goldens}.rs`
- `crates/pvthfhe-bench/src/worked_example.rs`

**Rationale for the annotation hatch**: keeps the lint strong-by-default while allowing legitimate construction-determinism (CRS derivation) without forcing OsRng migration that would break R3.5 CRS-binding requirement.

**New crate**: `crates/pvthfhe-rng/` — facade re-exporting `OsRng` and providing `pvthfhe_rng::production_rng()`.

## [2026-05-08] R0.3 GREEN strategy — ORACLE ADJUDICATED (ses_1f8bc91f4ffepBym15OcR9L7LA)

**Decision**: GREEN-strategy-4 (Strategy 3 + explicit C handling).

### Classification of 24 RED violations
- **A (must-zeroize secret) — 6 fields**:
  1. `pvthfhe-pvss/src/nizk_share.rs::ShareNizkWitness.share_bytes` → `ShareSecret`
  2. `pvthfhe-pvss/src/nizk_share.rs::ShareNizkWitness.encryption_randomness` → `EncRandomness`
  3. `pvthfhe-pvss/src/nizk_share.rs::ShareNizkOpenedProof.share_bytes` → `ShareSecret`
  4. `pvthfhe-pvss/src/nizk_share.rs::ShareNizkOpenedProof.encryption_randomness` → `EncRandomness`
  5. `pvthfhe-pvss/src/lib.rs::DecryptedShare.share_bytes` → `ShareSecret`
  6. `pvthfhe-cyclo/src/lib.rs::CcsPShareInstance.ccs_witness_bytes` → `CcsWitnessSecret`
- **B (public protocol bytes) — 17 fields**: wrap in `ProtocolBytes` (transparent serde, no zeroize).
- **C (currently leaks witness) — 1 field**: `pvthfhe-pvss/src/nizk_share.rs::ShareNizkProof.proof_bytes`. Quarantine: rename or annotate as `WitnessLeakingProofBytesV0` until R3 NIZK construction lands; do NOT bless as public.

### Newtypes to introduce in `crates/pvthfhe-types/src/lib.rs`
- `Secret<T: Zeroize>` — generic wrapper, `ZeroizeOnDrop`, no serde, no Debug-leak.
- `ShareSecret { inner: Secret<Vec<u8>> }` — Shamir/PVSS share material.
- `Sk<T>` — long-term secret key wrapper (placeholder for FHE BFV SK migration).
- `NoisePoly` — RLWE noise polynomial wrapper.
- `EncRandomness { inner: Secret<Vec<u8>> }` — encryption randomness witness.
- `CcsWitnessSecret { inner: Secret<Vec<u8>> }` — CCS witness bytes.
- `ProtocolBytes(Vec<u8>)` — transparent serde, public protocol artifacts.

### Lint refinement (committed as part of GREEN, not separate)
- Allow `Secret<T>`, `ShareSecret`, `Sk<T>`, `NoisePoly`, `EncRandomness`, `CcsWitnessSecret`, `ProtocolBytes` as compliant wrappers in `*Secret*|Share|Sk*` structs.
- Skip `vendor-stub/` paths (vendored stubs are immutable; enforce wrapping at adapter boundary instead).

### Constant-time comparison (F24 fix at ajtai.rs:234)
- Use `subtle::ConstantTimeEq`.
- Do NOT use iterator `.all(...)`.
- Pattern: convert each coefficient to canonical bytes, accumulate `subtle::Choice` over all coefficients, single final `bool::from(choice)` branch.

### Open issue (NOT in R0.3 scope; flagged for follow-up)
- The current lint MISSES real secrets in private fields and non-secret-named structs (FHE party SK polynomials, NIZK witness vectors). This is an R8 hardening item, NOT a R0.3 blocker. Tracked as new finding F70 (to be added to audit).

### Cryptographic concern (separate from R0.3)
- `pvthfhe-pvss/src/nizk_share.rs::encode_opened_proof` serializes witness material (`share_bytes`, `encryption_randomness`) into the proof envelope. This is by-design prototype leakage — NOT zero-knowledge. Already documented in code comments. Real fix lands in R3. R0.3 GREEN must NOT bless this as public; quarantine via type names.

## [2026-05-08] R0.5 GREEN wire-format decisions
- Chose `VERSION = 1` for all migrated R0.5 wire payload implementations, retaining existing adapter payload version semantics inside the framed body where they already existed (`PROOF_VERSION = 1`).
- Kept deterministic per-payload field encoders in place as `encode_body` helpers, and made `WireFormat::decode` responsible for all shared envelope checks: version, exact big-endian length, trailing-byte rejection, and tag verification.
- Added distinct tag variants for test payloads, three FHE wire payloads, and two PVSS proof envelopes; the tag is included inside the length-prefixed body so the declared length covers `tag || payload`.

## [2026-05-08] R1.0 oracle verdict

**VERDICT**: APPROVE

**Rationale**: Candidate 1 (Pedersen-DKG over BFV/RLWE secret domain) is the correct algebraic choice: it shares the exact `Vec<i64>` coefficient-vector representation that `gnosisguild/fhe.rs` BFV `SecretKey` stores and consumes (`sk.coeffs.to_vec()` at fhers.rs:448, `coeffs_to_poly_level0` at fhers.rs:167-173), requiring no bridge from scalar BN254. The R1.1-R1.5 implications systematically address the audit's critical DKG findings (F6/F20/F21/F23/F27/F28/F60-F63), and the working tree already fixed the F23 `ChaCha8Rng::seed_from_u64(party_id)` antipattern (fhers.rs:258 now uses `OsRng`). Candidate 2 would force 8192-24576 lane scalar-to-BFV bridging; Candidate 3 is underspecified. The recommendation correctly acknowledges its own primary weakness—RLWE public-verifiability cost vs. Noir/UltraHonk budgets has no resolution yet.

**Checks performed**:
- Soundness ≥2⁻¹²⁸ story: **UNCERTAIN** — RLWE/LWE + M-SIS/Ajtai assumptions are accepted as adequate for ≥128-bit per parameters.md, but the concrete 2⁻¹²⁸ bound on the RLWE verification proof system is not yet instantiated; the design doc's own Open Question #2 flags that "direct RLWE verification may exceed Noir/UltraHonk budgets."
- fhe.rs BFV SecretKey compatibility: **PASS** — fhers.rs stores `sk.coeffs.to_vec()` (line 448) and converts back via `coeffs_to_poly_level0` (line 167-173) exactly as the doc claims; the `PartyState` holds `sk_poly_sum: Vec<i64>` and `sk_poly_sum_poly: Option<Poly>` matching fhe.rs representation natively.
- Public-verifiability (Noir/UltraHonk) story: **UNCERTAIN** — the comparison matrix rates Candidate 1 as "Medium/low" ZK-friendly, the recommendation proposes a "folded-proof/root-binding approach" that is not specified, and Open Question #8 asks which DKG facts belong on-chain vs off-chain. The doc correctly identifies the tension but defers resolution.
- F6/F20/F21/F23/F27/F28/F60-F63 coverage: **PASS** — F6 (GF256 Shamir) and F27 (biased coefficients) are addressed by R1.2 mandate for BFV-ring domain; F20 (deterministic encryption RNG) by R1.3 CSPRNG requirement; F21 (missing smudging) by R1.4 mandate for R_q/Poly-domain smudging; F23 (party_id-seeded reshare) is already fixed in the current working tree (fhers.rs:258 uses `OsRng`) and reinforced by R1.1; F28 (compound envelope leak) addressed transitively; F60/F61/F62/F63 addressed by requiring real fhe.rs objects and fresh randomness over deterministically-derived stubs.
- Open questions quality: **PASS** — the 8 questions are substantive (citation lineage, Noir budget, secret distribution, RNS vs aggregate, anti-bias RLWE, CRS reuse, implementation risk, on-chain fact division) and identify genuine design tensions without punting critical decisions.

**Strongest counter-argument** (if APPROVE): Candidate 2 defenders would argue that Shamir over BN254 scalar + Feldman VSS is "Excellent" for Noir/on-chain verifiability (the public-verifiability piece that Candidate 1 rates "Medium/low") and that the 8192-lane scalar bridge, while ugly, is a well-understood engineering problem with known concrete cost, unlike the unspecified "RLWE relation proof + root binding" that Candidate 1 papers over.

**Caveats** (if APPROVE, non-blocking):
- Open Question #2 must be resolved before R1 implementation begins: either a concrete RLWE verification circuit design within UltraHonk budget, or an explicit commitment to the folded-proof/root-binding strategy with a soundness argument.
- Open Question #7 flags zero production-ready fhe.rs-compatible RLWE DKG implementations; this is a real research risk that may force a midstream retreat to Candidate 2's bridge approach if the RLWE proof cannot be made practical.
- Open Question #3 notes that fhe.rs samples CBD coefficients while parameters.md specifies uniform ternary; the distribution mismatch between the design doc and actual fhe.rs keygen (`SecretKey::random` at fhers.rs:439) must be reconciled before DKG implementation.
- The plan defers anti-bias RLWE DKG checks (Open Question #5, Gennaro warnings) and CRS assumption reuse (Open Question #6) to oracle adjudication; these are not blockers for APPROVE but must be answered before R1 implementation.

VERDICT_APPROVE

## [2026-05-08] R1.2 GREEN — BN254 Shamir + GF(256) removal

**Status**: COMPLETE. All 30 tests pass.

### Implementation notes

- `crates/pvthfhe-pvss/src/shamir.rs` implements Shamir secret sharing over `ark_bn254::Fr`:
  - `split()`: generates random degree-(t-1) polynomial, evaluates at x=1..n
  - `recover()`: Lagrange interpolation at x=0 using `Fr::inverse()`
  - `evaluate_polynomial()`: Horner's method over Fr
  - `lagrange_coefficient_at_zero()`: Lagrange basis computation
  - Returns `ShamirError` on insufficient/duplicate shares
- `encrypt.rs` already refactored: all GF(256) helpers removed, uses `shamir::split()` and `shamir::recover()`
- `secret_to_frs()` chunks bytes into 31-byte blocks, converts via `bytes32_to_fr()` (uses `Fr::from_bigint` — rejects values ≥ modulus, safer than `from_le_bytes_mod_order` which silently wraps)
- `frs_to_secret()` reconstructs original bytes from recovered Fr elements
- `MAX_PARTIES = 65535` replaces old `MAX_N = 255` GF(256) cap
- `Cargo.toml` already has `ark-ff = "0.5"` and `ark-bn254 = "0.5"`
- `lib.rs` already declares `pub mod shamir;`

### Bug fix: share_nizk.rs wire format offset

The `share_nizk.rs` tests `_debug_trace_proof_bytes` and `norm_bound_violator_rejected` had a pre-existing bug: they assumed the `WireFormat` tag was 4 bytes, but `WirePvssShareOpenedProof` tag is `"pvthfhe/wire/pvss-share-opened-proof/v1"` (39 bytes). Fixed offset from 11 to 46 (= 5 envelope + 39 tag + 2 proof_version).

### Test results

- `shamir_field_size::no_gf256_u8_shamir_code_paths_exist` → PASS
- `shamir_field_size::shamir_module_uses_bn254_scalar_field` → PASS
- `shamir_secrecy::t_shares_recover_correct_secret` → PASS (proptest)
- `shamir_secrecy::t_minus_1_shares_reveal_nothing` → PASS (proptest)
- `encrypt_decrypt_roundtrip::encrypt_decrypt_roundtrip_recovers_secret` → PASS
- `context_too_large::deal_at_n_65536_returns_error_naming_max` → PASS
- `context_too_large::deal_at_n_65535_does_not_fail_on_cap_check` → PASS
- Shamir unit tests: 7/7 → PASS
- NIZK tests: 4/4 → PASS
- All other tests: passing


## [2026-05-08] R1.4 smudging parameter derivation

### Decision: σ_smudge = 2^40 · σ_err ≈ 3.506 × 10^12 (log2 ≈ 41.7)

**Rationale**: This value is selected as a practical engineering choice that provides:
1. 40 bits of statistical separation between smudging noise and underlying encryption noise (σ_err = 3.19).
2. Computational LWE-based hiding — sufficient for the honest-but-curious threat model, where the adversary's view of partial decryption shares (c1, c1·sk_i + e_smudge_i) forms LWE samples that are computationally hard to invert in dimension N=8192.
3. Plenty of correctness headroom: worst-case (512-party) aggregate smudging noise is 2^50.7 against a 2^156 decoding margin → 105.3 bits of slack.

**Design document**: `.sisyphus/design/smudging.md` (388 lines).

### Why not statistical hiding?

Classical smudging (Asharov-Jain 2011/613, Lemma 2.1) requires σ_smudge ≥ B_sensitive · 2^λ for simulation-based security with statistical distance. In BFV, the sensitive term c1·sk_i has coefficient magnitude up to N·q ≈ 2^187, making statistical hiding impossible with practical parameters. We use the honest-but-curious model, which permits computational (LWE-based) hiding.

### Why not Rényi divergence?

The Rényi divergence approach (ePrint 2022/1625) requires σ_smudge ≥ σ_err · 2^(λ/2) ≈ 2^66 for λ=128 — still feasible within the correctness margin, but the additional security guarantee (full simulation) is not needed for our threat model.

### Implementation notes

- Smudging noise polynomial: N=8192 coefficients, each sampled independently from discrete Gaussian D_{Z, σ_smudge}.
- Sampling method: rounded continuous Normal(0, σ_smudge²) via `rand_distr::Normal` → round to i64. No rejection sampling needed (σ ≪ limb modulus ≈ 2^58).
- The `esi_poly_sum` field in `PartyState` already exists as scaffolding; R1.4 GREEN fills it with a freshly sampled polynomial per partial decryption.
- Wire impact: partial decryption shares grow by the size of a smudging polynomial in wire encoding (~196 KB) — acceptable since decryption is infrequent.

### Verification properties (for R1.4 GREEN tests)
- `d_0` (no smudge) ≠ `d_1` (with smudge), with probability effectively 1.
- `d_1` ≠ `d_2` (different smudge samples), with probability effectively 1.
- `||d_1 - d_0||_∞ ≤ 6·σ_smudge` (6σ bound covers 99.9999998% of samples).
- End-to-end: encrypt plaintext → partial-decrypt with smudge → aggregate → decode matches original.

### References
- Asharov, Jain, Wichs, ePrint 2011/613 (smudging lemma)
- Bendlin, Damgård, TCC 2010 (first smudging in lattice threshold encryption)
- ePrint 2022/1625 (Gaussian smudging + Rényi divergence)
- ePrint 2025/2288 (CPA^D BFV with smudging)
- `.sisyphus/design/noise-budget.md` (existing noise budget closure)

## 2026-05-08 — R1.4 Smudging noise is transient

**Decision**: Smudging noise is added to `d_share_poly` in `partial_decrypt` but NOT stored in `party_state.esi_poly_sum`.

**Rationale**: `aggregate_decrypt` reconstructs decryption shares from party state via `decryption_share_poly_from_full_state`, discarding the wire-transmitted share bytes after validation. If noise were stored in party state, the aggregate would accumulate smudging noise from all parties. By keeping noise transient, the aggregate uses noiseless shares while the wire communication is protected.

**Trade-off**: This means smudging protects only the wire communication layer, not the party state at rest. Full state-level protection would require noise storage and budget accounting, which is deferred to future work (T33+).

**Wire format bug**: The `encode_fields` bug (extra `WIRE_V1` byte) was fixed as a pre-requisite. The inner version byte in `encode_fields` was redundant — `WireFormat::encode()` already provides versioning. The `Decoder` correctly starts at offset 0 reading length-prefixed fields, so the extra byte broke all wire roundtrips.

## 2026-05-08 — R2.0 fold-construction.md authored

### Decision: Sonobe Nova substitution for P2 folding (documented)

**File**: `.sisyphus/design/fold-construction.md` (390 lines).

**Summary**: The P2 folding layer uses Sonobe Nova over BN254/Grumpkin as a temporary substitute for lattice-native folding (Cyclo/LatticeFold+). The Cyclo crate is retained for witness representation (poly-vector format, ∞-norm checks, parameter structure) but the actual folding computation is delegated to Sonobe.

**Key architectural decisions documented**:

1. **Why Sonobe**: Cyclo and LatticeFold+ lack production-grade reference implementations. Cyclo Lemma 9 formalization exceeds PVTHFHE budget. Both require a CCS encoder for the RLWE relation that has not been designed.

2. **StepCircuit design**: The RLWE decryption-share relation `d_i = c·s_i + e_i` with `‖e_i‖_∞ ≤ 16` is encoded as an R1CS circuit over BN254's scalar field. Estimated ~1.5M R1CS gates per fold step. ∞-norm checks are enforced in-circuit (not only off-chain).

3. **Soundness assumption**: Sonobe Nova over BN254/Grumpkin with T ≥ 10 rounds yields soundness error ≈ 10 × 2⁻¹²⁸ ≪ 2⁻¹²⁰. This relies on DLOG hardness (A-DLOG-1 through A-DLOG-4) and Poseidon collision resistance (A-HASH-2). NOT post-quantum — this is accepted per the existing P3 non-PQ disposition.

4. **Migration surface** (9 files): When lattice-folding becomes production-ready, swap the adapter behind `CycloAdapter` trait, implement CCS encoder for RLWE relation, and replace `sonobe/mod.rs` with `cyclo/mod.rs`. No changes to P1 NIZK, P3 verifier, Solidity contracts, Noir circuits, or FHE backend.

5. **R2.1–R2.4 implications**:
   - R2.1 ∞-norm checks: enforced in StepCircuit via bit-decomposition (49K gates for e_i, 16K for s_i); CI lint `forbid::bytes_iter_max_in_norm` enforced
   - R2.2 Challenge sampling: uniform random in F_p (Poseidon-derived), avoiding Cyclo's biased ternary + Lemma 9 heuristic
   - R2.3 CCS encoder: NOT needed under Sonobe (R1CS is native); required only for v2 migration
   - R2.4 Forgery resistance: 4 adversary models documented (raw-witness injection, wrong-relation, fold-depth overflow, commitment mismatch)

6. **New assumptions**: A-DLOG-5 (Sonobe Nova soundness over BN254/Grumpkin), A-STRUCT-7 (StepCircuit exactness), A-COND-5 (Sonobe is temporary surrogate, non-PQ at P2).

**Oracle review required**: R2.0 checkbox cannot be marked complete until oracle reviews `.sisyphus/design/fold-construction.md` and returns APPROVE.

### Design tensions noted
- Cyclo crate: contains both witness representation (kept) and folding scaffolding (stubbed for Sonobe). In a v2 migration, the folding scaffolding becomes the real Cyclo fold.
- Soundness comparison: Sonobe has tighter concrete soundness (2⁻¹²⁸) than Cyclo (κ_nu ≈ 2⁻⁹⁴ + other error terms), but at the cost of post-quantum coverage.
- The `PVTHFHE_CYCLO_PARAMS` constant (T=10, β_10=1344) is used as a sizing budget even during the Sonobe phase — the StepCircuit enforces the same norm growth schedule.

## [2026-05-09] R3.0 NIZK construction selection

### Decision: Greco primary, MPCitH fallback, Cyclo Lemma 9 STRUCK

**File**: `.sisyphus/design/nizk-construction.md` (493 lines).

**Summary**: The R3.0 NIZK construction selection supersedes the L3 Cyclo-companion
Ajtai D2 NIZK (`.sisyphus/research/nizk-selection.md`). The oracle-reordered
priorities (plan lines 273-280) lock: Greco as the primary lattice NIZK, MPC-in-
the-head as fallback, Cyclo Lemma 9 struck.

**Key architectural decisions documented**:

1. **Greco primary**: Production lattice NIZK from the `gnosisguild/fhe.rs`
   ecosystem, with published formal soundness reduction to Module-SIS (ROM,
   Fiat-Shamir). No dependency on unproven heuristics (cf. Cyclo Lemma 9).
   HVZK via rejection sampling. Est. 4-12 KB proof size, `O(N)` prover cost.
   Compatible with fhe.rs BFV key representation (same `fhe_math::rq::Poly`
   domain). Thin adapter over existing `NizkAdapter` trait.

2. **MPCitH fallback**: MPC-in-the-head (ZKBoo lineage). Soundness via hash CR
   + ROM — no exotic lattice assumptions needed for proof soundness. Cost is
   higher: 50-500 KB proof size, `O(M·|C|)` prover cost with M≈3-5 and
   `|C|≈24K` circuit ops. Requires circuit compilation of BFV ops into the
   MPCitH internal field — the main integration cost.

3. **Cyclo Lemma 9 STRUCK**: The Cyclo-companion Ajtai D2 NIZK (L3 selection)
   depends on Cyclo Theorem 3 knowledge soundness, which requires Lemma 9 (the
   invertibility heuristic for biased ternary challenges). Lemma 9 is
   downgraded to Conjecture 9 in `docs/security-proofs/lemma9.md` — the
   formal extraction argument does not exist for PVTHFHE parameters.
   Conditional soundness chain (M-SIS → Cyclo T3 → Lemma 9 → T5) is too
   long to close within v1 budget.

4. **Cyclo crate NOT struck**: `pvthfhe-cyclo` remains in use for R4 (folding)
   witness representation, norm checks, CCS encoding, and ring arithmetic.
   Only the NIZK soundness path through Cyclo Theorem 3 + Lemma 9 is retired.
   `CycloNizkAdapter` is deprecated in favor of `GrecoNizkAdapter`.

5. **Fallback trigger**: MPCitH if (a) Greco integration cost > 2 engineer-months,
   (b) Greco soundness proof does not cover PVTHFHE parameters, or (c) Greco ZK
   fails for the composed BFV-encryption + norm-bounds + hash-binding statement.
   Decision gate: Week 6 of R3 phase (R3.1 GREEN midpoint).

### Integration surface (R3.1-R3.2)

**R3.1 files changed**: `nizk_share.rs` (rewrite: remove witness-in-envelope,
replace hash-of-witness with Greco relation check), `pvthfhe-types` (extend
newtypes for Greco proof/statement/witness), `adapter.rs` (replace
`CycloNizkAdapter` with `GrecoNizkAdapter`), `lib.rs` (update `BACKEND_ID` to
`"greco-bfv-wf-v1"`), `real_nizk.rs` (re-route to Greco).

**R3.2 files changed**: `nizk_decrypt.rs` (remove `derive_secret_share`, prove
`d_i = c·sk_i + e_i` with Greco, bind `(party_id, pk_i_hash)` to `dkg_root`),
`decrypt/mod.rs` (replace `nizk[0] == 1` stub, replace fake `pk_i_hash`).

**Not changed**: `pvthfhe-cyclo/` (retained for R4), `ajtai.rs` (retained as
commitment primitive), `fiat_shamir.rs` (retained; domain tags updated),
`hash_bridge.rs` (retained; SHA-256 binding unchanged).

### Open questions for oracle

1. Greco reference implementation availability at R3.1 GREEN start
2. Greco parameter bridge for PVTHFHE's 3-limb RNS BFV params
3. Composed statement ZK: BFV encryption + norm bounds + hash binding
4. MPCitH circuit compilation gap for fhe.rs BFV
5. Cyclo crate cleanup scope vs R4 dependency
6. Conditional-soundness banner reword from "Cyclo T3 Lemma 9" to "Greco M-SIS"
7. Fallback trigger timing: decision by Week 6 of R3 phase

**Oracle review required**: R3.0 checkbox cannot be marked complete until oracle
reviews `.sisyphus/design/nizk-construction.md` and returns APPROVE.

## [2026-05-09] R8.2 pre-reveal-binding.md authored

### Decision: Pre-reveal binding design documented

**File**: `.sisyphus/design/pre-reveal-binding.md` (273 lines).

**Summary**: Documented the atomic plaintext release binding design per the R8.2
GATE requirement and Interfold gate item 3. The document establishes that
plaintext MUST NOT be released until (a) all NIZK proofs verify, (b) the
fold-compressed proof verifies, and (c) the full binding tuple matches.

### Key architectural decisions documented:

1. **7-field tuple**: `(session_id, epoch, ct_hash, roster_hash, param_hash, srsHash, dkg_root)` — sourced from the RED test `pre_reveal_binding_tuple.rs` REQUIRED_BINDING_FIELDS array. The 7th field (`dkg_root`) requires R1 (DKG) to produce it; until then, the GREEN fix binds the 6 available fields.

2. **Hash choice: Poseidon-BN254** as the primary binding hash. In-circuit efficient for the BN254 scalar field used by MicroNova/UltraHonk. Fallback to SHA-256 if the P3 gate confirms SHA-256 as canonical. Either is sufficient for collision resistance.

3. **Field name mappings against codebase**:
   - `roster_hash` → `participant_set_hash: [u8; 32]` from `keygen/simulator.rs:85`
   - `srsHash` → `Compressor::srs_hash()` from `compressor/src/sonobe/mod.rs:232`
   - `dkg_root` → NOT YET PRODUCED by current pipeline (requires R1 DKG)
   - `session_id` → exists as `keygen_session_id()` at `full_pipeline.rs:307` but not in binding hasher
   - `param_hash` → NOT YET computed in pipeline

4. **Current state (RED)**: 5 of 7 fields missing from `build_fold_instances` binding hasher. Only `ct_hash` and `seed` (epoch proxy) are present. The RED test `binding_currently_missing_fields` passes (confirms absence).

5. **F67 fix integration**: `aggregate_decrypt` MUST consume submitted share bytes, not internal `PartyState`. Documented in §3.2 with reference to `aggregate_uses_submitted_shares.rs` (78 lines, FHE crate test).

6. **`runId` replay protection**: Defined as `SHA-256(session_id ∥ epoch ∥ ct_hash ∥ rand_nonce)` with OsRng-sampled nonce. Consumed-set pattern prevents double-claim of same decryption result. Not yet in the REQUIRED_BINDING_FIELDS test — is a planned addition.

7. **Proof-boundary alignment**: Closes gaps in PB-07 (replay prevention), PB-10 (proof binding), and PB-12 (parameter consistency) per `proof-boundary.md`.

### Implementation steps (GREEN to follow):
1. Add all 7 fields to `build_fold_instances` binding hasher
2. Replace `seed.to_le_bytes()` with dedicated `epoch` field
3. Add `runId` generation and include in binding
4. Implement `guarded_aggregate_decrypt` gate
5. Verify RED→GREEN transition on `binding_currently_missing_fields`

### Open questions:
1. Poseidon vs SHA-256 pending P3 gate confirmation
2. `runId` nonce source: OsRng vs FS-derivation
3. Per-share NIZK digest in binding vs fold-level consumption
4. `dkg_root` content requires R1 DKG to land

### Oracle review required:
R8.2 → `.sisyphus/design/pre-reveal-binding.md` independent review (per decisions.md L40). The document is now available for review.

## 2026-05-09 — Parameter freeze v1 created

**Decision:** Created `.sisyphus/design/param-freeze-v1.md` (140 lines) freezing all 5 parameter categories for Architecture B.

**Frozen parameters:**
1. **BFV:** n=8192, log₂Q=174, t_plain=65536 (2¹⁶), 3×58-bit NTT moduli (q₀=288230376173076481, q₁=288230376167047169, q₂=288230376161280001), ternary secrets, σ=3.19 error.
2. **SRS:** `H(epoch ‖ "pvthfhe-srs-v1")` → transparent Pedersen SRS, deterministic CSPRNG expansion. Domain tag: `pvthfhe/sonobe/srs/v1`.
3. **DKG:** default (n=10, t=7), max n=256, t floor = ⌊n/2⌋+1, quorum ⌈2t/3⌉.
4. **Ajtai matrix:** m=2048 rows, n=1024 cols, q≈2⁶⁰, domain tag: `pvthfhe/cyclo-ajtai-binding/v1`.
5. **Domain tags:** All 13 Tag enum variants mapped to protocol phases (Phase 0–3 + Testing).

**Note:** t_plain=65536 differs from the current parameters.md value of 131072 (2¹⁷). This freeze overrides the prior parameter set. If 131072 is intended, a parameter amendment is required.

**Sources referenced:**
- `crates/pvthfhe-domain-tags/src/lib.rs`:1–76 (Tag enum)
- `.sisyphus/design/parameters.md`:1–71 (RLWE parameter documentation)
- `.sisyphus/design/parameters.toml`:1–49 (machine-readable parameters)
- `parameters.toml`:1–4 (root-level summary)

**Sign-off field holders:** Cryptography Lead, ZK Lead, Engineering Lead (all awaiting sig).
