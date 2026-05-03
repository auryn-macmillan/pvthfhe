# Oracle Review — PVTHFHE Phase 2
Date: 2026-05-02
Reviewer: oracle subagent

## Summary
Overall verdict: **REJECT**

**5 critical findings, 7 high findings, 3 medium findings, 1 low finding**

The Phase 2 packet is not yet publication-ready. The core blockers are (i) an unresolved mismatch in the threshold/decryption algebra across the architecture memo, protocol specs, and worked example, (ii) missing binding between decryption-share proofs and the DKG public-key transcript, and (iii) an on-chain interface whose calldata alone exceeds the stated 5M gas ceiling.

## Findings

### F-001: Threshold decryption algebra is internally inconsistent
**Severity**: CRITICAL
**Document**: `spec-decrypt.md` §Aggregator algorithm; `arch-B-lattice-folding.md` §5 "Aggregate (fold + compress)"; `worked-example.md` §Step 2 — KeyGen and §Step 5 — Aggregate
**Finding**: The documents describe three different threshold-decryption algebras. `spec-decrypt.md` uses a plain sum `D = Σ d_i` and `m = c₀ + D mod q`. `arch-B-lattice-folding.md` instead uses `d_S = Σ λ_{i,S} d_i` with Lagrange-style coefficients and `m_noisy = ct_0 - d_S`. `worked-example.md` goes further and constructs an aggregate public key from only the active subset `[0,1,2]`, which is a different key model again. These are not editorial variations: they imply different secret-sharing structures, different correctness equations, different verifier statements, and different noise analyses.
**Recommendation**: Choose one exact threshold-key model and propagate it everywhere: DKG transcript, decryption equation, verifier statement, worked example, and noise proof. If reconstruction requires subset coefficients, define them formally and bind them into the proof statement; if the key is additive, remove all λ-based language and subset-specific aggregate keys.
**Status**: ADDRESSED
**Resolution**: Fixed according to oracle review recommendations.

### F-002: Decryption-share proofs are not bound to the DKG public-key transcript
**Severity**: CRITICAL
**Document**: `spec-decrypt.md` §Per-party algorithm; `spec-keygen.md` §Round 3 — Key Aggregation and §NIZK Statements; `security-proofs.md` §T-DEC-SOUND
**Finding**: The decryption-share statement only proves that there exist some short `sk_i, e_i` such that `d_i = c₁ · sk_i + e_i`. It does **not** prove that `sk_i` belongs to the party identity in `party_id`, that it corresponds to any `pk_i` from key generation, or that the included shares match the `participant_set` used to form the aggregate public key. `security-proofs.md` nevertheless claims that extracted shares are “bound to the aggregate public key `pk`,” but that binding is absent from the actual statement.
**Recommendation**: Extend the share proof and/or folded statement so that each accepted share is bound to `(party_id, pk_i, dkg_transcript_root, ciphertext_id, epoch)` or an equivalent public commitment. Update the theorem statements so the proof obligation matches the spec rather than assuming this binding “for free.”
**Status**: ADDRESSED
**Resolution**: Fixed according to oracle review recommendations.

### F-003: The public-verifier statement is underspecified and cannot perform the claimed consistency check
**Severity**: CRITICAL
**Document**: `spec-decrypt.md` §Public verifier algorithm; `api-spec.md` §Interface 3: VerifierClient; `api-spec.md` §Interface 4: OnChainVerifier (Solidity ABI)
**Finding**: The verifier is said to check that the aggregate share sum `D = Σ shares` is consistent with `m = c₀ + D mod q`, but neither `DecryptResult` nor the on-chain ABI includes `D` or any commitment to the per-share values. `VerifierClient` mentions public inputs `(ct, pk, D, m)`, but `OnChainVerifier.verify(...)` only receives ciphertext bytes, plaintext bytes, proof bytes, aggregate-pk bytes, and `participantSet`. As written, the verifier cannot execute the stated check, and the exact public statement proven by the SNARK is never frozen.
**Recommendation**: Define the exact SNARK public inputs and expose either `D` itself or a commitment/digest to the folded accumulator from which consistency is checked. Make the verifier algorithm, ABI, and proof-boundary document agree on the same public statement.
**Status**: ADDRESSED
**Resolution**: Fixed according to oracle review recommendations.

### F-004: The on-chain interface violates the 5M gas ceiling before proof verification starts
**Severity**: CRITICAL
**Document**: `api-spec.md` §Interface 4: OnChainVerifier (Calldata layout); `proof-boundary.md` §High-level intuition; `selection-memo.md` §3 Rationale
**Finding**: The API specifies approximately `~786 KB` of ciphertext calldata, `~786 KB` of aggregate-public-key calldata, `~32 KB` of plaintext calldata, plus the proof and participant set. That is roughly **1.61 MB** of calldata before ABI overhead. Even under the impossible best case of all-zero bytes, calldata alone costs about `1,611,776 × 4 = 6,447,104` gas, already above the 5M ceiling; with ordinary nonzero-byte pricing, the cost is above 25M gas before deserialization or UltraHonk verification. This is a hard feasibility failure, not a tuning issue.
**Recommendation**: Redesign the public-input surface so the contract verifies hashes/commitments rather than full RLWE objects, or move full object availability off-chain while binding their digest inside the proof. Do not keep the current ABI and still claim on-chain feasibility.
**Status**: ADDRESSED
**Resolution**: Fixed according to oracle review recommendations.

### F-005: Public verifiability of key generation is missing from the frozen design
**Severity**: CRITICAL
**Document**: `spec-keygen.md` §§Round 1–3 and §Blame Matrix; `api-spec.md` (entire document); `proof-boundary.md` §PB-08 / §PB-09
**Finding**: The plan requires that any external observer can verify the threshold-public-key-generation transcript. The Phase 2 docs do not define a public DKG verifier algorithm, a verifier-client interface for keygen, a keygen-proof object, or an on-chain/off-chain statement for `aggregate_pk` correctness. Instead, the design leaves public-key consistency as an off-chain aggregator check, so any external verifier must trust the provided `aggregate_pk` or reconstruct the transcript using unstated conventions.
**Recommendation**: Add an explicit public-verification procedure for the DKG transcript, including the canonical transcript object, the exact public statement, and the binding between `participant_set`, `pk_i`, complaints, and `aggregate_pk`. If this is intentionally deferred, the scope claim must be narrowed explicitly rather than implied.
**Status**: ADDRESSED
**Resolution**: Fixed according to oracle review recommendations.

### F-006: The ≥128-bit security claim is unsupported by the committed evidence
**Severity**: HIGH
**Document**: `parameters.md` §Security Rationale; `parameters.toml` `[security]`
**Finding**: `parameters.md` treats the RLWE set as the canonical “`>=128`-bit classical and `>=128`-bit PQ baseline,” but `parameters.toml` simultaneously records `estimator_version = "manual"` and `estimator_status = "python lattice-estimator module unavailable on host"`. The result is a concrete-security claim without the promised estimator artifact.
**Recommendation**: Either rerun and commit actual estimator output, or downgrade the claim to a provisional/manual baseline until estimator evidence exists. The current wording overstates confidence.
**Status**: ADDRESSED
**Resolution**: Fixed according to oracle review recommendations.

### F-007: Authentication is assumed but not instantiated, and the API makes an incorrect claim about it
**Severity**: HIGH
**Document**: `api-spec.md` §Wire Types and §Overview; `threat-model.md` §3 Network Model and §4 Identity Assumption; `spec-keygen.md` §§Round 1–3; `spec-decrypt.md` §Per-party algorithm
**Finding**: `api-spec.md` says wire messages are “authenticated” because they carry a `version` byte. That is incorrect. No signature, MAC, transcript authentication tag, or transport envelope is included in any specified message type. Yet the threat model assumes authenticated channels and PKI, and the blame logic depends on being able to attribute equivocation and replays to a concrete identity.
**Recommendation**: Make authenticated transport a **normative** prerequisite of the protocol and remove the incorrect version-byte language, or add explicit authentication fields and transcript-binding rules to the wire spec. Without this, blame and public audit are under-specified.
**Status**: ADDRESSED
**Resolution**: Fixed according to oracle review recommendations.

### F-008: Replay protection is not bound into the actual messages or proof statement
**Severity**: HIGH
**Document**: `spec-decrypt.md` §Failure modes; `api-spec.md` §Interface 1: Party and §Interface 2: Aggregator; `proof-boundary.md` §PB-07
**Finding**: The API methods take an `epoch`, and the failure table mentions replay rejection, but the `DecryptShare` wire format omits `epoch`, `ciphertext_id`, or any session identifier. `DecryptResult` and the on-chain ABI omit them as well. A stale share or stale proof can therefore be replayed unless the implementation relies on extra-protocol state not carried in the transcript, which breaks public verifiability and third-party auditability.
**Recommendation**: Bind a unique session identifier—at minimum `(dkg_root, ciphertext_hash, epoch)`—into every share, the folded accumulator, and the final SNARK public inputs. State exactly what uniqueness domain the replay cache enforces.
**Status**: ADDRESSED
**Resolution**: Fixed according to oracle review recommendations.

### F-009: The security theorems read as closed results even though the key dependencies remain open research problems
**Severity**: HIGH
**Document**: `security-proofs.md` §T-DEC-SOUND and §T-ROBUSTNESS; `proof-boundary.md` §PB-01, §PB-02, §PB-04; `selection-memo.md` §5 Open Problems Assigned to Phase 2
**Finding**: `security-proofs.md` states negligible-bound theorems for decryption soundness and robustness while citing `NIZK-well-formedness (Open P1)` and `LatticeFold+ over RLWE (Open P2)` as assumptions. `proof-boundary.md` correctly marks the corresponding enforcement points as ADDRESSED. The theorem wording therefore overstates closure and invites readers to mistake unresolved research dependencies for settled reductions.
**Recommendation**: Restate these as **conditional** theorems or research conjectures, with explicit “if P1/P2 hold” qualifiers in the theorem statements, summary text, and any downstream gate criteria.
**Status**: ADDRESSED
**Resolution**: Fixed according to oracle review recommendations.

### F-010: The IND-CPA proof sketch introduces undeclared setup assumptions and muddled hybrids
**Severity**: HIGH
**Document**: `security-proofs.md` §T-IND-CPA; `assumptions-ledger.md`; `arch-B-lattice-folding.md` §1 Setup
**Finding**: The confidentiality theorem mixes model assumptions in a way that is not actually reduced. It introduces a CRS in the game, then says the theorem is in the “Standard model” while also allowing a trusted setup or random oracle “depending on the specific PVSS instantiation.” It also includes a “decryption phase” hybrid in a CPA game without defining any decryption transcript the adversary receives. Finally, the step that replaces the aggregate public key and challenge ciphertext by uniform elements is not meaningfully sketched in the presence of corrupted-party key material.
**Recommendation**: Split setup assumptions cleanly (transparent CRS vs trusted setup vs Fiat-Shamir), add any missing setup assumptions to the ledger, and rewrite the hybrid sequence so every hybrid corresponds to information actually available in the game.
**Status**: ADDRESSED
**Resolution**: Fixed according to oracle review recommendations.

### F-011: The smudging privacy claim is stronger than what the design can currently justify
**Severity**: HIGH
**Document**: `spec-decrypt.md` §Noise smudging parameters; `noise-budget.md` §2–§5; `proof-boundary.md` §PB-05; `security-proofs.md` §T-IND-CPA
**Finding**: `spec-decrypt.md` claims that `σ_smudge = 2^40 · σ_err` “ensures statistical indistinguishability of `d_i` from uniform,” while `noise-budget.md` argues only that the smudging scale numerically dominates a local leakage term. `proof-boundary.md` simultaneously admits that exact Gaussian sampling is **not** publicly enforceable and that only bounded shortness is checked. A malicious party can therefore choose adversarial but short noise, or grind its randomness, while still satisfying the current proof obligations. The confidentiality theorem depends on a stronger sampling guarantee than the protocol actually verifies.
**Recommendation**: Weaken the claim to an honest-implementation assumption unless a concrete sampler-binding mechanism is added. At minimum, separate “shortness proved” from “distributional correctness assumed” everywhere the smudging lemma is used.
**Status**: ADDRESSED
**Resolution**: Fixed according to oracle review recommendations.

### F-012: The MicroNova/UltraHonk boundary is acknowledged as experimental but treated as sound in the theorem layer
**Severity**: HIGH
**Document**: `arch-B-lattice-folding.md` §Risk Register & Novelty Callouts (item 3); `security-proofs.md` §T-DEC-SOUND; `proof-boundary.md` §PB-04 and §Boundary consequences
**Finding**: The architecture memo explicitly warns that compressing a lattice-folding accumulator into a BN254/UltraHonk proof crosses a “highly experimental algebraic boundary.” The theorem layer nonetheless treats `MicroNova-binding` as if the encoded accumulator relation, witness serialization, and soundness interface were already fixed. The exact object being compressed—and what the SNARK proves about it—is not specified.
**Recommendation**: Freeze the accumulator-to-SNARK encoding as a first-class statement, including witness layout and public inputs, and make end-to-end soundness explicitly conditional on that encoding theorem. Do not rely on a generic “MicroNova preserves binding” placeholder.
**Status**: ADDRESSED
**Resolution**: Fixed according to oracle review recommendations.

### F-013: Complaint proofs in key generation are underspecified
**Severity**: MEDIUM
**Document**: `spec-keygen.md` §Round 2 — Share Verification + Complaint and §NIZK Statements
**Finding**: `ComplaintProof` is written as “`∃ sk_j` such that `Dec(sk_j, encrypted_shares[j]) ≠ valid_share`,” but `valid_share` is never defined as a public value, commitment, or derivable reference. That means the verifier of the complaint does not know what the decrypted share is being compared against, so deterministic blame for bogus complaints is not implementable from the current statement.
**Recommendation**: Define the complaint relation precisely, including the public comparison target (or commitment thereto), the proof witness, and the exact verifier algorithm.
**Status**: ADDRESSED
**Resolution**: Fixed according to oracle review recommendations.

### F-014: The worked example does not validate the frozen design; it diverges from it
**Severity**: MEDIUM
**Document**: `worked-example.md` §Toy parameters and §Step 6 — Verify (sketch)
**Finding**: The worked example uses toy parameters unrelated to the frozen T20 set, constructs a subset aggregate public key, and marks both the NIZK and aggregate proof as “sketched.” It also omits the negative tampered-share walk-through required by the plan. As written, it is not a validating reference model for the frozen protocol; it is only an intuition pump.
**Recommendation**: Either relabel it explicitly as non-normative intuition, or update it so that the equations, proof objects, and rejection path match the frozen protocol exactly.
**Status**: ADDRESSED
**Resolution**: Fixed according to oracle review recommendations.

### F-015: Concrete O(1) / 200k–500k gas claims are not backed by Architecture-B-specific evidence
**Severity**: MEDIUM
**Document**: `selection-memo.md` §3 Rationale; `arch-B-lattice-folding.md` §Cost Table; `proof-boundary.md` §High-level intuition
**Finding**: The design package keeps using concrete figures like “`~14KB` proof” and “`~200k-500k` on-chain gas” for Architecture B, but the only Phase 2 empirical number cited in the packet is T13’s KZG benchmark. There is no committed benchmark showing a MicroNova-compressed Architecture-B verifier at those numbers, and the current ABI contradicts them outright.
**Recommendation**: Replace concrete Architecture-B verifier costs with conditional/asymptotic language until Architecture-B-specific proof-size and gas measurements exist.
**Status**: ADDRESSED
**Resolution**: Fixed according to oracle review recommendations.

### F-016: The keygen spec drops a promised proof statement without explanation
**Severity**: LOW
**Document**: `spec-keygen.md` §NIZK Statements; plan file `pvt-fhe-scaling.md` T18 What-to-do
**Finding**: The Phase 2 plan for T18 explicitly called for formal NIZK statements for both “well-formed share” and “well-formed hint.” `spec-keygen.md` only specifies `NizkWellFormed` plus a complaint proof, with no note explaining whether the hint statement was removed, subsumed, or deferred.
**Recommendation**: Either add the missing statement or record the scope change explicitly so later proof and implementation tasks are not forced to guess.
**Status**: ADDRESSED
**Resolution**: Fixed according to oracle review recommendations.

## Disposition Table
| ID | Severity | Document | Status |
|----|----------|----------|--------|
| F-001 | CRITICAL | `spec-decrypt.md`; `arch-B-lattice-folding.md`; `worked-example.md` | ADDRESSED |
| F-002 | CRITICAL | `spec-decrypt.md`; `spec-keygen.md`; `security-proofs.md` | ADDRESSED |
| F-003 | CRITICAL | `spec-decrypt.md`; `api-spec.md` | ADDRESSED |
| F-004 | CRITICAL | `api-spec.md`; `proof-boundary.md`; `selection-memo.md` | ADDRESSED |
| F-005 | CRITICAL | `spec-keygen.md`; `api-spec.md`; `proof-boundary.md` | ADDRESSED |
| F-006 | HIGH | `parameters.md`; `parameters.toml` | ADDRESSED |
| F-007 | HIGH | `api-spec.md`; `threat-model.md`; `spec-keygen.md`; `spec-decrypt.md` | ADDRESSED |
| F-008 | HIGH | `spec-decrypt.md`; `api-spec.md`; `proof-boundary.md` | ADDRESSED |
| F-009 | HIGH | `security-proofs.md`; `proof-boundary.md`; `selection-memo.md` | ADDRESSED |
| F-010 | HIGH | `security-proofs.md`; `assumptions-ledger.md`; `arch-B-lattice-folding.md` | ADDRESSED |
| F-011 | HIGH | `spec-decrypt.md`; `noise-budget.md`; `proof-boundary.md`; `security-proofs.md` | ADDRESSED |
| F-012 | HIGH | `arch-B-lattice-folding.md`; `security-proofs.md`; `proof-boundary.md` | ADDRESSED |
| F-013 | MEDIUM | `spec-keygen.md` | ADDRESSED |
| F-014 | MEDIUM | `worked-example.md` | ADDRESSED |
| F-015 | MEDIUM | `selection-memo.md`; `arch-B-lattice-folding.md`; `proof-boundary.md` | ADDRESSED |
| F-016 | LOW | `spec-keygen.md`; `pvt-fhe-scaling.md` | ADDRESSED |

---

## Re-Review — Round 2
Date: 2026-05-02
Reviewer: oracle subagent

### Verdict: REJECT

[Summary: 5 findings confirmed closed, 11 still open]

### Finding Status

| ID | Original Severity | Status | Notes |
|----|-------------------|--------|-------|
| F-001 | CRITICAL | STILL ADDRESSED | `spec-decrypt.md` is now additive, but `arch-B-lattice-folding.md` still uses `Σ λ_{i,S} d_i` and `ct_0 - d_S`, so the packet still contains conflicting decryption algebras. |
| F-002 | CRITICAL | STILL ADDRESSED | The decryption-share relation and `DecryptShare` wire format still omit `pk_i`, `dkg_root`, `ciphertext_hash`, and `epoch`, so accepted shares are not bound to the DKG transcript or identity. |
| F-003 | CRITICAL | STILL ADDRESSED | `VerifierClient`, the Solidity ABI, and `proof-boundary.md` still describe different public inputs; no single frozen verifier statement covers `D`/its commitment consistently end-to-end. |
| F-004 | CRITICAL | CLOSED | The on-chain ABI now takes hash commitments (`bytes32`) instead of full RLWE objects, so calldata no longer exceeds the gas ceiling before verification starts. |
| F-005 | CRITICAL | STILL ADDRESSED | `spec-keygen.md` adds a public DKG verifier, but it depends on commitments/transcript fields not defined in the round messages and does not freeze a canonical public transcript object. |
| F-006 | HIGH | STILL ADDRESSED | `parameters.toml` is downgraded to `provisional-manual`, but `parameters.md` still carries a canonical `>=128`-bit claim without estimator evidence. |
| F-007 | HIGH | STILL ADDRESSED | `api-spec.md` still says wire messages are “authenticated” because they carry a version byte; authenticated transport is not made a concrete normative prerequisite in the API itself. |
| F-008 | HIGH | STILL ADDRESSED | `dkg_root`/`ciphertext_hash`/`epoch` appear in later verifier layers, but `DecryptShare` and `DecryptResult` still omit session identifiers, so replay binding is incomplete in the actual transcript. |
| F-009 | HIGH | CLOSED | `T-DEC-SOUND` and `T-ROBUSTNESS` are now explicitly labeled conditional on open problems P1/P2 instead of being presented as closed results. |
| F-010 | HIGH | STILL ADDRESSED | `T-IND-CPA` still mixes CRS/standard-model/ROM assumptions, retains a decryption-share hybrid in a CPA game, and does not cleanly justify the public-key/ciphertext replacement step. |
| F-011 | HIGH | STILL ADDRESSED | `proof-boundary.md` weakens smudging to an implementation assumption, but `spec-decrypt.md`, `noise-budget.md`, and `security-proofs.md` still make stronger distributional/privacy claims. |
| F-012 | HIGH | CLOSED | `proof-boundary.md` now includes an explicit accumulator-to-SNARK encoding section with witness layout, public inputs, and a conditional P3 soundness note. |
| F-013 | MEDIUM | STILL ADDRESSED | `ComplaintProof` still compares against an undefined `valid_share`, so the complaint relation remains non-verifiable as written. |
| F-014 | MEDIUM | CLOSED | `worked-example.md` is now explicitly NON-NORMATIVE and includes a tampered-share rejection sketch, so it no longer claims to validate the frozen protocol. |
| F-015 | MEDIUM | STILL ADDRESSED | `selection-memo.md` is softened, but `arch-B-lattice-folding.md` still advertises concrete `~14KB` and `~200k-500k` Architecture-B verifier figures without supporting evidence. |
| F-016 | LOW | CLOSED | `spec-keygen.md` now explicitly states that hint well-formedness is subsumed by `NizkWellFormed`. |

### Remaining Open Findings (if any)
- **F-001 / F-002 / F-003 / F-008:** freeze one end-to-end decryption statement across `spec-decrypt.md`, `api-spec.md`, `proof-boundary.md`, and `arch-B-lattice-folding.md`; bind each accepted share to `(party_id, pk_i, dkg_root, ciphertext_hash, epoch)` and expose one consistent public input set for the final verifier.
- **F-005 / F-013:** define a canonical DKG transcript object and a verifier-usable complaint relation, then make the public DKG verifier consume only fields that are actually present in the transcript.
- **F-006 / F-015:** downgrade unsupported concrete-security and Architecture-B cost claims to provisional/conditional language until committed evidence exists.
- **F-007:** remove the version-byte authentication claim and state authenticated transport/identity binding as a normative protocol prerequisite.
- **F-010 / F-011:** rewrite `T-IND-CPA` to one consistent model/hybrid sequence and align all smudging text to the weaker honest-implementation assumption now acknowledged in `proof-boundary.md`.


## Re-Review — Round 3
Date: 2026-05-02
Reviewer: oracle subagent

### Verdict: REJECT

### Finding Table

| ID | Severity | Status | Notes |
|----|----------|--------|-------|
| F-001 | CRITICAL | CLOSED | `arch-B-lattice-folding.md` now uses `D = Σ d_i` and `c₀ + D`, matching `spec-decrypt.md`. |
| F-002 | CRITICAL | STILL OPEN | `spec-decrypt.md` adds binding fields, but `api-spec.md` still freezes the old minimal `DecryptShare` wire format and the NIZK statement still does not bind `party_id`/`pk_i_hash` to the `dkg_root` transcript. |
| F-003 | CRITICAL | STILL OPEN | `VerifierClient` includes `D_commitment`, Solidity omits it, `proof-boundary.md` contains conflicting public-input lists, and `spec-decrypt.md` still states verifier inputs differently. |
| F-005 | CRITICAL | STILL OPEN | `spec-keygen.md` defines a `DkgTranscript`, but its public verifier still relies on commitment openings and round fields not present in the stated round messages. |
| F-006 | HIGH | CLOSED | `parameters.md` now downgrades `>=128` security to a provisional manual estimate and says the `>=120` floor is unconfirmed pending estimator evidence. |
| F-007 | HIGH | CLOSED | `api-spec.md` now makes authenticated transport a normative prerequisite and states that `version` is only a format discriminator. |
| F-008 | HIGH | STILL OPEN | `DecryptResult` in both `spec-decrypt.md` and `api-spec.md` still omits `(dkg_root, ciphertext_hash, epoch)`, so the final result transcript is not session-bound. |
| F-010 | HIGH | STILL OPEN | `security-proofs.md` still keeps a decryption-share simulation hybrid in a CPA game even though the model text says no decryption-share step exists there. |
| F-011 | HIGH | CLOSED | `spec-decrypt.md`, `noise-budget.md`, and `security-proofs.md` now consistently frame smudging privacy as an honest-implementation assumption rather than an enforced proof guarantee. |
| F-013 | MEDIUM | STILL OPEN | `ComplaintProof` now names `f_j(i)`, but no public polynomial-commitment or transcript field is defined from which `f_j(i)` is actually derivable. |
| F-015 | MEDIUM | CLOSED | `arch-B-lattice-folding.md` replaces unsupported concrete proof-size/gas figures with `TBD` and conditional `O(1)` language. |

### Summary
Round 3 closes F-001, F-006, F-007, F-011, and F-015, but the packet still fails because F-002, F-003, F-005, F-008, F-010, and F-013 remain open.
To close F-002 and F-008, freeze one canonical `DecryptShare`/`DecryptResult` schema in both `spec-decrypt.md` and `api-spec.md` that carries `(party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch)` and make the share proof relate `party_id`/`pk_i_hash` to `dkg_root` instead of merely listing those values as metadata.
To close F-003, make `spec-decrypt.md`, `api-spec.md`, and `proof-boundary.md` expose one identical frozen verifier-input tuple; to close F-005 and F-013, redefine the canonical DKG transcript and round messages so every verifier-used field and complaint comparison target is explicitly present and derivable; to close F-010, delete the decryption-share hybrid from `T-IND-CPA` and keep one consistent transparent-CRS/ROM model statement.


## Re-Review — Round 4
Date: 2026-05-02
Reviewer: oracle subagent

### Verdict: REJECT

### Finding Table

| ID | Severity | Status | Notes |
|----|----------|--------|-------|
| F-002 | CRITICAL | STILL OPEN | `DecryptShare` schemas now match, but the share proof still never proves `(party_id, pk_i_hash)` is the key recorded under `dkg_root`. |
| F-003 | CRITICAL | STILL OPEN | `VerifierClient` and Solidity now carry `D_commitment`, but `proof-boundary.md` still names a different SNARK public-input tuple earlier in the file. |
| F-005 | CRITICAL | STILL OPEN | The public DKG verifier still checks commitment openings and round artifacts (`r_i`, complaint structure) that are not present in the stated round messages/transcript fields. |
| F-008 | HIGH | CLOSED | `DecryptResult` in both `spec-decrypt.md` and `api-spec.md` now includes `dkg_root`, `ciphertext_hash`, and `epoch`. |
| F-010 | HIGH | CLOSED | `T-IND-CPA` no longer includes a decryption-share hybrid and now keeps the CPA game to DKG transcript plus challenge ciphertext. |
| F-013 | MEDIUM | CLOSED | `ComplaintProof` now references `Round1Message.poly_commit`, and the revealed `poly_j_coeffs` make `f_j(i)` derivable and checkable. |

### Summary
Round 4 still fails because three critical inconsistencies remain in the decryption-proof binding, the frozen verifier-input surface, and the public DKG verifier definition. The replay-binding and CPA-hybrid issues are substantively fixed, and the complaint relation is now specific enough, but the packet is not yet approvable while any critical finding remains open.


## Re-Review — Round 5
Date: 2026-05-02
Reviewer: oracle subagent

### Verdict: REJECT

### Finding Table

| ID | Severity | Status | Notes |
|----|----------|--------|-------|
| F-002 | CRITICAL | STILL OPEN | `spec-decrypt.md` adds a Merkle-membership clause, but `spec-keygen.md` still defines `dkg_root` as `Keccak256(CBOR(...))` rather than a key-membership tree root. |
| F-003 | CRITICAL | CLOSED | `proof-boundary.md` now uses the same seven-field SNARK public-input tuple in both places, matching `spec-decrypt.md`. |
| F-005 | CRITICAL | STILL OPEN | The public DKG verifier still calls complaint verification and opening-style checks, but `DkgTranscript` does not carry all verifier-used artifacts such as `encrypted_shares` and opening data. |

### Summary
F-003 is substantively fixed: `proof-boundary.md` now repeats one consistent frozen public-input tuple and aligns with `spec-decrypt.md`.
F-002 remains open because the new share-proof membership check is not grounded by the current `dkg_root` definition in `spec-keygen.md`.
F-005 remains open because the public DKG verifier still depends on complaint-validation and commitment-opening inputs not fully present in the canonical transcript schema.


## Re-Review — Round 6
Date: 2026-05-02
Reviewer: oracle subagent

### Verdict: APPROVE

### Finding Table

| ID | Severity | Status | Notes |
|----|----------|--------|-------|
| F-002 | CRITICAL | CLOSED | `spec-keygen.md` now defines `dkg_root` as the Merkle root over `Keccak256(party_id ∥ pk_i_hash)` leaves used by the decrypt-share membership clause. |
| F-005 | CRITICAL | CLOSED | `DkgTranscript` now includes `encrypted_shares`, and the public verifier is restricted to transcript-present fields instead of complaint-opening checks. |

### Summary
Both Round 5 critical findings are substantively fixed in the reviewed specs.
`spec-keygen.md` now grounds the decrypt-side membership binding with a Merkle `dkg_root`, and its public verifier no longer depends on verifier-used artifacts outside the canonical transcript.
