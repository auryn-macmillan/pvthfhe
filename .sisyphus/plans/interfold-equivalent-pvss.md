# Plan: Interfold-Equivalent PVSS Guarantees with Batched PVTHFHE Performance

**Plan**: `interfold-equivalent-pvss`  
**Goal**: Strengthen PVTHFHE's public-verifiability and BFV threshold-decryption guarantees to be roughly comparable to The Interfold's current PVSS / PV-TBFV implementation, while preserving PVTHFHE's intended asymptotic and practical performance advantage.  
**Intent**: Match Interfold's guarantee surface, not its proof granularity. Prove the same security-critical objects, especially smudging-noise shares, but batch/fold them with PVTHFHE-native lattice machinery so the fast path does not pay a naive 2× proof cost.

---

## Context

An applied cryptographer familiar with The Interfold's PVSS implementation raised these concerns:

1. The current PVTHFHE NIZK story is unclear: what exactly is being proved?
2. The current proof appears to be a one-shot proof about encrypted shares, not a public DKG transcript proof.
3. The current repo does not fully account for smudging-noise shares, whereas Interfold treats smudging noise as first-class DKG material.
4. In Interfold, proving/sharing smudging noise duplicates substantial work; PVTHFHE's goal is comparable assumptions/guarantees with radically better performance.

This plan resolves that gap by promoting smudging noise from an implementation-side decryption term into committed, shared, and publicly verified PVSS material.

---

## Current Evidence and Comparison Target

### Current PVTHFHE state

Relevant local files:

- `crates/pvthfhe-pvss/src/nizk_share.rs`
  - Current share proof claims BFV share-encryption well-formedness.
  - It is still a local/per-share proof surface, not an end-to-end DKG transcript proof.
- `crates/pvthfhe-pvss/src/nizk_decrypt.rs`
  - Current decryption proof wraps a Cyclo/Ajtai adapter for a relation shaped like `d_i = c · sk_i + e_i` with bounded error.
- `crates/pvthfhe-fhe/src/fhers.rs`
  - `partial_decrypt` samples fresh smudging noise locally using `SIGMA_SMUDGE` and adds it to the decryption-share polynomial.
- `.sisyphus/design/smudging.md`
  - Documents smudging-noise rationale and current treatment.
- `.sisyphus/design/nizk-construction.md`
  - Documents current share/decryption NIZK construction boundaries.
- `.sisyphus/design/proof-boundary.md`
  - Documents current proof boundary and known proof-system assumptions.

Core gap: PVTHFHE currently proves that a decryption share is consistent with some bounded error/noise term. It does **not** yet prove that the smudging-noise term is drawn from committed, PVSS-shared DKG material bound to the original public transcript.

### Current Interfold comparison target

Use the current Interfold monorepo as the reference, not the archived `gnosisguild/pvss` repo.

Primary public references:

- `https://github.com/gnosisguild/enclave/tree/main/circuits`
- `https://github.com/gnosisguild/enclave/blob/main/circuits/README.md`
- `https://github.com/gnosisguild/enclave/blob/main/docs/pages/cryptography.mdx`

Current Interfold circuit map:

| Interfold item | Path | Guarantee role |
| --- | --- | --- |
| C0 `PkBfv` | `circuits/bin/dkg/pk` | Commit to each party's individual BFV public key. |
| C1 `PkGeneration` | `circuits/bin/threshold/pk_generation` | Prove threshold public-key contribution and commit to threshold secret material and smudging material. |
| C2a `SkShareComputation` | `circuits/bin/dkg/sk_share_computation` | Prove Shamir / Reed-Solomon structure for secret-key shares. |
| C2b `ESmShareComputation` | `circuits/bin/dkg/e_sm_share_computation` | Prove Shamir / Reed-Solomon structure for smudging-noise shares. |
| C3 `ShareEncryption` | `circuits/bin/dkg/share_encryption` | Prove BFV encryption of DKG shares under recipient individual BFV keys. |
| C4 `DkgShareDecryption` | `circuits/bin/dkg/share_decryption` | Prove decryption/opening/aggregation of received DKG shares and commitments forwarded to P4. |
| C5 `PkAggregation` | `circuits/bin/threshold/pk_aggregation` | Prove aggregation of honest public-key shares into threshold pk. |
| C6 `ThresholdShareDecryption` | `circuits/bin/threshold/share_decryption` | Prove partial decryption uses committed aggregated `sk` and committed aggregated `e_sm`. |
| C7 `DecryptedSharesAggregation` | `circuits/bin/threshold/decrypted_shares_aggregation` | Prove Lagrange combination, CRT reconstruction, and decoding. |

Interfold's important distinguishing guarantee for this plan: smudging noise (`e_sm`) is a first-class committed, shared, and proved object from DKG through threshold decryption.

---

## Target Security Statement

After this plan, PVTHFHE should support the following end-to-end public statement for a session:

```text
Given a public DKG transcript root, an honest/accepted participant set, an aggregated threshold public key, an evaluated BFV ciphertext, and a claimed plaintext:

1. Every accepted participant's threshold secret contribution and smudging-noise contribution were committed.
2. Secret-key shares and smudging-noise shares were Shamir/RS-valid.
3. Encrypted DKG shares encrypt the committed plaintext shares under the recipients' committed individual BFV keys.
4. Each party's aggregated secret-key share and aggregated smudging-noise share are committed outputs of DKG.
5. Each threshold decryption share uses exactly the committed aggregated secret-key share and a committed/fresh smudging-noise share/slot.
6. Final plaintext is the result of combining enough valid threshold decryption shares and decoding correctly.
```

The intended relationship to Interfold is:

```text
Same objects verified; different proof architecture.

Interfold: separate C2a/C2b and repeated C3/C4-style circuits.
PVTHFHE target: batched two-track lattice statements + folding/compression.
```

---

## Non-Goals

- Do not copy Interfold's Noir circuits wholesale.
- Do not abandon the locked `gnosisguild/fhe.rs` backend decision unless a later plan explicitly changes the backend.
- Do not replace PVTHFHE's folding/compression strategy with Interfold's recursive aggregation design unless benchmarks force that choice.
- Do not claim distributional proof of Gaussian sampling unless explicitly implemented. Bounded committed smudging material is the first target; distributional sampling guarantees require a separate proof or a Fiat-Shamir/VRF-derived sampler design.
- Do not delete and recreate stub files. Replace stubs in place per repo protocol.

---

## Architecture

### Current simplified architecture

```text
PVSS share path:
  secret -> Shamir share -> BFV encrypt to recipient -> local share proof

Threshold decryption path:
  partial_decrypt samples fresh local smudging noise
  proof shows d_i = c · sk_i + bounded_error
```

### Target architecture

```text
Two-track DKG transcript:
  track 1: threshold secret-key material        sk
  track 2: smudging-noise material             e_sm

For each dealer i and recipient j:
  sk_i        -> Shamir sk_share[i][j]      -> BFV encryption -> proof
  e_sm_i[k]   -> Shamir e_sm_share[i][j][k] -> BFV encryption -> proof

For each recipient j after DKG:
  aggregate received sk shares      -> sk_agg_share[j]      -> commitment
  aggregate received e_sm shares    -> e_sm_agg_share[j][k] -> commitment

For each threshold decryption:
  d_j = c0 + c1 · sk_agg_share[j] + e_sm_agg_share[j][slot] + quotient terms
  proof binds d_j to DKG sk/e_sm commitments and ciphertext hash
```

### Performance principle

Interfold's current public circuit model proves `sk` and `e_sm` as parallel tracks. The naive implementation duplicates the expensive share-computation/share-encryption path.

PVTHFHE should instead implement a batched two-track relation:

```text
One proof/folded instance proves, for a party or batch:
  - sk shares are Shamir/RS-valid
  - e_sm shares are Shamir/RS-valid
  - encrypted sk shares match sk-share commitments
  - encrypted e_sm shares match e_sm-share commitments
  - all BFV encryption witnesses satisfy bounds
  - all commitments are linked to the same transcript root
```

Target overhead:

- two-track DKG prover cost ≤ 1.5× current one-track PVTHFHE path;
- verifier/on-chain cost remains O(polylog n) or constant after folding/compression;
- per-party work remains O(n) or better for DKG share publication, with aggregation/folding preserving the repo's verifier-cost thesis.

---

## DAG Batches

```text
Batch A: Spec and threat-model alignment
  └─> Freezes Interfold-equivalence target and exact PVTHFHE statements.

Batch B: Witnessable BFV encryption/decryption primitives
  └─> Makes proof witnesses real instead of opaque backend bytes.

Batch C: Two-track DKG transcript and wire types
  └─> Adds first-class sk/e_sm commitments, shares, ciphertexts, and slots.

Batch D: Real share-encryption proof replacement
  └─> Replaces local placeholder proof with batched BFV encryption/share proof.

Batch E: Share-computation and DKG aggregation proof
  └─> Proves Shamir/RS validity and aggregates sk/e_sm shares to DKG anchors.

Batch F: C6-equivalent threshold decryption proof
  └─> Binds partial decryption to committed sk and committed e_sm slot.

Batch G: C7-equivalent final aggregation proof
  └─> Proves participant selection, Lagrange, CRT, and decode.

Batch H: Folding/compression/on-chain anchor linkage
  └─> Preserves PVTHFHE verifier-cost target.

Batch I: Benchmark and security-proof closure
  └─> Demonstrates comparable guarantees with lower practical cost.
```

---

## Batch A — Spec and Threat-Model Alignment

### A.1 — Add Interfold equivalence matrix

- [x] **Doc**: `.sisyphus/design/interfold-equivalence.md`
- [x] **Content**: Map PVTHFHE target statements to Interfold C0-C7 using current `gnosisguild/enclave/main/circuits` paths.
- [x] **Must include**:
  - Current Interfold monorepo commit hash used for comparison.
  - Explicit note that archived `gnosisguild/pvss` is historical only.
  - Table of PVTHFHE local modules that currently implement or approximate each relation.
- [x] **GATE**: Every target guarantee has one of: `implemented`, `partial`, `missing`, or `deferred-with-rationale`.

### A.2 — Update threat model for smudging shares

- [x] **Doc**: `.sisyphus/design/threat-model-v1.md`
- [x] **Change**: Add adversarial cases:
  - malicious party uses fresh uncommitted smudging noise;
  - party reuses smudging slot across decryptions;
  - party substitutes `e_sm` share from another session/ciphertext;
  - aggregator mixes DKG anchors from one session with decryption proof from another.
- [x] **GATE**: Threat model states the target accepted behavior for each case.

### A.3 — Freeze target relations

- [x] **Doc**: `.sisyphus/design/nizk-construction.md`
- [x] **Change**: Add target relation names:
  - `R-share-encrypt-batched-sk-esm`
  - `R-share-computation-batched-sk-esm`
  - `R-dkg-aggregate-sk-esm`
  - `R-threshold-decrypt-with-committed-smudge`
  - `R-decrypt-aggregate-final`
- [x] **GATE**: Relations identify public inputs, private witnesses, commitments, and domain separators.

---

## Batch B — Witnessable BFV Encryption/Decryption Primitives

### B.1 — Add explicit BFV encryption witness type

- [x] **Files**: `crates/pvthfhe-fhe`, `crates/pvthfhe-types`
- [x] **RED**: Test proves current public encryption API cannot return `u/e0/e1/quotient/message` witnesses needed by the proof layer.
- [x] **GREEN**: Add an internal/private API that returns a structured encryption witness:
  - plaintext polynomial/message representation;
  - encryption randomness polynomial `u`;
  - error polynomials `e0`, `e1`;
  - quotient/reduction polynomials needed by the target relation;
  - ciphertext bytes and canonical polynomial decomposition.
- [x] **Security**: Witness type must zeroize on drop and must not implement leaking `Debug`.
- [x] **GATE**: Existing public encryption API remains unchanged for normal callers.

### B.2 — Add explicit decryption-share witness type

- [x] **Files**: `crates/pvthfhe-fhe`, `crates/pvthfhe-types`
- [x] **RED**: Test shows current `partial_decrypt` only returns bytes and does not expose quotient terms or committed `e_sm` witness.
- [x] **GREEN**: Add internal threshold-decryption witness with:
  - `ct0`, `ct1` polynomial decomposition;
  - aggregated `sk` share polynomial;
  - aggregated `e_sm` share polynomial/slot;
  - quotient/reduction polynomials;
  - resulting decryption-share polynomial and canonical bytes.
- [x] **GATE**: No fresh local smudging noise is used in the proof-producing path once committed `e_sm` is available.

### B.3 — Separate legacy/local smudging from committed-smudge mode

- [x] **Files**: `crates/pvthfhe-fhe/src/fhers.rs`, `crates/pvthfhe-pvss`
- [x] **Change**: Make current fresh local smudging mode explicit as `legacy_local_smudge` or equivalent internal compatibility path.
- [x] **RED**: Test asserts committed-smudge mode rejects calls that do not supply an `e_sm` slot witness.
- [x] **GATE**: Production/demo path can be configured to require committed-smudge mode.

---

## Batch C — Two-Track DKG Transcript and Wire Types

### C.1 — Extend transcript model with sk/e_sm tracks

- [ ] **Files**: `crates/pvthfhe-keygen-spec/src/lib.rs`, `crates/pvthfhe-types`, wire crates as needed.
- [ ] **RED**: Serialization roundtrip test for old one-track transcript fails to represent `e_sm` commitments.
- [ ] **GREEN**: Add two-track structures:
  - `SkContributionCommitment`
  - `ESmContributionCommitment`
  - `SkShareCommitment`
  - `ESmShareCommitment`
  - `AggregatedSkShareCommitment`
  - `AggregatedESmShareCommitment`
  - `SmudgeSlotId`
  - `DkgAnchorSet`
- [ ] **GATE**: Wire version bumped or variant-tagged without breaking decode errors.

### C.2 — Add smudge-slot policy

- [ ] **Files**: `crates/pvthfhe-keygen-spec`, `.sisyphus/design/smudging.md`
- [ ] **Change**: Define one of:
  - single-decryption E3 policy: one `e_sm` slot per session/ciphertext;
  - multi-decryption policy: bounded slot vector generated during DKG.
- [ ] **Recommendation**: Start with bounded slot vector of configurable size, with a strict no-reuse registry.
- [ ] **RED**: Slot reuse test must fail before implementation.
- [ ] **GATE**: Slot id is bound to `(session_id, epoch, ciphertext_hash, decrypt_round)` or a documented equivalent.

### C.3 — Add transcript root and anchor binding

- [ ] **Files**: `crates/pvthfhe-pvss`, `crates/pvthfhe-keygen-spec`, `contracts` if anchor is on-chain.
- [ ] **RED**: Test mixing DKG anchors from session A with decryption proof from session B is accepted today or unrepresentable.
- [ ] **GREEN**: DKG root includes:
  - participant set hash;
  - individual BFV pk commitments;
  - threshold pk contribution commitments;
  - `sk_agg_commits[]`;
  - `esm_agg_commits[]`;
  - smudge-slot policy;
  - parameter digest.
- [ ] **GATE**: Decryption statement must include or derive this DKG root.

---

## Batch D — Real Batched Share-Encryption Proof

### D.1 — Replace share-encryption placeholder with explicit BFV relation

- [ ] **File**: `crates/pvthfhe-pvss/src/nizk_share.rs`
- [ ] **RED**: A proof for ciphertext encrypting one share but committing to another must fail.
- [ ] **GREEN**: Prove/verify relation:
  - ciphertext is BFV encryption of the committed share under committed recipient pk;
  - plaintext/share bytes decode to bounded ring representation;
  - encryption randomness/noise are bounded;
  - quotient terms satisfy BFV modular equations;
  - statement binds session, dealer, recipient, params, transcript root.
- [ ] **GATE**: Verifier no longer relies on hash-only binding as the primary consistency check.

### D.2 — Generalize to batched sk/e_sm share encryption

- [ ] **Files**: `crates/pvthfhe-pvss/src/nizk_share.rs`, proof schema/types.
- [ ] **RED**: Tampering only the `e_sm` encrypted share while leaving `sk` valid must fail.
- [ ] **GREEN**: One batched proof can cover both:
  - `sk_share[i][j]` encryption;
  - `e_sm_share[i][j][slot_or_batch]` encryption.
- [ ] **GATE**: Batching must preserve independent commitments for `sk` and `e_sm` tracks.

### D.3 — Domain separation and replay rejection

- [ ] **Files**: `crates/pvthfhe-domain-tags`, `crates/pvthfhe-pvss`
- [ ] **RED**: Cross-use of a proof from `sk` track as `e_sm` track must fail.
- [ ] **GREEN**: Add domain tags for:
  - batched DKG share encryption;
  - `sk` track;
  - `e_sm` track;
  - smudge slot batch;
  - transcript-root binding.
- [ ] **GATE**: Existing cross-session replay tests still pass.

---

## Batch E — Share-Computation and DKG Aggregation Proof

### E.1 — Add batched Shamir/RS share-computation relation

- [ ] **Files**: `crates/pvthfhe-pvss`, `crates/pvthfhe-nizk`, `crates/pvthfhe-cyclo` as appropriate.
- [ ] **RED**: Non-low-degree/tampered share vector passes current path or is unproved.
- [ ] **GREEN**: Prove batched relation:
  - `sk` shares are evaluations of a degree-`t` polynomial with correct secret commitment;
  - `e_sm` shares are evaluations of degree-`t` polynomials/slots with correct smudge commitment;
  - Reed-Solomon parity or equivalent Shamir validity check holds;
  - coefficient bounds hold.
- [ ] **GATE**: Relation is foldable as a PVTHFHE instance.

### E.2 — Add DKG share decryption/aggregation proof

- [ ] **Files**: `crates/pvthfhe-pvss`, `crates/pvthfhe-nizk`
- [ ] **RED**: Recipient aggregate commitment can be inconsistent with decrypted DKG shares.
- [ ] **GREEN**: Prove recipient-side aggregation:
  - encrypted shares decrypt to values whose commitments match C/D outputs;
  - aggregate `sk` share is sum over accepted dealers;
  - aggregate `e_sm` share/slot is sum over accepted dealers;
  - outputs are `sk_agg_commit[j]` and `esm_agg_commit[j][slot]`.
- [ ] **GATE**: DKG anchor set stores these commitments as public outputs.

### E.3 — Honest/accepted set binding

- [ ] **Files**: `crates/pvthfhe-aggregator`, `contracts` if applicable.
- [ ] **RED**: Aggregator can omit a valid participant or include a failed participant without changing anchor semantics.
- [ ] **GREEN**: Accepted set is explicitly hashed and bound into DKG root and all aggregate commitments.
- [ ] **GATE**: Public verifier can determine the exact accepted set used by C5/decryption.

---

## Batch F — C6-Equivalent Threshold Decryption with Committed Smudging

### F.1 — Change decryption relation to committed-smudge form

- [ ] **File**: `crates/pvthfhe-pvss/src/nizk_decrypt.rs`
- [ ] **RED**: Proof using fresh local smudging noise instead of committed `e_sm` is accepted today or untested.
- [ ] **GREEN**: Prove relation:
  ```text
  d_j = c0 + c1 · sk_agg_share[j] + e_sm_agg_share[j][slot] + quotient terms
  ```
  with public checks:
  - `commit(sk_agg_share[j]) == DKG.sk_agg_commits[j]`;
  - `commit(e_sm_agg_share[j][slot]) == DKG.esm_agg_commits[j][slot]`;
  - ciphertext hash matches statement;
  - slot id is fresh and bound to decrypt round;
  - all bounds hold.
- [ ] **GATE**: Decryption proof cannot be generated in committed-smudge mode without an `e_sm` witness.

### F.2 — Add smudge-slot freshness enforcement

- [ ] **Files**: `crates/pvthfhe-aggregator`, `contracts`, or session registry equivalent.
- [ ] **RED**: Reusing the same smudge slot for two ciphertexts fails.
- [ ] **GREEN**: Public registry/anchor rejects reused `(session_id, party_id, slot)` for distinct ciphertext/decrypt rounds.
- [ ] **GATE**: Freshness check is part of acceptance, not only a local client convention.

### F.3 — Preserve legacy path only as explicit non-equivalent mode

- [ ] **Files**: `README.md`, `SECURITY.md`, `.sisyphus/design/smudging.md`
- [ ] **Change**: Document that fresh local smudging is not Interfold-equivalent unless accompanied by a distribution/freshness proof.
- [ ] **GATE**: Security docs distinguish `legacy_local_smudge` vs `committed_smudge_pvss`.

---

## Batch G — C7-Equivalent Final Decryption Aggregation

### G.1 — Add final aggregation proof relation

- [ ] **Files**: `crates/pvthfhe-pvss`, `crates/pvthfhe-nizk`, `crates/pvthfhe-aggregator`
- [ ] **RED**: Wrong plaintext with valid-looking partial shares is accepted or unproved.
- [ ] **GREEN**: Prove:
  - at least threshold many valid decryption shares;
  - participant ids are unique and in accepted set;
  - Lagrange coefficients are correct for selected ids;
  - decryption shares combine correctly;
  - CRT reconstruction is correct;
  - plaintext decoding is correct under BFV plaintext modulus.
- [ ] **GATE**: Public verifier can reject wrong plaintext without redoing full BFV aggregation off-chain.

### G.2 — Bind C7 proof to C6 proof set

- [ ] **Files**: `crates/pvthfhe-aggregator`, proof schema/wire crates.
- [ ] **RED**: Aggregator can combine decryption shares from different ciphertexts or sessions.
- [ ] **GREEN**: Final aggregation statement includes:
  - DKG root;
  - ciphertext hash;
  - selected participant ids;
  - decryption-share commitments/proof refs;
  - plaintext hash/message.
- [ ] **GATE**: Mixed-session/ciphertext share aggregation fails.

---

## Batch H — Folding, Compression, and On-Chain/Public Anchor Linkage

### H.1 — Define surfaced anchor values

- [ ] **Files**: `crates/pvthfhe-aggregator`, `crates/pvthfhe-compressor`, `contracts`, docs.
- [ ] **Change**: DKG folded proof surfaces:
  - `dkg_root`;
  - `aggregated_pk_commit`;
  - `participant_set_hash`;
  - `sk_agg_commits_root`;
  - `esm_agg_commits_root`;
  - `smudge_slot_policy_hash`.
- [ ] **Change**: Decryption folded proof surfaces:
  - `dkg_root`;
  - `ciphertext_hash`;
  - `expected_sk_commits_root`;
  - `expected_esm_commits_root`;
  - `slot_id/decrypt_round`;
  - `plaintext_hash`.
- [ ] **GATE**: Public verifier checks equality of DKG/decryption anchors.

### H.2 — Fold batched two-track instances

- [ ] **Files**: `crates/pvthfhe-cyclo`, `crates/pvthfhe-aggregator`
- [ ] **RED**: Existing folding relation cannot encode both `sk` and `e_sm` commitments independently.
- [ ] **GREEN**: Extend fold instance encoding to include multi-track commitments and norms:
  - `sk` witness commitment;
  - `e_sm` witness commitment;
  - encryption witness commitment(s);
  - per-track norm bounds;
  - instance count/party binding.
- [ ] **GATE**: Fold verification rejects tampered `e_sm` subinstance while `sk` remains valid.

### H.3 — Contract/public verifier anchor checks

- [ ] **Files**: `contracts`, `crates/pvthfhe-offchain-verifier`
- [ ] **RED**: DKG proof and decryption proof with mismatched `esm_agg_commits_root` must fail.
- [ ] **GREEN**: Verifier stores/loads DKG anchors and checks decryption anchors before accepting plaintext.
- [ ] **GATE**: On-chain or off-chain public verifier performs only compact anchor checks plus proof verification.

---

## Batch I — Benchmarks and Security-Proof Closure

### I.1 — Benchmark one-track vs two-track PVTHFHE

- [ ] **Files**: `bench/`, `bench/results/`
- [ ] **Run**: Benchmark current one-track path and new two-track committed-smudge path for representative `n` values.
- [ ] **Metrics**:
  - DKG prover time per party;
  - decryption proof time per party;
  - fold/compression time;
  - verifier time;
  - proof/wire size;
  - peak memory.
- [ ] **GATE**: Two-track overhead is measured and explained. Target is ≤ 1.5× one-track PVTHFHE for DKG proof-producing path.

### I.2 — Compare against Interfold cost model

- [ ] **Doc**: `bench/results/interfold-equivalent-pvss-comparison.md`
- [ ] **Content**:
  - Interfold C0-C7 proof-count model from current monorepo docs;
  - PVTHFHE batched proof-count model;
  - concrete measured local costs where available;
  - caveats about hardware/toolchain/backend differences.
- [ ] **GATE**: Claim is framed as comparable guarantee surface with measured PVTHFHE performance, not an apples-to-apples audited proof-system equivalence.

### I.3 — Security proof note

- [ ] **Doc**: `docs/security-proofs/interfold-equivalent-pvss.md`
- [ ] **Content**:
  - assumptions: RLWE/BFV secrecy, binding commitments, proof soundness, Fiat-Shamir model, threshold corruption bound;
  - theorem sketch from DKG transcript validity to decryption-share soundness;
  - smudge-slot one-time-use lemma;
  - explicit limitations around distributional sampling of `e_sm` if only boundedness is proved.
- [ ] **GATE**: Security note states exactly what is now comparable to Interfold and what remains different.

---

## Required RED Test Inventory

Implementers must write RED tests before GREEN changes, per repo TDD policy.

Minimum negative tests:

- [ ] Tampered `sk_share` commitment is rejected.
- [ ] Tampered `e_sm_share` commitment is rejected.
- [ ] Ciphertext encrypting wrong `sk_share` is rejected.
- [ ] Ciphertext encrypting wrong `e_sm_share` is rejected.
- [ ] Cross-track replay (`sk` proof reused for `e_sm`) is rejected.
- [ ] Cross-session replay is rejected.
- [ ] Decryption proof using fresh local noise instead of committed `e_sm` is rejected.
- [ ] Reused smudge slot is rejected.
- [ ] Decryption proof with wrong ciphertext hash is rejected.
- [ ] Decryption proof with wrong DKG root is rejected.
- [ ] Duplicate participant ids in final aggregation are rejected.
- [ ] Participant outside accepted set is rejected.
- [ ] Wrong Lagrange coefficients are rejected.
- [ ] Wrong CRT reconstruction is rejected.
- [ ] Wrong plaintext decode is rejected.
- [ ] Folded proof with tampered `e_sm` subinstance is rejected.
- [ ] DKG/decryption anchor mismatch is rejected by public verifier.

---

## Acceptance Criteria

- [ ] Current Interfold monorepo circuit target is pinned and documented.
- [ ] PVTHFHE has first-class committed smudging-noise DKG material.
- [ ] PVTHFHE DKG transcript includes both `sk` and `e_sm` tracks.
- [ ] Share encryption proof proves real BFV encryption relation with explicit witnesses, not only hash binding.
- [ ] Batched share proof covers both `sk` and `e_sm` shares or an equivalent folded batch with documented soundness.
- [ ] Threshold decryption proof uses committed `e_sm` share/slot, not fresh uncommitted local smudging.
- [ ] Smudge-slot freshness is publicly enforceable.
- [ ] Final decryption aggregation proof verifies participant ids, Lagrange interpolation, CRT reconstruction, and plaintext decoding.
- [ ] DKG folded proof and decryption folded proof surface matching anchor values.
- [ ] Public verifier rejects mismatched `sk`/`e_sm` anchors.
- [ ] Security documentation clearly states comparable assumptions and remaining differences vs Interfold.
- [ ] Benchmarks quantify overhead and show whether PVTHFHE keeps the intended performance advantage.
- [ ] All implementation changes follow RED→GREEN→GATE.
- [ ] No new production proof path silently falls back to legacy/local smudging.

---

## Suggested Start-Work Order

1. Start with Batch A. Do not implement cryptography until the exact Interfold-equivalence matrix and target relations are frozen.
2. Then Batch B, because real proof statements need explicit BFV witnesses.
3. Then Batch C, because wire/transcript objects determine public statement shape.
4. Then Batch D/E in parallel if useful: share encryption and share computation are separable once transcript types are fixed.
5. Then Batch F/G for decryption and final aggregation.
6. Then Batch H/I for folding, public verifier, benchmarks, and security proof closure.

Recommended `start-work` focus for first pass:

```text
Batch A only: freeze Interfold-equivalence matrix, smudging threat model, and target relations.
```

This avoids premature implementation of a relation whose public inputs may still be wrong.
