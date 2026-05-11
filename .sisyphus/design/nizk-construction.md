# R3.0 NIZK Construction Selection

Status: **draft — R3.1/R3.2 construction selected; R3.4 target relations frozen**.

Scope: select the lattice NIZK construction for PVTHFHE share well-formedness
(R3.1) and partial decryption (R3.2), superseding the Cyclo-companion Ajtai D2
NIZK selected at L3 and the current witness-in-envelope placeholder.

Non-scope: implementation, witness-language schema (R3.0a), CRS binding (R3.3),
or plan updates.

---

## Context

PVTHFHE needs zero-knowledge NIZK proofs for two relations:

**R3.1 — share well-formedness.** Each dealer proves knowledge of
`(s_i, {r_ij}_j)` such that, for each recipient `j`:
1. `(u_ij, v_ij)` is a valid BFV encryption of `s_i` under `pk_j` with
   randomness `r_ij`,
2. `‖s_i‖_∞ ≤ B_s` (short secret bound),
3. `‖r_ij‖_∞ ≤ B_r` (short randomness bound), and
4. `C_i = SHA256(session_id ‖ i_le ‖ s_i_be)` (D2 hash binding).

Citation: `.sisyphus/design/spec-pvss.md` lines 16–29.

**R3.2 — partial decryption.** Each decrypting party proves knowledge of
`sk_i` such that:
1. `d_i = c·sk_i + e_i mod q` with `‖e_i‖_∞ ≤ B_e`, and
2. `(party_id, pk_i_hash)` is bound under `dkg_root`.

Citation: `.sisyphus/design/spec-decrypt.md` §Per-party algorithm;
`.sisyphus/design/spec-real-p2p3.md` lines 70–112.

The current codebase has two NIZK paths, both inadequate:

- **`crates/pvthfhe-pvss/src/nizk_share.rs`**: witness-in-envelope
  antipattern — the proof body contains `share_bytes` and `encryption_randomness`
  in cleartext. Not zero-knowledge. Verified by hash recomputation rather than
  a lattice relation check.

  Citation: `nizk_share.rs` lines 1–9 document this as "research prototype —
  conditional soundness only"; line 384 encode_opened_proof serializes witness
  material; `.sisyphus/notepads/pvthfhe-remediation/decisions.md` lines 183–184
  quarantine the `WitnessLeakingProofBytesV0` type.

- **`crates/pvthfhe-nizk/src/adapter.rs` (CycloNizkAdapter)**: the Cyclo-companion
  Ajtai D2 NIZK selected at L3. Implements a sigma protocol over `R_{q_commit}`
  with Ajtai commitment, Fiat-Shamir transform, and SHA-256 hash binding. Has a
  real verifier that checks lattice relations. However, its soundness is
  conditional on Cyclo Theorem 3 + Lemma 9 (the invertibility heuristic),
  which was struck at R3.0 per the oracle.

  Citation: `ccs_instance_id` derivation at `adapter.rs` lines 275–285;
  `sigma::prove` at lines 103–110; `sigma::verify` at lines 186–191; Lemma 9
  downgraded to Conjecture 9 at `docs/security-proofs/lemma9.md` lines 3–26.

The plan (`.sisyphus/plans/pvthfhe-remediation.md` lines 273–280) reorders R3.0
to: **Greco primary, MPC-in-the-head fallback, Cyclo Lemma 9 struck**. The
greco primary choice locks on a production NIZK with formal soundness proof for
BFV well-formedness; MPCitH is a generic backup without exotic lattice
assumptions; Cyclo Lemma 9 is eliminated because its conditional soundness
cannot be closed within v1 budget.

Citation: plan lines 273–280 (oracle-reordered 2026-05-08):
"1. **Greco** (primary): production lattice NIZK with formal soundness proof for
BFV well-formedness; published reference implementation. 2. **ZKBoo /
MPC-in-the-head** (fallback): generic NIZK over the BFV decryption + share-WF
relation; higher proof size but no exotic assumptions. 3. ~~Cyclo Lemma 9 with
conditional-soundness argument~~ — **STRUCK** (oracle): conditional soundness
for production parameters not proven and unlikely within v1 budget."

---

## Candidates

### Candidate 1 — Greco (Primary)

#### Summary

Greco is a lattice-based NIZK system from the `gnosisguild/fhe.rs` ecosystem
designed for BFV ciphertext and share well-formedness. It provides:
- A sigma protocol with rejection sampling for the RLWE decryption relation,
- Short witness range proofs,
- A published reference implementation compatible with fhe.rs BFV key material,
- Formal soundness reduction to Module-SIS (not conditional on unproven
  heuristics like Cyclo Lemma 9).

#### Protocol sketch

For the share-WF relation (R3.1):
1. Prover constructs a witness `(s_i, {r_ij}_j)` over `R_q`.
2. Prover samples masking values, computes a lattice commitment, and applies
   Fiat-Shamir to produce a non-interactive proof.
3. The proof asserts: (a) BFV encryption correctness `(u_ij, v_ij) = Enc(pk_j, s_i; r_ij)`,
   (b) `‖s_i‖_∞ ≤ B_s` and `‖r_ij‖_∞ ≤ B_r`, (c) the D2 hash binding
   `C_i = SHA256(...)`.

For the partial-decryption relation (R3.2):
1. Prover constructs witness `sk_i` from the party's threshold secret share.
2. The sigma protocol proves `d_i = c·sk_i + e_i mod q` with `‖e_i‖_∞ ≤ B_e`.
3. The proof binds `(party_id, pk_i_hash)` to `dkg_root` via the Merkle
   membership path defined in `spec-keygen.md`.

#### Soundness model

Module-SIS over the commitment ring, ROM via Fiat-Shamir. Formal reduction
published in the Greco paper; T2 extractor obligation satisfied by the Greco
extraction argument rather than the Cyclo T3 ∘ T5 skeleton.

Citation: `.sisyphus/design/assumptions-ledger.md` A-LATTICE-1 (M-SIS over
`R_{q_commit}`), A-LATTICE-2 (MLWE for RLWE secret/error).

#### ZK property

Honest-verifier zero-knowledge via rejection sampling on the response. The
proof envelope does NOT contain witness material — the verifier checks the
lattice relation and the hash binding, not a hash-of-witness.

#### Per-party cost

For N=8192, `log₂q≈174` (3 RNS limbs):
- Prover: O(N) ring multiplications per proof; expected O(1) rejection sampling
  trials with standard Lyubashevsky parameters (σ≈11·B).
- Proof size: O(N) coefficients ≈ 4–12 KB (compressed via MSIS aggregation).
- Verifier: O(N) ring operations.

#### fhe.rs compatibility

Greco is published within the `gnosisguild/fhe.rs` ecosystem and operates over
the same `fhe_math::rq::Poly` / BFV key representation as the FHE backend.
No bridge from BN254 scalars needed; no CRT/RNS decomposition mismatch.

Citation: `crates/pvthfhe-fhe/src/fhers.rs` lines 31–40 store BFV polys in
the same representation.

#### Implementation evidence

Published reference implementation assumed as part of `gnosisguild/fhe.rs` or
a companion crate. The plan cites "published reference implementation" —
integration delta is lower than MPCitH: the `RealNizkAdapter` trait (`prove`,
`verify`, `batch_verify`) is a thin wrapper around the Greco prover/verifier.

#### Conditional-soundness story

The R3.0 plan tasks the Greco selection with closing the T2 extraction
obligation that currently lives as a skeleton in the theorem inventory. Under
Greco, the conditional-soundness banner shrinks from "Cyclo T3 ∘ T5 (skeleton)"
to "M-SIS + ROM (published reduction)." The hash binding (T5) remains proved.

### Candidate 2 — MPC-in-the-Head (MPCitH, Fallback)

#### Summary

MPC-in-the-head (ZKBoo lineage: Ishai-Kushilevitz-Ostrovsky-Sahai STOC 2007,
Giacomelli-Madsen-Orlandi CRYPTO 2016, Katz-Kolesnikov-Wang CCS 2019) provides
generic NIZKs: the prover simulates a toy MPC protocol among virtual parties,
commits to the views, opens a random subset on the verifier's challenge, and
argues that the majority view is consistent with the statement.

For PVTHFHE, the circuit being proved is the BFV share-encryption or
decryption-share computation expressed as an arithmetic circuit over a small
field, with the RLWE relation decomposed into local linear operations.

#### Protocol sketch

1. The statement (BFV encryption/decryption correctness, norm bounds) is
   compiled into a Boolean or arithmetic circuit.
2. The prover emulates `M` virtual parties, each simulating a share of the
   computation of the witness.
3. The prover commits to each virtual party's view (via hash trees or Merkle
   commitments).
4. The Fiat-Shamir challenge selects a subset of `M-1` parties to open.
5. The verifier checks: opened party views are consistent with each other and
   with the public statement, and simulate the circuit correctly.

#### Soundness model

Soundness reduces to the collision resistance of the commitment scheme (SHA-256)
and the circuit correctness of the BFV emulation. No lattice-specific hardness
assumptions needed for soundness (RLWE/M-SIS are only needed for the underlying
FHE scheme, not the proof system). This is a different assumption profile than
Greco: soundness is hash-based, not lattice-based.

Model: ROM (hash commitments, FS challenge).

#### ZK property

Computational zero-knowledge: the opened views are simulated using the circuit
simulator; the unopened views are hidden behind the commitment.

#### Per-party cost

- Prover: O(M · |C|) where M is the number of virtual parties (typically 3–5)
  and |C| is the circuit size for the BFV relation. For RLWE with N=8192
  and RNS decomposition, |C| ≈ O(N·L) ≈ 24,576 operations per share.
  Concrete cost is higher than Greco (MPCitH has a multiplicative overhead
  of ~10–100× vs native sigma protocols).
- Proof size: O(|C| · M) bytes. For 3-party MPCitH and a BFV share-WF circuit,
  estimated 50–500 KB per proof — larger than Greco.
- Verifier: O(|C|) circuit operations, slower than Greco's O(N) ring check.

#### fhe.rs compatibility

MPCitH operates on the circuit representation, not directly on fhe.rs objects.
The BFV computations (`Enc`, `Dec`, norm checks) must be compiled into the
MPCitH circuit. This is a generic compilation, not fhe.rs-specific — no
compatibility issue, but no free ride either. The circuit compiler must handle
the specific BFV parameterization (N=8192, 3 RNS limbs, ternary secret, σ=3.19
error).

#### Implementation evidence

MPCitH libraries exist: `ZK-Garage/zkboo`, `Plonky3 MPCitH`, `kobigurk/curdleproofs`
(informal). However, none is pre-integrated with `gnosisguild/fhe.rs`. The
circuit compilation step (BFV → MPCitH circuit) is the main integration cost.

#### Conditional-soundness story

Cleaner than Greco: soundness is hash-based (ROM, collision resistance).
No lattice extraction argument needed for proof soundness. The only lattice
assumptions remain in the underlying FHE (A-LATTICE-2). The T2 theorem
inventory entry changes from "Cyclo T3 ∘ T5 (skeleton)" to "ROM hash-binding +
MPCitH majority soundness."

The trade-off is proof size and prover cost.

### Candidate 3 — Cyclo Lemma 9 (STRUCK)

#### Summary

The Cyclo-companion Ajtai D2 NIZK was selected at L3 (`.sisyphus/research/nizk-selection.md`)
and implemented in `crates/pvthfhe-nizk/src/adapter.rs` (CycloNizkAdapter).
It embeds the per-share NIZK natively in Cyclo's commitment ring `R_{q_commit}`
(φ=256, `q_commit≈2^50`) and relies on Cyclo Theorem 3 knowledge soundness,
which in turn depends on Lemma 9 (the invertibility heuristic for biased ternary
challenges in power-of-two cyclotomics).

Citation: `nizk-selection.md` lines 181–234 (recommendation for Candidate D);
`cyclo-digest.md` §5.5 and §6.5; `lemma9.md` lines 1–26.

#### Why struck

1. **Lemma 9 is conditional, not proved.** As of `lemma9.md` lines 19–26:
   "the following obstacles prevent a complete formal proof ... Lemma 9 is
   downgraded to Conjecture 9." The heuristic assumes the challenge set has
   `κ_nu ≈ 2^{-94}` non-invertible challenge differences. The authors of Cyclo
   themselves note this is heuristic and specific to power-of-two cyclotomics.

2. **The conditional soundness chain is too long for v1.** A-COND-1
   (`.sisyphus/design/assumptions-ledger.md` lines 102–113) chains:
   M-SIS (A-LATTICE-1) → Cyclo T3 (Lemma 9 heuristic) → T5 (SHA-256, proved).
   Each link is conditional; the joint extractor (T2) is a skeleton. Closing
   this chain formally is a research project, not engineering.

3. **The plan's cost estimate is explicit.** "conditional soundness for
   production parameters not proven and unlikely within v1 budget." The R3
   phase (Week 3–10) cannot accommodate a full formal proof of Lemma 9 for
   PVTHFHE parameters.

4. **The existing implementation is real but marked as conditional.**
   `CycloNizkAdapter` at `adapter.rs` lines 65–219 implements a working sigma
   protocol, but its `BACKEND_ID = "cyclo-ajtai-d2-conditional"` (at
   `lib.rs` line 25) advertises the conditional status. The plan requires
   unconditional (or at least proved-conditional) soundness for R3.1/R3.2.

5. **The Cyclo folding crate can be retained** for witness representation, norm
   checks, and R_{q_commit} ring arithmetic, even while the NIZK itself is
   replaced by Greco. The `pvthfhe-cyclo` crate is not struck — only the Cyclo-
   based NIZK soundness path is.

#### Verdict

**STRUCK** as the R3.0 NIZK construction. The existing CycloNizkAdapter and the
Cyclo crate remain as code but are retired from the production NIZK path.
The fold layer (R4) continues to use Cyclo for witness representation; the NIZK
layer (R3) switches to Greco.

---

## Comparison Matrix

| Candidate | Soundness model | ZK | Proof size | Prover cost | Verifier cost | fhe.rs compat | Impl risk |
|---|---|---|---|---|---|---|---|
| **Greco (primary)** | M-SIS + ROM, published reduction, no conditional heuristic | HVZK via rejection sampling | ~4–12 KB | O(N) R_q mults, expected O(1) retries | O(N) ring ops | **Strong** — same `fhe_math::rq` domain | Low — reference impl exists, thin adapter |
| **MPCitH (fallback)** | Hash CR + ROM, generic MPC soundness | Computational ZK (simulatable views) | ~50–500 KB | O(M·\|C\|) where M≈3–5 and \|C\|≈24K ops | O(\|C\|) circuit ops | Medium — requires circuit compilation of BFV ops | Medium — no BFV-specific MPCitH circuit |
| ~~Cyclo Lemma 9~~ | M-SIS + Cyclo T3 + Lemma 9 heuristic (unproven) | Conditional on Cyclo HVZK | N/A (folded) / ~50–60 KB acc | O(a·m) R_q_commit mults, T=10 folds | O(a)=O(13) ring ops | Strong (R_q_commit domain) | Struck — conditional soundness cannot close in v1 |

Cost estimates: `.sisyphus/design/parameters.md` lines 17–36 (N=8192,
log₂q≈174, 3-limb RNS).

---

## Recommendation

**Recommended pending oracle review: Candidate 1 — Greco primary, with
Candidate 2 (MPCitH) as the fallback.**

### Primary rationale

1. **Soundness closure.** Greco provides a published formal soundness reduction
   to Module-SIS with ROM Fiat-Shamir. Unlike Cyclo Lemma 9 (struck), Greco's
   extraction argument does not depend on an unproven invertibility heuristic.
   This satisfies the plan's requirement that R3.1/R3.2 "NIZK soundness ≥2⁻¹²⁸."

2. **fhe.rs ecosystem integration.** Greco is part of the `gnosisguild/fhe.rs`
   ecosystem, same as the FHE backend locked in AGENTS.md F1. This eliminates
   the CRT/RNS representation mismatch that plagues non-native constructions.

   Citation: AGENTS.md Backend Lock; `.sisyphus/design/spec-real-p2p3.md` §4.1
   addendum.

3. **ZK property closes with rejection sampling.** The current
   witness-in-envelope antipattern (`nizk_share.rs` encodes `share_bytes` in
   the proof body) is eliminated: the Greco sigma protocol uses rejection
   sampling on the response, making the proof transcript independent of the
   witness.

4. **Minimum integration delta.** The existing `NizkAdapter` trait in
   `crates/pvthfhe-nizk/src/lib.rs` defines `prove`, `verify`, `batch_verify`.
   The Greco adapter is a thin wrapper; the adapter surface does not change.
   The `CycloNizkAdapter` can be archived and the `RealNizkAdapter` in
   `crates/pvthfhe-fhe/src/real_nizk.rs` re-routed to Greco.

### Fallback trigger

MPCitH becomes the construction if either:

1. **Integration cost exceeds 2 engineer-months.** If Greco's reference
   implementation requires extensive PVTHFHE-specific adaptation (parameter
   bridging, trait mismatch, RNS-to-field decomposition), and the estimate to
   reach a passing `nizk_share_soundness.rs` test exceeds 8 weeks.

2. **Greco soundness proof does not cover PVTHFHE parameters.** If the
   published reduction is specific to a different parameter regime (e.g.,
   different ring degree, different BFV limb count, different secret
   distribution) and extending it requires novel cryptanalysis.

3. **Greco ZK for the composed statement.** If the composed statement
   (BFV encryption correctness + norm bounds + hash binding) cannot be expressed
   in Greco's native witness language without losing ZK or soundness for any
   component.

### Cyclo Lemma 9 disposition

Struck with the following rationale:
- The Lemma 9 heuristic (`κ_nu ≈ 2⁻⁹⁴`) is not formally proved for biased
  ternary challenges in the power-of-two cyclotomic `X²⁵⁶+1`.
- Extending the proof to formal closure exceeds the v1 budget (the plan
  explicitly dismisses it as "unlikely within v1 budget").
- The `pvthfhe-cyclo` crate is NOT struck — its ring arithmetic (`RqPoly`),
  norm checks (`range_check.rs`), CCS encoding (`ccs_encode.rs`), and folding
  scaffold (`fold.rs`) remain in use for R4 witness representation and
  aggregation. Only the NIZK soundness path through Cyclo Theorem 3 + Lemma 9
  is retired.
- The conditional-soundness banner for P1 in `SECURITY.md` §P1 is updated from
  "Cyclo Theorem 3 + Lemma 9" to "Greco M-SIS reduction + SHA-256 binding."

---

## Integration Sketch

### Files changed (R3.1)

| File | Change | Reason |
|---|---|---|
| `crates/pvthfhe-pvss/src/nizk_share.rs` | Rewrite. Remove witness-in-envelope encoding. Replace hash-of-witness verifier with Greco relation check. `ProofEnvelope` drops `witness` field. | Fixes F4 (share-WF NIZK). Closes ZK antipattern. |
| `crates/pvthfhe-types/src/lib.rs` | Extend newtypes. Add `GrecoProof`, `GrecoStatement`, `GrecoWitness` (or use adapter-generic types). | R3.0a witness-language schema continuity with R4/R5. |
| `crates/pvthfhe-nizk/src/adapter.rs` | Rewrite. Replace `CycloNizkAdapter` with `GrecoNizkAdapter`. Keep the same `NizkAdapter` trait surface. | Supersedes Cyclo-companion NIZK. |
| `crates/pvthfhe-nizk/src/lib.rs` | Update `BACKEND_ID` to `"greco-bfv-wf-v1"`. Update conditional-soundness banners. | Reflects new backend identity. |
| `crates/pvthfhe-fhe/src/real_nizk.rs` | Re-route `RealNizkAdapter` to `GrecoNizkAdapter`. Remove Cyclo pass-through. | Production path uses Greco. |

### Files changed (R3.2)

| File | Change | Reason |
|---|---|---|
| `crates/pvthfhe-pvss/src/nizk_decrypt.rs` | Rewrite. Remove `derive_secret_share`. Prove `d_i = c·sk_i + e_i` with Greco. Bind `(party_id, pk_i_hash)` to `dkg_root` via membership path. | Fixes F5, F58. |
| `crates/pvthfhe-aggregator/src/decrypt/mod.rs` | Replace `nizk[0] == 1` stub with real `verify_partial` calling `GrecoNizkAdapter::verify`. Replace `pk_i_hash: [0u8;32]` with real `pk_i` commitment. | Fixes F5 stub. |

### Files NOT changed

| File/Folder | Reason |
|---|---|
| `crates/pvthfhe-cyclo/` | Retained. Ring arithmetic, norm checks, CCS encoding remain in use for R4 witness representation. Only the NIZK path through Cyclo is retired. |
| `crates/pvthfhe-nizk/src/ajtai.rs` | Retained. Ajtai commitment scheme may be used as a commitment primitive under Greco (Greco's commitment layer can reuse `R_{q_commit}` parameters). |
| `crates/pvthfhe-nizk/src/sigma.rs` | Retained or replaced based on Greco API. If Greco exposes its own sigma, this file is archived. If Greco is a commitment-compatible drop-in, this file becomes the adapter glue. |
| `crates/pvthfhe-nizk/src/fiat_shamir.rs` | Retained. Fiat-Shamir transcript is protocol-level plumbing; Greco uses it. Domain separator tags updated for `"greco-bfv-wf-v1"`. |
| `crates/pvthfhe-nizk/src/hash_bridge.rs` | Retained. SHA-256 hash binding (T5 proved) is outside the lattice proof; Greco checks this via the same D2 pattern. |

### Orphaned code

| Code | Disposition |
|---|---|
| `CycloNizkAdapter` (adapter.rs lines 63–219) | Archive: keep in git history; remove from active use. Add a `#[deprecated]` annotation pointing to `GrecoNizkAdapter`. |
| `CcsPShareInstance` (cyclo/src/lib.rs) | Retained for R4 aggregation. Not orphaned. |
| `CycloAccumulator` (cyclo/src/lib.rs) | Retained for R4 aggregation. Not orphaned. |
| Old `ProofPayload` (real_nizk.rs) | Remove. The Greco proof envelope replaces it. |

---

## Open Questions / Risks

1. **Greco reference implementation availability.** The plan asserts Greco has
   a "published reference implementation." If this implementation is not yet
   released at the time R3.1 GREEN work begins, the fallback trigger must be
   evaluated before proceeding.

2. **Greco parameter bridge.** PVTHFHE uses N=8192, `log₂q≈174` (3 RNS limbs).
   If Greco's reference parameters assume a different BFV instantiation (e.g.,
   different RNS limb count or ring degree), the bridge between fhe.rs BFV
   parameters and Greco proof parameters must be designed and soundness-
   verified. This is the primary "integration cost" metric for the fallback
   trigger.

3. **Composed statement ZK.** The share-WF proof composes four sub-statements
   (BFV encryption, secret bound, randomness bound, hash binding). Greco must
   either support composition natively or PVTHFHE must run separate proofs and
   bind them with a transcript. The latter approach may leak structure.

4. **MPCitH circuit compilation gap.** The fallback requires compiling BFV
   encryption and decryption operations into a circuit over a small field (the
   MPCitH internal field). The RNS decomposition of `R_q` into 3 limbs and the
   NTT polynomial multiplication must be emulated in-circuit. No existing
   library performs this compilation for fhe.rs BFV specifically.

5. **Cyclo crate cleanup scope.** The `CycloNizkAdapter` should be deprecated
   but not deleted (git history preservation). The `CycloAdapter` trait in
   `crates/pvthfhe-cyclo/src/lib.rs` continues to serve the R4 folding layer.
   During R3.1 GREEN, ensure no accidental breakage of R4's dependency on the
   Cyclo crate's ring arithmetic and norm checking.

6. **Conditional-soundness banner update.** After Greco migration, the P1
   banner in `SECURITY.md` must be reworded from "Cyclo Theorem 3 + Lemma 9"
   to "Greco M-SIS reduction + SHA-256 binding." The T2 entry in
   `theorem-inventory.md` must be updated to reflect the Greco extraction
   argument rather than the Cyclo T3 ∘ T5 skeleton.

7. **Fallback trigger timing.** The decision to switch to MPCitH should be made
   no later than Week 6 of the R3 phase (the R3.1 GREEN midpoint). If Greco
   integration is not demonstrably working by Week 6, activate the fallback.

---

## R3.4 — Interfold-Equivalent Target Relations

These five relations collectively capture the guarantee surface of Interfold's C0-C7 circuit suite (see `.sisyphus/plans/interfold-equivalent-pvss.md` §Current Interfold comparison target) in a batched, folded PVTHFHE architecture. The two-track design treats secret-key material (`sk`) and smudging-noise material (`e_sm`) as parallel, independently committed channels that share BFV ciphertext space and Shamir structure. Each channel follows the same lifecycle: share encryption, share computation, DKG aggregation, threshold decryption, and final aggregation. Because the tracks are structurally identical, a single batched lattice NIZK proves both tracks simultaneously. Folding then compresses batches of these proofs without duplicating the expensive BFV prover work. The canonical End-to-End Public Statement (`.sisyphus/plans/interfold-equivalent-pvss.md` lines 76-85) decomposes into these five relations, each inheriting its security guarantees from the NIZK construction selected at R3.0 (Greco primary, MPCitH fallback). Together these relations implement the full lifecycle from dealer share publication through final plaintext recovery under publicly verifiable anchors.

### R3.4.1 — R-share-encrypt-batched-sk-esm

**What it proves**: One batched proof covers BFV encryption of both `sk_share` and `e_sm_share` from a dealer to a single recipient. The proof establishes that `(ciphertext_u, ciphertext_v)` is a valid BFV encryption of the committed `sk_share` under `recipient_pk_commitment`, that the same ciphertext simultaneously encodes the committed `e_sm_share` via batched plaintext encoding, and that all witness polynomials satisfy their respective norm bounds. The statement binds to session, epoch, dealer index, and recipient index for replay rejection.

**Public inputs**:
- `session_id: [u8; 32]` — session identifier
- `dealer_index: u32` — dealer party index
- `recipient_index: u32` — recipient party index
- `recipient_pk_commitment: Commitment` — commitment to recipient's individual BFV pk
- `ciphertext_u: RqPoly` — BFV ciphertext component u
- `ciphertext_v: RqPoly` — BFV ciphertext component v
- `sk_share_commitment: Commitment` — commitment to the sk share plaintext
- `e_sm_share_commitment: Commitment` — commitment to the e_sm share plaintext
- `epoch: u64` — protocol epoch for replay prevention

**Private witnesses**:
- `sk_share_bytes: [u8]` — serialized sk share plaintext
- `e_sm_share_bytes: [u8]` — serialized e_sm share plaintext
- `u_sk: RqPoly` — BFV encryption randomness (sk track)
- `u_esm: RqPoly` — BFV encryption randomness (e_sm track)
- `e0_sk: RqPoly` — BFV error term e0 (sk track)
- `e0_esm: RqPoly` — BFV error term e0 (e_sm track)
- `e1_sk: RqPoly` — BFV error term e1 (sk track)
- `e1_esm: RqPoly` — BFV error term e1 (e_sm track)
- `quotients: Vec<RqPoly>` — quotient/reduction polynomials

**Commitment bindings**:
1. `recipient_pk_commitment` opens to the recipient's individual BFV public key, established at DKG registration (Interfold C0-equivalent).
2. `sk_share_commitment` opens to `sk_share_bytes` interpreted as a bounded ring element.
3. `e_sm_share_commitment` opens to `e_sm_share_bytes` interpreted as a bounded ring element.

**Domain separator**: `"pvthfhe-R-share-encrypt-batched-sk-esm-v1"`

### R3.4.2 — R-share-computation-batched-sk-esm

**What it proves**: Both `sk` and `e_sm` share vectors are valid Shamir/Reed-Solomon evaluations of degree-`t` polynomials whose secret coefficients open to the dealer's committed contribution. The proof establishes that each `sk_share_commitments[j]` opens to the evaluation at participant `j` of a degree-`t` polynomial `P_sk` where `P_sk(0)` opens to `expected_sk_commitment`, and similarly for the `e_sm` track with `expected_esm_commitment`. All polynomial coefficients satisfy the boundedness constraints required by Shamir secret sharing over the BFV secret domain. This relation corresponds to Interfold C2a (SkShareComputation) and C2b (ESmShareComputation) as a single batched statement.

**Public inputs**:
- `session_id: [u8; 32]` — session identifier
- `dealer_index: u32` — dealer party index
- `degree_t: u32` — Shamir polynomial degree (threshold minus one)
- `n_parties: u32` — total number of parties
- `expected_sk_commitment: Commitment` — commitment to the dealer's sk contribution (polynomial constant term)
- `expected_esm_commitment: Commitment` — commitment to the dealer's e_sm contribution
- `sk_share_commitments: [Commitment; n_parties]` — per-recipient sk share commitments
- `esm_share_commitments: [Commitment; n_parties]` — per-recipient e_sm share commitments

**Private witnesses**:
- `sk_shares: [RqPoly; n_parties]` — sk share evaluations
- `esm_shares: [RqPoly; n_parties]` — e_sm share evaluations
- `shamir_polynomial_coeffs_sk: [RqPoly; degree_t + 1]` — sk polynomial coefficients
- `shamir_polynomial_coeffs_esm: [RqPoly; degree_t + 1]` — e_sm polynomial coefficients

**Commitment bindings**:
1. `expected_sk_commitment` opens to `shamir_polynomial_coeffs_sk[0]`, the sk secret constant term.
2. `expected_esm_commitment` opens to `shamir_polynomial_coeffs_esm[0]`, the e_sm secret constant term.
3. For each `j` in `0..n_parties`: `sk_share_commitments[j]` opens to `sk_shares[j]`, and `sk_shares[j]` equals `P_sk(evaluation_point[j])`.
4. For each `j` in `0..n_parties`: `esm_share_commitments[j]` opens to `esm_shares[j]`, and `esm_shares[j]` equals `P_esm(evaluation_point[j])`.
5. All polynomial coefficients satisfy `‖coeff‖_∞ ≤ B_s`.

**Domain separator**: `"pvthfhe-R-share-computation-batched-sk-esm-v1"`

### R3.4.3 — R-dkg-aggregate-sk-esm

**What it proves**: A recipient correctly aggregates decrypted DKG shares received from an accepted dealer set into committed aggregate values for both tracks. The proof establishes that `sk_agg_commitment` opens to the sum of all `decrypted_sk_shares` from dealers in the set identified by `dealer_set_hash`, and that `esm_agg_commitments[slot]` opens to the sum of all `decrypted_esm_shares[slot]` from the same dealer set. The output commitments are anchored in `dkg_root` as the recipient's contribution to the public DKG transcript. This relation corresponds to Interfold C4 (DkgShareDecryption) extended to the two-track batched model.

**Public inputs**:
- `session_id: [u8; 32]` — session identifier
- `recipient_index: u32` — recipient party index
- `dealer_set_hash: [u8; 32]` — hash of the set of dealer indices whose shares were aggregated
- `sk_agg_commitment: Commitment` — commitment to the recipient's aggregated sk share
- `esm_agg_commitments: [Commitment; n_slots]` — commitments to aggregated e_sm shares per slot
- `dkg_root: [u8; 32]` — merkle root of the DKG transcript anchor set

**Private witnesses**:
- `decrypted_sk_shares: [RqPoly]` — decrypted sk shares from accepted dealers
- `decrypted_esm_shares: [[RqPoly]; n_slots]` — decrypted e_sm shares per slot from accepted dealers

**Commitment bindings**:
1. `sk_agg_commitment` opens to `sum(decrypted_sk_shares)` interpreted as a ring element.
2. For each `slot`: `esm_agg_commitments[slot]` opens to `sum(decrypted_esm_shares[slot])`.
3. `dealer_set_hash` is the SHA-256 hash of the sorted list of dealer indices whose shares were included in the aggregation.
4. `dkg_root` commits to a merkle tree whose leaves include `sk_agg_commitment` and `esm_agg_commitments` for `recipient_index`.

**Domain separator**: `"pvthfhe-R-dkg-aggregate-sk-esm-v1"`

### R3.4.4 — R-threshold-decrypt-with-committed-smudge

**What it proves**: A party's partial decryption share is correctly computed using the party's committed aggregated secret-key share and committed smudging-noise share. The proof establishes the RLWE decryption-share relation `d_j = c0 + c1 · sk_agg_poly + esm_agg_poly + quotient_polys` where `sk_agg_poly` opens to `sk_agg_commitment` from the DKG anchor set, `esm_agg_poly` opens to `esm_agg_commitment` for the specified `slot_id`, and all witness polynomials satisfy their norm bounds. The smudge slot is bound to `(session_id, epoch, ciphertext_hash)` so no slot may be reused across decryptions of distinct ciphertexts. This relation replaces the prior placeholder that sampled fresh uncommitted local smudging noise and corresponds to Interfold C6 (ThresholdShareDecryption) with the committed-smudge extension.

**Public inputs**:
- `session_id: [u8; 32]` — session identifier
- `party_index: u32` — decrypting party index
- `dkg_root: [u8; 32]` — merkle root of the DKG transcript (binds sk_agg and esm_agg commitments)
- `ciphertext_hash: [u8; 32]` — SHA-256 of `(ciphertext_u, ciphertext_v)`
- `sk_agg_commitment: Commitment` — commitment to the party's aggregated sk share (from DKG)
- `esm_agg_commitment: Commitment` — commitment to the party's aggregated e_sm share (from DKG)
- `slot_id: u64` — smudge slot identifier
- `ciphertext_u: RqPoly` — BFV ciphertext component u (c0)
- `ciphertext_v: RqPoly` — BFV ciphertext component v (c1)
- `decrypted_share_bytes: [u8]` — serialized decryption share d_j
- `epoch: u64` — protocol epoch

**Private witnesses**:
- `sk_agg_poly: RqPoly` — party's aggregated sk share polynomial
- `esm_agg_poly: RqPoly` — party's aggregated e_sm share polynomial for `slot_id`
- `quotient_polys: Vec<RqPoly>` — quotient/reduction polynomials
- `bound_witness: Vec<RqPoly>` — auxiliary witness material for norm-bound proofs

**Commitment bindings**:
1. `sk_agg_commitment` opens to `sk_agg_poly` and `‖sk_agg_poly‖_∞ ≤ B_s`.
2. `esm_agg_commitment` opens to `esm_agg_poly` and `‖esm_agg_poly‖_∞ ≤ B_smudge`.
3. `dkg_root` commits to a merkle tree that includes both `sk_agg_commitment` and `esm_agg_commitment` for `party_index`.
4. `ciphertext_hash` matches SHA-256(`ciphertext_u`, `ciphertext_v`).
5. `decrypted_share_bytes` decodes to a polynomial `d_j` satisfying the RLWE decryption-share relation with the committed witnesses and bounded quotient terms.

**Domain separator**: `"pvthfhe-R-threshold-decrypt-committed-smudge-v1"`

### R3.4.5 — R-decrypt-aggregate-final

**What it proves**: The final plaintext is the correct output of combining at least `threshold_t` valid decryption shares via Lagrange interpolation, CRT reconstruction, and BFV plaintext decoding. The proof establishes that `participant_ids` are all distinct and belong to the accepted participant set (bound via `dkg_root`), that the Lagrange coefficients are correct for the selected indices, that the combined share reconstructs to a valid BFV plaintext under `bfv_params_digest`, and that the decoded message hashes to `expected_plaintext_hash`. This relation corresponds to Interfold C7 (DecryptedSharesAggregation) plus participant-set validity checks.

**Public inputs**:
- `dkg_root: [u8; 32]` — merkle root of the DKG transcript (binds accepted participant set)
- `ciphertext_hash: [u8; 32]` — SHA-256 of the ciphertext being decrypted
- `participant_ids: [u32; threshold_t]` — indices of participants whose shares are included
- `decrypted_share_commitments: [Commitment; threshold_t]` — per-participant decryption-share commitments
- `expected_plaintext_hash: [u8; 32]` — SHA-256 of the expected plaintext message
- `threshold_t: u32` — number of shares required (must be ≥ degree_t + 1)
- `n_parties: u32` — total number of parties
- `bfv_params_digest: [u8; 32]` — hash of BFV parameterization (N, q, t_plain)

**Private witnesses**:
- `lagrange_coefficients: [RqPoly; threshold_t]` — Lagrange basis coefficients at the selected participant indices
- `decrypted_shares: [RqPoly; threshold_t]` — decrypted share polynomials
- `crt_quotients: Vec<RqPoly>` — CRT reduction quotients satisfying the RNS-to-plaintext modular equations
- `plaintext_message: Vec<u8>` — recovered plaintext bytes

**Commitment bindings**:
1. `participant_ids` are all distinct and each index belongs to the accepted set encoded in `dkg_root`.
2. For each `i`: `decrypted_share_commitments[i]` opens to `decrypted_shares[i]`.
3. The Lagrange-combined share `Σ lagrange_coefficients[i] · decrypted_shares[i]` equals the CRT-reconstructed plaintext polynomial under `bfv_params_digest`.
4. The BFV-decoded message hashes to `expected_plaintext_hash`.
5. `crt_quotients` satisfy the modular reduction equations for the RNS CRT plaintext space specified by `bfv_params_digest`.

**Domain separator**: `"pvthfhe-R-decrypt-aggregate-final-v1"`

---

## R3.5 — Relation Composition

The five target relations are not independent proofs to be verified in isolation. They compose into an end-to-end transcript by sharing three cross-batch binding anchors: the DKG root, the ciphertext hash, and the smudge slot identifier.

**DKG root** (`dkg_root`). This merkle root is the central binding anchor across all five relations. It is constructed during Batch C (`.sisyphus/plans/interfold-equivalent-pvss.md` §C.3) and commits to the entire public DKG transcript: participant set hash, individual BFV pk commitments, threshold pk contribution commitments, `sk_agg_commits[]`, `esm_agg_commits[]`, smudge-slot policy, and parameter digest. Every relation that references `dkg_root` implicitly checks that the inputs it consumes (commitments, participant sets, aggregated shares) are consistent with this single transcript root.

The composition chain proceeds as follows:

1. **R-share-encrypt-batched-sk-esm** and **R-share-computation-batched-sk-esm** produce per-dealer proofs during the DKG share-publication phase. These proofs reference `session_id` and dealer/recipient indices. Their output commitments (`sk_share_commitment`, `esm_share_commitment`) are independently verifiable at this stage; binding to the transcript root occurs downstream through the aggregation relation.

2. **R-dkg-aggregate-sk-esm** consumes the decrypted share outputs from the share-encryption and share-computation phases. It produces `sk_agg_commitment` and `esm_agg_commitments[]` and anchors them in `dkg_root`. This is the transition point where per-dealer material becomes per-recipient aggregated material bound to the public transcript. After this step, every subsequent relation references `dkg_root` rather than individual dealer commitments.

3. **R-threshold-decrypt-with-committed-smudge** references `dkg_root` to load the party's `sk_agg_commitment` and `esm_agg_commitment`. It also references `ciphertext_hash` to bind the decryption to a specific evaluated ciphertext, and `slot_id` to enforce one-time use of the smudge slot. The verifier checks that the commitments loaded from `dkg_root` match the commitments used in the proof and that the slot has not been consumed previously for the same tuple.

4. **R-decrypt-aggregate-final** references `dkg_root` to validate the accepted participant set and `ciphertext_hash` to ensure all decrypted shares correspond to the same ciphertext. It consumes per-party `decrypted_share_commitments`, each of which binds to an R3.4.4 proof, and verifies the final plaintext recovery against `expected_plaintext_hash`.

**Ciphertext hash** (`ciphertext_hash`). This anchor appears in R3.4.4 and R3.4.5. It is the SHA-256 digest of `(ciphertext_u, ciphertext_v)`. Including it in every per-party decryption proof statement prevents an adversary from presenting valid decryption shares for one ciphertext as if they were shares for another. The aggregator rejects any share whose proof references a different `ciphertext_hash` than the rest of the batch.

**Smudge slot identifier** (`slot_id`). This anchor appears in R3.4.3 and R3.4.4. The DKG transcript pre-allocates a bounded number of smudge slots per recipient, modelled as `esm_agg_commitments[slot]` for `slot` in `0..n_slots`. Each threshold decryption operation consumes exactly one slot. The slot id is bound to `(session_id, epoch, ciphertext_hash, decrypt_round)` so that reusing a slot for a different ciphertext or decrypt round produces a detectably mismatched statement. The aggregator or public verifier enforces slot freshness by maintaining a consumed-slot registry keyed by `(session_id, party_index, slot_id)`.

**End-to-end binding invariant**. An adversary controlling up to `t-1` parties cannot produce a valid end-to-end transcript for a plaintext that differs from the honest decryption result. The DKG root fixes the expected aggregated share commitments for every party. The ciphertext hash fixes the ciphertext being decrypted. The slot id prevents smudge-noise reuse across decryptions. The Lagrange combination in R3.4.5 enforces the threshold requirement. Any deviation in any relation creates a mismatched anchor that the final verifier detects through anchor equality checks.

---

## References

1. Greco: Greco lattice NIZK, `gnosisguild/fhe.rs` ecosystem. (Full citation:
   Greco paper / ePrint reference to be confirmed by oracle — the plan cites
   "production lattice NIZK with formal soundness proof for BFV
   well-formedness; published reference implementation.")

2. ZKBoo / MPCitH lineage:
   - Ishai, Kushilevitz, Ostrovsky, Sahai, "Zero-knowledge Proofs from Secure
     Multiparty Computation," STOC 2007.
   - Giacomelli, Madsen, Orlandi, "ZKBoo: Faster Zero-Knowledge for Boolean
     Circuits," CRYPTO 2016.
   - Katz, Kolesnikov, Wang, "Improved Non-Interactive Zero Knowledge with
     Applications to Post-Quantum Signatures," CCS 2019.

3. Cyclo: Garreta, Lipmaa, Luhaäär, Osadnik, "Cyclo: Lightweight Lattice-based
   Folding via Partial Range Checks," Eurocrypt 2026, IACR ePrint 2026/359.
   See `.sisyphus/research/cyclo-digest.md` for full digest.

4. Lemma 9 / Conjecture 9: `docs/security-proofs/lemma9.md` (this repo, 45
   lines) — downgrades Lemma 9 to Conjecture 9 pending formal extraction
   argument.

5. NIZK selection (L3): `.sisyphus/research/nizk-selection.md` (this repo, 482
   lines) — the L3 selection that chose Cyclo-companion Ajtai D2; now
   superseded by this document.

6. Assumptions ledger: `.sisyphus/design/assumptions-ledger.md` lines 100–113
   (A-COND-1, Cyclo T3 ∘ T5), lines 125–133 (A-COND-3, Lemma 9 heuristic),
   lines 40–48 (A-LATTICE-1 through A-LATTICE-5).

7. PVSS spec: `.sisyphus/design/spec-pvss.md` lines 16–29 (share-WF relation),
   lines 30–34 (Fiat-Shamir parameters).

8. NIZK infrastructure:
   - `crates/pvthfhe-pvss/src/nizk_share.rs` (current witness-in-envelope
     placeholder; 488 lines).
   - `crates/pvthfhe-nizk/src/adapter.rs` (CycloNizkAdapter, 516 lines).
   - `crates/pvthfhe-fhe/src/real_nizk.rs` (RealNizkAdapter, to be re-routed).
   - `crates/pvthfhe-pvss/src/nizk_decrypt.rs` (partial-decrypt NIZK).

9. Plan: `.sisyphus/plans/pvthfhe-remediation.md` lines 273–280 (R3.0
   construction selection), lines 282–287 (R3.0a witness-language schema).

10. SECURITY.md: `SECURITY.md` lines 16–17 and 48–49 (P1 conditional
    soundness declaration, P2 Lemma 9 heuristic).

11. Parameters: `.sisyphus/design/parameters.md` lines 13–36 and
    `.sisyphus/design/parameters.toml`.
