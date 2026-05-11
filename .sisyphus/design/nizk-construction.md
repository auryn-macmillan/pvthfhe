# R3.0 NIZK Construction Selection

Status: **draft — recommended pending oracle review**.

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
