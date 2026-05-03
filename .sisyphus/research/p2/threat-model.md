# P2 Folding Threat Model

## Goal

Freeze the adversary model, folding-specific threats, and knowledge-soundness assumptions for P2 so the folding layer preserves the already-frozen P1 security object instead of silently changing it.

## Scope and inherited baseline

- P2 consumes prover-generated `NizkProof` bytes from P1 according to `.sisyphus/contracts/p1-to-p2-bundle.md`.
- The baseline security setting is inherited from P1: static malicious corruption of at most `t-1` out of `n` parties under honest majority, synchronous sessions, ROM Fiat-Shamir, and rewinding-based extraction.
- P2 does **not** repair the known P1 caveats around direct witness opening or deferred T4 simulation-extractability; it must remain consistent with them.

## 1. Corruption Model

- **Inherited adversary:** P2 inherits the P1 adversary model unchanged: a malicious PPT adversary may statically corrupt at most `t-1` out of `n` parties, with `t = floor(n/2) + 1`, so honest majority still holds.
- **Folding-specific capability:** the adversary may submit malformed or strategically chosen P1 proofs as inner statements to the accumulator, including proofs that are well-formed at the byte level but invalid with respect to the P1 verification equation.
- **Visibility limits:** the adversary cannot observe honest parties' secret shares, mask randomness, or any witness randomness beyond what P1 already exposes in the accepted proof object.
- **Scheduling baseline:** sessions remain synchronous with rushing behavior inside each round, matching P1/P4; P2 does not assume asynchronous safety or adaptive corruption resilience.

## 2. Folding-Specific Threats

### Threat 1 — Malicious prover injecting invalid inner P1 proof

- **Description:** A malicious prover supplies a P1 proof that parses correctly and fits the frozen binary layout, but does not satisfy the intended P1 verifier semantics.
- **Attack Vector:** The prover crafts `NizkProof` bytes with syntactically valid transcript fields, then attempts to exploit incomplete deserialization, omitted semantic checks, or an underconstrained fold relation so the malformed inner proof is accepted into the accumulator.
- **Consequence:** P2 could fold an invalid base statement, breaking the claim that every accepted folded proof corresponds to valid underlying P1 witnesses.
- **Mitigation:** The fold relation must embed the full frozen P1 verification equation from the bundle, including SHA-256 transcript recomputation, participant/session binding, and norm/range checks. Accumulator transitions may accept only statements that satisfy the full inner verifier, not merely byte-shape checks.

### Threat 2 — Accumulator binding break

- **Description:** The adversary finds two distinct accumulated statement sets that map to the same accumulator state.
- **Attack Vector:** The attacker exploits a collision or algebraic ambiguity in the folding commitment/binding layer so different fold histories or statement multisets collapse to an identical accumulator digest.
- **Consequence:** Soundness of the accumulated claim fails because a verifier can no longer tell which underlying statements were actually folded.
- **Mitigation:** Require accumulator binding under the relevant module/ring SIS assumption (M-SIS / RingSIS, depending on the concrete accumulator instantiation). The folded state must bind the ordered fold transcript and the accumulated statement data strongly enough that distinct states cannot collide except by breaking the stated hardness assumption.

### Threat 3 — FS challenge grinding across folds

- **Description:** The adversary tries many fold orderings or transcript encodings to bias Fiat-Shamir challenges across the fold tree.
- **Attack Vector:** The attacker permutes fold order, restarts prover attempts, or re-encodes intermediate states until the random-oracle outputs induce a favorable sequence of ternary challenges.
- **Consequence:** Effective soundness degrades because the adversary can search for easier challenge paths rather than being bound to one canonical transcript.
- **Mitigation:** Domain-separate each fold step and bind the Fiat-Shamir input to the ordered accumulator state, fold index/depth, session identifier, and inner statement commitments. The challenge derivation must remain ROM-based and inherit P1's ternary challenge space `{-1, 0, 1}` so challenge semantics do not drift across phases.

### Threat 4 — Soundness amplification analysis

- **Description:** Folding composes per-fold soundness error over depth `d`; this must be stated quantitatively rather than heuristically.
- **Attack Vector:** An implementation or proof sketch hand-waves repeated folding as “amplifying soundness” without stating the exact accumulated acceptance probability for a cheating prover.
- **Consequence:** Downstream claims overstate security, especially when the ternary challenge space gives only constant per-fold soundness.
- **Mitigation:** If the per-fold special-soundness failure probability is `ε`, and the cheating prover must succeed independently across a depth-`d` fold tree, then the aggregate soundness error is upper-bounded by `ε^d` under the idealized independent-fold analysis assumed by the folding proof. For the inherited ternary challenge space, the baseline per-fold bound is `ε = 1/3`, giving total error `(1/3)^d`. Any concrete P2 theorem must state deviations from this product form explicitly.

## 3. Knowledge-Soundness Model

- **Extractor model:** P2 uses a rewinding extractor that forks each sigma-style transcript appearing in the fold tree. The extractor is not straight-line and remains in the ROM, matching the P1 baseline.
- **Fold-tree extraction:** For a fold tree of depth `d`, the extractor may need to rewind each branch point to obtain enough accepting transcripts for special soundness. A conservative extraction budget is therefore `2^d` rewindings in the worst case.
- **Acceptable depth:** This exponential rewinding cost is acceptable only for modest folding depth. Concretely, `d` must stay small enough that `2^d` extractor work remains polynomial and operationally meaningful for the theorem statement; P2 should therefore treat large unrestricted depth as unsupported unless a tighter extraction argument is provided.
- **P1 reconciliation:** P1 already fixes the base proof as a standard ROM proof of knowledge with a rewinding extractor, while T4 simulation-extractability remains deferred. P2 must therefore build only on extractability of prover-generated accepted P1 proofs and must not assume simulation-soundness or stronger extractor properties than P1 states.

## 4. P1 Consistency Check

The P2 threat model is consistent with the P1 threat model in the following ways:

- **Corruption model matches:** both phases use a static malicious adversary corrupting at most `t-1` of `n` parties under honest majority.
- **Challenge space matches:** P2 preserves P1's ternary challenge space `{-1, 0, 1}` rather than silently upgrading or changing the verifier challenge domain.
- **Session binding carries through:** the folded statement must continue to bind the `session_id` already fixed by P1 and inherited from P4.
- **Participant binding carries through:** the folded verifier relation still depends on the participant-specific binding already enforced by the P1 `pvss_commitment` opening equation.
- **Oracle/extractor model matches:** both phases remain in the ROM and use rewinding extraction rather than claiming QROM or straight-line extraction.
- **Deferred properties remain deferred:** P2 does not upgrade the deferred P1 T4 simulation-extractability question into a baseline assumption.

## 5. Assumption Ledger

- **RLWE hardness (inherited from P1):** the underlying lattice relation and parameterized witness semantics still rest on the RLWE-style assumptions already fixed upstream.
- **M-SIS / RingSIS:** needed for accumulator binding / collision resistance in the folding state, depending on whether the chosen accumulator is module-based or ring-based.
- **ROM:** required for Fiat-Shamir challenge derivation across fold steps, just as P1 relies on ROM for its non-interactive sigma transcript.
- **Module-NTRU / related lattice assumptions:** only if the selected folding backend instantiates its commitment or compression layer over a Module-NTRU-style primitive; if used, this must be stated as an explicit added assumption rather than implied.
- **Ring-SIS over the NTT domain:** only if the concrete accumulator argument is phrased in an NTT-domain representation; this is acceptable as an implementation-level restatement of binding hardness, but it must remain consistent with the broader SIS-family assumption language rather than drifting away from P1's lattice baseline.

## 6. Out-of-Scope

- **Adaptive corruption:** not part of the baseline P2 claim; supporting it would require an erasure / forward-security story across P4→P1→P2.
- **Simulation-soundness for P2:** not required by the P3 contract and not inherited from P1; any future need for it must be stated as a cross-phase upgrade.
- **QROM hardening:** deferred exactly as in P1.
- **Unlimited-depth extraction claims:** not supported without a tighter-than-`2^d` extraction analysis.

## Downstream consequence for P3

P3 may rely only on the folded proof object and the assumptions listed above; it must not assume that P2 established stronger properties than P1 provides, especially around simulation-extractability or hidden witness privacy.
