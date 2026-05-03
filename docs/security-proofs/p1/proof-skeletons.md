# P1 Proof Skeletons — SLAP Primary Stack

This document expands the T1–T5 inventory entries into theorem statements and reduction skeletons for the frozen **SLAP** primary stack. The baseline relation is the Phase P1 statement language from `.sisyphus/design/p1/interface-spec.md`: for public statement

\[
x=(\mathsf{session\_id},\mathsf{participant\_id},c,d_i,h_i,q,N,B_e,k)
\]

the witness is

\[
w=(s_i,e_i,r_i)
\]

such that all of the following hold simultaneously:

1. `h_i = SHA256(session_id || participant_id || s_i)` under the byte ordering frozen in the P4→P1 bundle;
2. `d_i = c \cdot s_i + e_i \pmod q` in the ring \(R_q = \mathbb{Z}_q[X]/(X^N+1)\);
3. the coefficient norm of \(e_i\) is bounded by \(\lVert e_i \rVert_\infty \le B_e\);
4. `r_i` is valid prover randomness for the interactive SLAP protocol whose Fiat–Shamir transform yields the published proof.

Throughout, the adversary model is the frozen P1 threat model: malicious PPT adversaries, static corruption, ROM baseline, rewinding extractor baseline, and no baseline simulation-soundness claim. The named assumptions are **M-LWE**, **M-SIS**, and **ROM** exactly as used below.

## T1 — Completeness

### Formal statement

Let \(\lambda\) be the security parameter. Let \(q=q(\lambda)\), \(N=N(\lambda)\), module rank \(k=k(\lambda)\), and error bound \(B_e=B_e(\lambda)\) be any admissible parameter tuple for the frozen SLAP instantiation, with ring \(R_q=\mathbb{Z}_q[X]/(X^N+1)\). For every PPT honest prover \(\mathsf{P}_{\mathsf{SLAP}}\), every honestly generated statement-witness pair

\[
(x,w)=((\mathsf{session\_id},\mathsf{participant\_id},c,d_i,h_i,q,N,B_e,k),(s_i,e_i,r_i))
\]

satisfying

\[
h_i = H(\mathsf{session\_id}\|\mathsf{participant\_id}\|s_i), \qquad d_i = c\cdot s_i + e_i \bmod q, \qquad \lVert e_i \rVert_\infty \le B_e,
\]

where \(H\) is the Fiat–Shamir random oracle, the verifier \(\mathsf{V}_{\mathsf{FS-SLAP}}\) accepts the non-interactive proof \(\pi\leftarrow \mathsf{P}_{\mathsf{FS-SLAP}}(x,w)\) with probability at least

\[
1-\mathsf{negl}(\lambda).
\]

Equivalently, any rejection event for an honest prover is confined to negligible probability arising from implementation-level transcript parsing failure, canonical-encoding failure, or negligible bad randomness events excluded by the SLAP parameter discipline. The theorem relies only on correct arithmetic and transcript derivation and does not invoke M-LWE or M-SIS hardness.

### Proof technique

Direct correctness argument over the interactive SLAP equations followed by the Fiat–Shamir determinization step. The proof is constructive: show that each verifier predicate is satisfied by the honest witness and honestly generated response polynomials.

### Reduction

There is no hardness reduction for completeness, but the proof skeleton still needs an explicit structure because the verifier checks a joint statement, not a single algebraic identity.

1. **Commitment binding of the public statement.** Because the statement encoding is frozen by the interface spec, the prover and verifier hash the same ordered tuple `(session_id, participant_id, c, d_i, h_i, q, N, B_e, k)` into the Fiat–Shamir transcript. The only way completeness could fail at this stage is non-canonical encoding; that event is ruled out by the deterministic serialization contract.
2. **Validity of the SHA-256 side relation.** The honest prover computes `h_i` directly from the witness share `s_i` and the inherited P4 transcript identifiers. Therefore the commitment-opening predicate accepted by SLAP's statement encoder is satisfied exactly, not only statistically.
3. **Validity of the lattice relation.** The witness satisfies `d_i = c·s_i + e_i mod q` by construction of the honest partial decryption share. Substituting the witness into the verifier's polynomial relation leaves the zero polynomial in every checked coordinate.
4. **Boundedness check.** The honest generation algorithm samples or derives `e_i` from the admissible error distribution and rejects internally if the coefficient bound exceeds `B_e`; therefore any proof emitted by the honest prover already satisfies the norm bound embedded in the statement.
5. **Interactive acceptance.** SLAP's honest-prover response rule makes each verifier equation true for the verifier challenge `\alpha` because the response polynomial/vector is computed as the standard affine correction using the same witness committed in the first move.
6. **Fiat–Shamir compilation.** The non-interactive verifier recomputes the same challenge `\alpha = H(\mathsf{domsep} || x || \mathsf{com})`. Since the prover used the same deterministic input and `\mathsf{com}` is the same first message, the compiled proof is exactly an accepting interactive transcript written non-interactively.
7. **Conclusion.** Acceptance is therefore perfect except for negligible bad events outside the theorem's algebraic core: malformed encodings, hash-input ambiguity, or implementation faults already excluded by the frozen interface.

### Tightness

The theorem has no asymptotic reduction loss because it is a correctness theorem rather than a hardness theorem. The explicit quantitative statement is:

\[
\Pr[\mathsf{V}_{\mathsf{FS-SLAP}}(x,\pi)=1]\ge 1-\varepsilon_{\mathsf{enc}}-\varepsilon_{\mathsf{parse}}-\varepsilon_{\mathsf{honest\_abort}},
\]

where each \(\varepsilon\)-term is negligible in \(\lambda\) under the frozen implementation conventions. In the ideal mathematical model with canonical encoding and no honest aborts, the bound is exactly 1.

### Assumptions named

- **ROM:** only to define the deterministic Fiat–Shamir challenge.
- **M-LWE:** not used.
- **M-SIS:** not used.

## T2 — Knowledge Soundness

### Formal statement

Let \(\Pi_{\mathsf{SLAP}}\) be the frozen interactive SLAP argument for the relation above, and let \(\mathsf{FS}(\Pi_{\mathsf{SLAP}})\) denote its Fiat–Shamir transform in the ROM. For every PPT prover \(\mathcal{A}^H\) making at most \(Q_H\) random-oracle queries and outputting, on input public parameters \((q,N,B_e,k)\), an accepting proof

\[
\pi=(\mathsf{com},\mathsf{rsp})
\]

for a statement

\[
x=(\mathsf{session\_id},\mathsf{participant\_id},c,d_i,h_i,q,N,B_e,k)
\]

with probability

\[
\Pr[\mathsf{V}_{\mathsf{FS-SLAP}}^H(x,\pi)=1] = \epsilon(\lambda),
\]

there exists an expected-polynomial-time extractor

\[
\mathcal{E}^{\mathcal{A},H}_{\mathsf{fork}}
\]

obtained by the classical forking / rewinding lemma for Fiat–Shamir transcripts, such that \(\mathcal{E}^{\mathcal{A},H}_{\mathsf{fork}}(x)\) outputs a witness

\[
(s_i',e_i',r_i')
\]

satisfying

\[
h_i = H(\mathsf{session\_id}\|\mathsf{participant\_id}\|s_i'), \qquad d_i = c\cdot s_i' + e_i' \bmod q, \qquad \lVert e_i'\rVert_\infty \le B_e,
\]

except with probability at most

\[
\varepsilon_{\mathsf{ext}}(\lambda) \le \varepsilon_{\mathsf{fork}}(\lambda) + \varepsilon_{\mathsf{MSIS}}(\lambda) + \varepsilon_{\mathsf{MLWE}}(\lambda) + \varepsilon_{\mathsf{bind}}(\lambda).
\]

More explicitly, if \(\delta\) denotes the probability that the extractor obtains two accepting transcripts with identical first message and distinct challenges, then

\[
\delta \ge \frac{(\epsilon(\lambda)-Q_H/2^{\ell_H})^2}{Q_H+1} - \mathsf{negl}(\lambda),
\]

where \(\ell_H\) is the Fiat–Shamir challenge length. Conditioned on that fork, either the extractor outputs a valid witness, or it computes an M-SIS solution from inconsistent short responses, or it distinguishes an M-LWE-based hiding component if the concrete SLAP instantiation masks witness coordinates using an LWE-style hiding layer.

### Proof technique

Forking-lemma extraction from two accepting FS transcripts plus algebraic elimination of the challenge-dependent mask. The proof is a reduction with an explicit extractor, not only an existence claim.

### Reduction

Let \(\mathcal{A}\) be any prover that causes the FS verifier to accept with non-negligible probability.

1. **Record the decisive oracle query.** Run \(\mathcal{A}^H\) once. Because the final verifier challenge is `\alpha = H(\mathsf{domsep} || x || \mathsf{com})`, acceptance implies either (i) `\mathcal{A}` queried this exact string to `H`, or (ii) it guessed the challenge in advance. The guessing event contributes at most `Q_H / 2^{\ell_H}` to the success probability and is absorbed into the final loss.
2. **Fork at the challenge query.** Rewind \(\mathcal{A}\) to just before the decisive hash query on `(x, \mathsf{com})`, answer all prior oracle queries consistently, and respond to the decisive query with a fresh independent challenge `\alpha' \neq \alpha`. Continue execution with the same internal coins. By the classical rewinding lemma / forking lemma, two accepting transcripts with the same commitment and different challenges are obtained with probability at least `((\epsilon-Q_H/2^{\ell_H})^2)/(Q_H+1)` up to negligible bookkeeping loss.
3. **Form the transcript pair.** Denote the two accepting transcripts by
   \[
   (\mathsf{com},\alpha,\mathsf{rsp}) \quad \text{and} \quad (\mathsf{com},\alpha',\mathsf{rsp}').
   \]
   The first message `\mathsf{com}` is identical, while the challenge scalars differ.
4. **Algebraically solve for the witness opening.** In SLAP, the response has affine form relative to the hidden witness coordinates, e.g. schematically `\mathsf{rsp} = \mathbf{y} + \alpha \cdot \mathbf{w}` and `\mathsf{rsp}' = \mathbf{y} + \alpha' \cdot \mathbf{w}`. Since `\alpha \neq \alpha'`, the extractor computes
   \[
   \mathbf{w} = (\mathsf{rsp}-\mathsf{rsp}')/(\alpha-\alpha').
   \]
   The relevant coordinates of `\mathbf{w}` decode to candidate `(s_i', e_i', r_i')`. The exact inversion occurs over the challenge ring/domain chosen by SLAP and is well-defined whenever the verifier challenge space excludes zero divisors used in the extraction step.
5. **Check the full relation, not only algebraic consistency.** The extractor recomputes `h_i^* = SHA256(session_id || participant_id || s_i')` and verifies equality with the public `h_i`; then it recomputes `d_i^* = c·s_i' + e_i' mod q` and verifies equality with the public `d_i`; finally it checks `\lVert e_i'\rVert_\infty \le B_e`. If all checks pass, output the witness.
6. **Derive contradiction if extracted object fails.** If the algebraically derived witness does not satisfy the verifier equations despite both transcripts accepting, then the difference of the two accepting equations yields a non-zero short vector in the kernel of the public verification matrix. That kernel element is an **M-SIS** solution of norm bounded by the protocol's response bounds. This is the primary soundness contradiction for SLAP.
7. **Account for hiding-layer failure if present.** If the concrete SLAP instantiation uses an LWE-style masking distribution to hide witness coordinates in the first message, then any adversarial success mode that depends on distinguishing honest masking from simulated masking contributes an **M-LWE** term. This term is not the main extractor engine, but it must be named because the proof package is against the frozen SLAP stack rather than an abstract sigma protocol.
8. **Account for commitment-binding failure.** If the extracted `s_i'` satisfies the lattice equation but opens the wrong commitment hash, then the adversary has either found a second preimage/collision for the inherited SHA-256 commitment binding or induced transcript inconsistency outside the theorem's model. This event is bounded by `\varepsilon_{\mathsf{bind}}`.
9. **Conclude witness extraction.** Therefore any accepting adversary that is not already solving M-SIS, exploiting an M-LWE hiding failure, or breaking the inherited commitment binding yields a valid witness for the full P1 relation.

### Tightness

The concrete extraction bound is the sum of four explicit losses:

\[
\mathsf{Adv}^{\mathsf{ks}}_{\mathsf{FS-SLAP}}(\mathcal{A})
\le
\underbrace{\frac{Q_H}{2^{\ell_H}}}_{\text{challenge guessing}}
+
\underbrace{\sqrt{(Q_H+1)\cdot \mathsf{Adv}^{\mathsf{MSIS}}(\mathcal{B}_{\mathsf{sis}})}}_{\text{forking loss, rearranged}}
+
\underbrace{\mathsf{Adv}^{\mathsf{MLWE}}(\mathcal{B}_{\mathsf{lwe}})}_{\text{hiding layer, if instantiated}}
+
\underbrace{\mathsf{Adv}^{\mathsf{bind}}_{\mathsf{SHA256}}(\mathcal{B}_{\mathsf{bind}})}_{\text{commitment mismatch}}.
\]

Equivalent phrasing: if \(\mathcal{A}\) succeeds with probability \(\epsilon\), then the extractor succeeds with probability at least

\[
\frac{(\epsilon-Q_H/2^{\ell_H})^2}{Q_H+1} - \mathsf{Adv}^{\mathsf{MSIS}} - \mathsf{Adv}^{\mathsf{MLWE}} - \mathsf{Adv}^{\mathsf{bind}} - \mathsf{negl}(\lambda).
\]

The loss is therefore quadratic in the usual ROM forking sense and linear in the additive hardness failures. This is the precise baseline claim to carry into P2; no straight-line or QROM extractor is claimed here.

### Assumptions named

- **M-SIS:** primary extractor contradiction from two inconsistent short openings.
- **M-LWE:** secondary hiding term if the SLAP commitment/masking layer uses LWE indistinguishability.
- **ROM:** required for Fiat–Shamir and rewinding/forking analysis.

## T3 — HVZK to NIZK via Fiat–Shamir

### Formal statement

Let \(\Pi_{\mathsf{SLAP}}\) be the interactive SLAP protocol for the P1 relation, and assume \(\Pi_{\mathsf{SLAP}}\) is honest-verifier zero knowledge with simulator \(\mathsf{Sim}_{\mathsf{HVZK}}\). Let \(\mathsf{FS}(\Pi_{\mathsf{SLAP}})\) denote the Fiat–Shamir transform applied to \(\Pi_{\mathsf{SLAP}}\) using a random oracle \(H\). Then for every true statement

\[
x=(\mathsf{session\_id},\mathsf{participant\_id},c,d_i,h_i,q,N,B_e,k)
\]

there exists a PPT simulator \(\mathsf{Sim}^H_{\mathsf{FS-SLAP}}\) that outputs a non-interactive proof \(\pi^\star\) such that the ensembles

\[
\{(x,\pi^\star)\}_{\lambda}
\qquad \text{and} \qquad
\{(x,\pi) : \pi \leftarrow \mathsf{P}_{\mathsf{FS-SLAP}}^H(x,w)\}_{\lambda}
\]

are computationally indistinguishable for all witnesses \(w=(s_i,e_i,r_i)\) satisfying the P1 relation. The simulator need not know \((s_i,e_i,r_i)\). The theorem is specifically about the Fiat–Shamir transform applied to the frozen **SLAP** protocol; it is not merely a restatement of interactive HVZK.

### Proof technique

Program the random oracle at the Fiat–Shamir challenge point so that an HVZK-simulated accepting interactive transcript becomes a valid non-interactive transcript. Then bound the distinguishing gap by oracle-programming consistency and the HVZK indistinguishability bound.

### Reduction

1. **Start from the interactive HVZK simulator.** On input a true public statement `x`, run `\mathsf{Sim}_{\mathsf{HVZK}}(x)` for the SLAP protocol. This simulator outputs an accepting interactive transcript of the form
   \[
   (\mathsf{com}^\star, \alpha^\star, \mathsf{rsp}^\star)
   \]
   whose distribution is computationally indistinguishable from an honest interactive transcript for the same statement.
2. **Embed the transcript into Fiat–Shamir form.** The FS proof format publishes `(\mathsf{com}, \mathsf{rsp})`, with the verifier recomputing `\alpha = H(\mathsf{domsep} || x || \mathsf{com})`. Therefore the simulator sets
   \[
   \pi^\star := (\mathsf{com}^\star, \mathsf{rsp}^\star)
   \]
   and programs the random oracle so that
   \[
   H(\mathsf{domsep} || x || \mathsf{com}^\star) = \alpha^\star.
   \]
3. **Consistency of oracle programming.** The programming is sound provided the simulator controls the first reply to that exact query string. If the distinguisher queries that point before programming, the simulator aborts and outputs failure. The abort probability is bounded by the probability that the programmed point is guessed or queried prematurely; with domain separation and fresh `\mathsf{com}^\star`, this contributes a standard ROM term negligible in `\lambda` or at worst linear in the distinguisher's oracle budget over the challenge space size.
4. **Show verifier acceptance.** Because `(\mathsf{com}^\star, \alpha^\star, \mathsf{rsp}^\star)` is already an accepting interactive SLAP transcript, and because the programmed oracle makes the non-interactive verifier recompute exactly `\alpha^\star`, the verifier accepts `\pi^\star` with probability 1 conditioned on no programming collision.
5. **Hybrid H0 → H1 (interactive honest transcript vs interactive simulated transcript).** Replace the honest interactive transcript used inside the Fiat–Shamir proof with the HVZK simulator's transcript. By the HVZK property of SLAP, this changes the distinguisher's view by at most `\mathsf{Adv}^{\mathsf{hvzk}}_{\Pi_{\mathsf{SLAP}}}`.
6. **Hybrid H1 → H2 (honest oracle vs programmed oracle).** Replace the real random oracle with one programmed only at the single point `(\mathsf{domsep} || x || \mathsf{com}^\star)`. The distinguishing gap is bounded by the probability of noticing that one programmed point, which is at most the adversary's probability of hitting that exact point before or outside the simulator's intended use. This is the standard uniform-challenge / ROM-programming term.
7. **Uniform challenge argument.** Since `\alpha^\star` produced by the HVZK simulator is distributed exactly as the honest verifier challenge in the interactive protocol, programming `H` to output `\alpha^\star` preserves the challenge distribution expected by the FS verifier. This is the explicit place where the Fiat–Shamir transform applied to SLAP inherits its NIZK story from HVZK plus ROM programmability.
8. **Conclude NIZK.** Combining the two hybrids gives a simulator for the non-interactive proof whose output is computationally indistinguishable from an honest FS-SLAP proof for every true statement.

### Tightness

Let \(Q_D\) be the distinguisher's oracle-query budget and \(\ell_H\) the challenge length. Then a standard bound is

\[
\mathsf{Adv}^{\mathsf{zk}}_{\mathsf{FS-SLAP}}(\mathcal{D})
\le
\mathsf{Adv}^{\mathsf{hvzk}}_{\Pi_{\mathsf{SLAP}}}(\mathcal{D}_1)
+ \frac{Q_D}{2^{\ell_H}} + \mathsf{negl}(\lambda).
\]

The first term is inherited from the interactive HVZK proof; the second is the cost of oracle programming / pre-query collision at the programmed FS point. No M-SIS or M-LWE loss is needed for the baseline simulator theorem except insofar as the interactive HVZK proof itself is computational rather than statistical.

### Assumptions named

- **ROM:** essential for oracle programmability and the Fiat–Shamir simulation.
- **M-LWE:** only if the underlying interactive HVZK argument uses LWE-style hiding to justify indistinguishability of commitments/messages.
- **M-SIS:** not the primary simulator assumption.

## T4 — Optional Upgrade: Simulation-Extractability

### Formal statement

**Optional upgrade only; not a baseline P1 theorem.** Under the frozen P1/P2 interface, simulation-extractability is not required, because P2 consumes prover-generated P1 proofs and does not grant an adversary oracle access to simulated accepting P1 transcripts prior to producing fresh statements. If a later Phase P2 design changes that interface, the upgraded theorem to be proved is the following:

For every PPT adversary \(\mathcal{A}^{H,\mathsf{Sim}}\) with access to the random oracle \(H\) and to a simulator oracle that returns accepting FS-SLAP proofs for adaptively chosen true statements, if \(\mathcal{A}\) outputs with non-negligible probability a fresh accepting proof \((x^\star,\pi^\star)\) outside the simulator's query set, then there exists a straight-line or simulation-aware extractor \(\mathcal{E}\) that outputs a witness \(w^\star=(s_i^\star,e_i^\star,r_i^\star)\) for \(x^\star\), except with probability bounded by the upgraded simulation-extractability advantage.

The parameter tuple remains explicit: \(x^\star\) binds `(q, N, B_e, k)` and the same P4-derived commitment hash relation. This upgraded theorem would require a stronger transform than plain FS-SLAP.

### Proof technique

Dependency-analysis theorem for the baseline, plus an upgrade sketch: tagged transcripts, simulator-oracle separation, and a straight-line extractor compatible with simulated proofs. The current section records the exact proof burden that would arise later rather than claiming it already holds.

### Reduction

1. **Baseline non-requirement claim.** The frozen threat model says no adversary in the current composition receives simulated accepting P1 proofs and then attacks freshness of new P1 statements. Therefore the present P1 security package needs T2 extraction from ordinary accepting proofs and T3 simulation for true statements, but not the combination demanded by simulation-extractability.
2. **Why T2+T3 do not automatically imply T4.** A rewinding extractor for plain FS transcripts can fail once the adversary also interacts with a simulator that programs the same random oracle. Likewise, an HVZK-to-FS simulator does not by itself guarantee that fresh adversarial outputs remain extractable after seeing simulated proofs. The gap is structural, not cosmetic.
3. **Freshness condition for the future theorem.** The upgraded experiment must define freshness as a statement/proof pair not previously output by the simulator oracle and not trivially replayed from earlier transcripts. It must also bind statement tags or session-specific domain separators so the adversary cannot recycle simulator outputs verbatim.
4. **Candidate upgraded extractor.** A future proof would likely use one of two routes:
   - a **tagged Fiat–Shamir** transform where simulated proofs and real proofs occupy disjoint transcript domains, enabling extraction on fresh-tag transcripts; or
   - a stronger transform with measure-and-reprogram / straight-line extractability machinery if QROM or simulator-oracle entanglement becomes relevant.
5. **Reduction target if the upgrade is activated.** Any failure of the future extractor would reduce either to breaking the upgraded transform's simulation-extractability theorem, to the same underlying **M-SIS** witness-binding property used in T2, or to the hiding assumption (**M-LWE**) if simulated transcripts rely on indistinguishable masking.
6. **Current conclusion.** Because none of those simulator-oracle attack surfaces exist in the frozen Phase P1 baseline, the correct theorem statement today is that T4 is deferred and optional, not silently assumed.

### Tightness

Baseline quantitative claim: the current design incurs **zero additional tightness loss** from not proving simulation-extractability, because the property is outside the baseline experiment. If activated later, the upgraded theorem must publish a new bound of the form

\[
\mathsf{Adv}^{\mathsf{simext}}_{\mathsf{FS-SLAP^+}}(\mathcal{A})
\le
\mathsf{Adv}^{\mathsf{transform}}(\mathcal{B}_1)
+ \mathsf{Adv}^{\mathsf{MSIS}}(\mathcal{B}_2)
+ \mathsf{Adv}^{\mathsf{MLWE}}(\mathcal{B}_3)
+ \varepsilon_{\mathsf{fresh}}.
\]

No such bound is claimed for the frozen baseline; the purpose of this section is to prevent accidental overclaiming and to define the exact upgrade target.

### Assumptions named

- **ROM:** baseline transcript domain; stronger simulator-oracle analysis would also live here unless upgraded to QROM.
- **M-SIS:** likely future extraction anchor.
- **M-LWE:** likely future simulator-hiding anchor if the upgraded transform retains LWE masking.

## T5 — Commitment Binding

### Formal statement

Let

\[
C = H(\mathsf{session\_id}\|\|\mathsf{participant\_id}_{\mathrm{le}}\|\|s)
\]

be the commitment function implemented by `RealNizkAdapter::commitment_hash`. For every PPT adversary \(\mathcal A\) that outputs two distinct openings \(s \neq s'\) such that

\[
H(\mathsf{session\_id}\|\|\mathsf{participant\_id}_{\mathrm{le}}\|\|s)
=
H(\mathsf{session\_id}\|\|\mathsf{participant\_id}_{\mathrm{le}}\|\|s'),
\]

there exists a collision-finding adversary against SHA-256 on the same domain. Equivalently, `pvss_commitment` is binding under SHA-256 collision resistance.

### Proof technique

Direct reduction from any successful double opening of the commitment to a collision in SHA-256 on two distinct preimages sharing the same session/participant prefix.

### Reduction

1. **Adversary output.** Run the double-opening adversary \(\mathcal A\) and obtain `(session_id, participant_id, s, s')` with `s != s'` but identical commitment digest.
2. **Form the two preimages.** Construct

\[
m = \mathsf{session\_id}\|\|\mathsf{participant\_id}_{\mathrm{le}}\|\|s_{\mathrm{be}},
\qquad
m' = \mathsf{session\_id}\|\|\mathsf{participant\_id}_{\mathrm{le}}\|\|s'_{\mathrm{be}}.
\]

3. **Distinctness.** Because `s != s'` and both openings are encoded in fixed-width 8-byte big-endian form, we have `m != m'`.
4. **Collision extraction.** The adversary assumption gives `H(m) = H(m')`, which is a direct SHA-256 collision.
5. **Conclusion.** Therefore any efficient double opener for `pvss_commitment` breaks SHA-256 collision resistance, so the commitment is computationally binding.

### Tightness

The reduction is tight up to constant overhead:

\[
\mathsf{Adv}^{\mathsf{bind}}_{\mathsf{pvss}}(\mathcal A)
\le
\mathsf{Adv}^{\mathsf{coll}}_{\mathsf{SHA256}}(\mathcal B).
\]

### Assumptions named

- **SHA-256 collision resistance:** primary and only reduction target for this theorem.
