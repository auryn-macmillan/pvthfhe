# P1 Theorem Inventory

## T1: Completeness
**Theorem ID**: P1-T1
**Assumption**: None beyond correct arithmetic in \(R_q = \mathbb{Z}_q[X]/(X^N + 1)\) and correct transcript parsing.
**Model**: Standard model / deterministic verification.
**Statement sketch**: For every session transcript inherited from P4 and every honest witness \((s_i,e_i)\) for participant \(i\) such that \(C_i = H(\mathsf{session\_id}\|\|i\|\|s_i)\), \(d_i = c \cdot s_i + e_i \bmod q\), and \(\lVert e_i \rVert_\infty \le B_e\), the honest prover outputs a proof \(\pi_i\) accepted by the P1 verifier on public statement \((\mathsf{session\_id}, i, t, c, d_i, C_i, q, N, k, B_e)\).
**Proof technique**: Direct correctness argument: honest prover responses satisfy the bounded decrypt-share relation, transcript-binding checks, and any deterministic verifier equations challenge-by-challenge.
**Reduction target**: N/A.
**Status**: skeleton

## T2: Knowledge Soundness
**Theorem ID**: P1-T2
**Assumption**: Baseline hardness of the chosen bounded-relation proof system under Module-SIS/Module-LWE-style assumptions at the instantiated ring degree \(N\), module rank \(k\), modulus \(q\), and error bound \(B_e\), plus SHA-256 binding for the inherited P4 commitment \(C_i\).
**Model**: ROM baseline with a rewinding extractor; QROM is a deferred strengthening, not part of the baseline claim.
**Statement sketch**: Let \(x_i = (\mathsf{session\_id}, i, t, c, d_i, C_i, q, N, k, B_e)\), where the relation requires a witness \(w_i = (s_i,e_i)\) satisfying \(C_i = H(\mathsf{session\_id}\|\|i\|\|s_i)\), \(d_i = c \cdot s_i + e_i \bmod q\), and \(\lVert e_i \rVert_\infty \le B_e\). For every PPT prover \(\mathcal{P}^H\) that makes the Fiat-Shamir verifier accept \((x_i,\pi_i)\) with non-negligible probability, there exists a ROM extractor \(\mathcal{E}^{\mathcal{P},H}\) that rewinds on the hash challenge and outputs \((s_i',e_i')\) satisfying the same relation except with probability bounded by the reduction loss to the underlying Module-SIS/Module-LWE-style argument and the probability of breaking SHA-256 commitment binding. Any QROM upgrade must restate the same witness relation with a quantum extractor or measure-and-reprogram analysis rather than inheriting this ROM theorem automatically.
**Proof technique**: Fiat-Shamir forking / rewinding extraction from two accepting transcripts with the same first message and distinct challenges, followed by relation checking against the RLWE equation and the SHA-256 commitment inherited from P4.
**Reduction target**: Primary reduction to the algebraic knowledge soundness target of the chosen proof system (expected Module-SIS for inconsistent openings / short-kernel violations, with Module-LWE entering only if the concrete relation proof uses an indistinguishability-based subargument), plus SHA-256 second-preimage or collision resistance for transcript-binding failures.
**Status**: skeleton

## T3: Zero-Knowledge / HVZK \(\rightarrow\) NIZK via Fiat-Shamir
**Theorem ID**: P1-T3
**Assumption**: Honest-verifier zero knowledge of the interactive base protocol for the joint SHA-256/RLWE relation, together with programmability of the random oracle used by Fiat-Shamir.
**Model**: ROM.
**Statement sketch**: For the same public statement space \(x_i = (\mathsf{session\_id}, i, t, c, d_i, C_i, q, N, k, B_e)\), there exists a PPT simulator \(\mathsf{Sim}^H\) that, without knowing \((s_i,e_i)\), outputs a non-interactive proof \(\pi_i^\star\) whose distribution is computationally indistinguishable from an honestly generated Fiat-Shamir proof for any true statement in the P1 language. Concretely, the simulator must reproduce proofs that bind simultaneously to the SHA-256 commitment \(C_i\) and the bounded decrypt-share equation, so the final NIZK claim is not merely HVZK of the underlying sigma protocol but ROM indistinguishability of the compiled public transcript.
**Proof technique**: Start from the HVZK simulator for the interactive protocol, then program the random oracle so the simulated first message and challenge become a valid Fiat-Shamir transcript; conclude with a game hop from interactive HVZK to non-interactive ROM simulation.
**Reduction target**: ROM programmability / Fiat-Shamir simulation lemma for the chosen sigma-style protocol; no hardness reduction beyond the simulator guarantee is expected for the baseline theorem.
**Status**: skeleton

## T4: Simulation-Extractability Decision
**Theorem ID**: P1-T4
**Assumption**: No additional assumption is required for the frozen P1 baseline because the P2 threat model does not give the adversary simulated accepting P1 proofs before continuation; if that interface changes, simulation-extractability would require a stronger transform and a fresh extractor theorem.
**Model**: Baseline sequential-composition setting from P4/P2; a future upgrade would likely need ROM or QROM with simulator oracle access.
**Statement sketch**: Under the current threat model, simulation-soundness / simulation-extractability is not a required P1 theorem obligation, because P2 consumes prover-generated P1 proofs and does not rely on adversarial reuse of simulated accepting transcripts. The recorded obligation is therefore a decision theorem: the baseline P1 security package stops at ROM knowledge soundness and ROM zero knowledge. If a later P2 design allows an adversary to see simulated accepting P1 proofs and then output a fresh accepting proof for a new statement, the required upgraded theorem would assert extractability of a witness \((s_i,e_i)\) for every fresh accepted proof relative to that simulator oracle.
**Proof technique**: Dependency analysis against the frozen P2 interface now; if upgraded later, expect tagged Fiat-Shamir plus simulation-extractable NIZK machinery or an Unruh-style transform rather than the current plain rewinding argument.
**Reduction target**: Baseline target is N/A because the theorem records non-requirement; future upgrade target would be simulation-extractability of the chosen FS transform against the same joint SHA-256/RLWE relation.
**Status**: skeleton

## T5: Batch Soundness
**Theorem ID**: P1-T5
**Assumption**: Either (a) independent per-instance soundness with a union bound across the amortized batch, or (b) a stronger aggregation lemma for the chosen batching mechanism; in both cases the underlying base proof must satisfy P1-T2 and preserve SHA-256 transcript binding.
**Model**: ROM baseline.
**Statement sketch**: Let \(x_1,\dots,x_m\) be P1 public statements for \(m \le t\) decrypt shares proved in one amortized batch, each of the form \((\mathsf{session\_id}, i_j, t, c_j, d_{i_j}, C_{i_j}, q, N, k, B_e)\). If the batch verifier accepts, then except with probability at most \(m\) times the base extraction failure (or the tighter bound proved by the aggregation argument), there exist witnesses \((s_{i_j}, e_{i_j})\) for every accepted component such that \(C_{i_j} = H(\mathsf{session\_id}\|\|i_j\|\|s_{i_j})\), \(d_{i_j} = c_j \cdot s_{i_j} + e_{i_j} \bmod q\), and \(\lVert e_{i_j} \rVert_\infty \le B_e\). This theorem is the soundness handoff needed before P2 folds batched P1 outputs.
**Proof technique**: Hybrid reduction from an accepting batch adversary to either one bad component (via averaging / union bound) or to the batching combiner's algebraic failure event, then invoke P1-T2 for the selected component or the stronger batch extractor.
**Reduction target**: Reduction to P1-T2 plus batching-combiner correctness; for linear-combination batching, expected target is failure of the random-combination argument or the same Module-SIS/Module-LWE-style base assumption used in P1-T2.
**Status**: skeleton
