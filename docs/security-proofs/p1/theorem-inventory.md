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
**Statement sketch**: For the abstract randomized SLAP core transcript—obtained by publishing only `(t_bytes, z_s, z_e)` and sampling fresh prover masks for the masked sigma relation—there exists a PPT simulator \(\mathsf{Sim}^H\) that, without knowing \((s_i,e_i)\), outputs a non-interactive transcript whose distribution is computationally indistinguishable from an honestly generated Fiat-Shamir proof for any true statement in the P1 language. This theorem is intentionally weaker than a claim about the current deterministic prototype payload in `real_nizk.rs`, which additionally opens witness values and derives masks from `SHA256(statement_bytes || witness_bytes)`.
**Proof technique**: Start from the HVZK simulator for the abstract randomized interactive protocol, then program the random oracle so the simulated first message and challenge become a valid Fiat-Shamir transcript; conclude with a game hop from interactive HVZK to non-interactive ROM simulation.
**Reduction target**: ROM programmability / Fiat-Shamir simulation lemma for the chosen sigma-style protocol; no hardness reduction beyond the simulator guarantee is expected for this abstract theorem.
**Status**: proved (abstract randomized core only)

## T4: Simulation-Extractability Decision
**Theorem ID**: P1-T4
**Assumption**: No additional assumption is required for the frozen P1 baseline because the P2 threat model does not give the adversary simulated accepting P1 proofs before continuation; if that interface changes, simulation-extractability would require a stronger transform and a fresh extractor theorem.
**Model**: Baseline sequential-composition setting from P4/P2; a future upgrade would likely need ROM or QROM with simulator oracle access.
**Statement sketch**: Under the current threat model, simulation-soundness / simulation-extractability is not a required P1 theorem obligation, because P2 consumes prover-generated P1 proofs and does not rely on adversarial reuse of simulated accepting transcripts. The recorded obligation is therefore a decision theorem: the baseline P1 security package stops at ROM knowledge soundness and ROM zero knowledge. If a later P2 design allows an adversary to see simulated accepting P1 proofs and then output a fresh accepting proof for a new statement, the required upgraded theorem would assert extractability of a witness \((s_i,e_i)\) for every fresh accepted proof relative to that simulator oracle.
**Proof technique**: Dependency analysis against the frozen P2 interface now; if upgraded later, expect tagged Fiat-Shamir plus simulation-extractable NIZK machinery or an Unruh-style transform rather than the current plain rewinding argument.
**Reduction target**: Baseline target is N/A because the theorem records non-requirement; future upgrade target would be simulation-extractability of the chosen FS transform against the same joint SHA-256/RLWE relation.
**Status**: skeleton

## T5: Commitment Binding
**Theorem ID**: P1-T5
**Assumption**: SHA-256 collision resistance on the exact commitment domain `session_id || participant_id_le || secret_share_be`.
**Model**: Standard hash-function security model for binding; ROM is not needed for the core binding statement.
**Statement sketch**: Let \(C_i = H(\mathsf{session\_id}\|\|i_{\mathrm{le}}\|\|s_i)\) be the P4-derived commitment carried into the implemented P1 verifier. For every PPT adversary that outputs two distinct openings \(s_i \neq s_i'\) to the same `pvss_commitment`, there exists a collision-finding adversary against SHA-256 on that exact byte-ordered input domain. Equivalently, any accepted P1 proof binds the public commitment to a unique opened `secret_share` except with negligible probability.
**Proof technique**: Direct reduction from double-opening of `pvss_commitment` to SHA-256 collision finding.
**Reduction target**: SHA-256 collision resistance / second-preimage resistance on the fixed commitment domain.
**Status**: proved
