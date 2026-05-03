# P1 Threat Model: Decrypt-Share NIZK

## Goal

Freeze the adversary model, security assumptions, and proof interface for the P1 decrypt-share NIZK so later theorem statements, P2 folding, and the inherited P4 composition story all speak about the same security object.

## Non-Goals

- This document does not upgrade the frozen P4 handoff from Shamir-over-`2^61-1` plus SHA-256 commitments into a final RLWE-native keygen artifact.
- This document does not claim adaptive-corruption security, UC security, straight-line extractability, or QROM security as baseline guarantees.
- This document does not weaken the proof target to honest-verifier zero knowledge; any such downgrade would break the intended non-interactive deployment setting and is therefore out of scope unless a later document gives an explicit replacement argument.

## Required Theorems

- **T1 — Completeness.** Honest provers with a valid share/witness tuple produce accepting P1 proofs.
- **T2 — Knowledge soundness.** Any PPT prover producing an accepting P1 proof yields an extractor that recovers a witness consistent with the bound decrypt-share relation, except with negligible probability.
- **T3 — Statement binding.** The accepted witness must bind to the public transcript inherited from P4 and to the concrete FHE parameter tuple used by the decrypt-share relation.
- **T4 — Sequential composition with P4.** P1 security statements must reuse the same static corruption interface and transcript semantics exported by P4 T5.
- **T5 — Sequential composition with P2.** P2 may fold only proofs/statements whose soundness assumptions match this document; no hidden strengthening or weakening is allowed at folding time.

## Allowed Assumptions

- **Adversary model:** malicious PPT adversary corrupting at most `t-1` parties out of `n`, where the threshold regime remains `t = floor(n/2) + 1` to match P4.
- **Corruption timing:** Static corruption is the baseline. The adversary chooses the corrupted set before protocol start. Adaptive corruption is explicitly out of scope unless future work adds erasures / forward-security assumptions across P4 and P1.
- **Network / scheduling:** synchronous-session baseline with a rushing adversary inside each round, matching the P4 threat model and bundle assumptions.
- **Hash / Fiat-Shamir model:** ROM is the baseline theorem model. QROM is a deferred strengthening, not an inherited default.
- **Extractor model:** rewinding extractor for baseline knowledge soundness; Straight-line extraction is not claimed.
- **Composition scope:** sequential composition with P4 and P2 is the required baseline claim; universal composability is not claimed.

## Threat Model Matrix

| Dimension | Baseline | Why it is fixed |
| --- | --- | --- |
| Adversary model | Malicious participants up to `t-1`, plus public verifier-observers that see the full transcript | Matches the frozen P4 honest-majority interface and prevents assumption drift on who may deviate |
| Rushing behavior | Yes: the adversary may see honest round messages before scheduling corrupted-party responses within the same round | Consistent with P4's synchronous rushing model and prevents hidden reliance on non-rushing delivery |
| Static corruption | Required baseline | P4 already freezes static corruption; P1 must not silently upgrade to adaptive corruption or silently rely on weaker semi-honest behavior |
| Adaptive corruption | Not required in the baseline | Without erasures, post-facto witness exposure would invalidate simulator/extractor claims across P4→P1 handoff |
| Random oracle model | ROM baseline | Most realistic P1 candidates in the prior-art screen rely on Fiat-Shamir analyses in ROM; this is the minimal consistent model today |
| QROM | Not required in the baseline; treat as future hardening target | Avoids overclaiming quantum-robust Fiat-Shamir security that the current candidate set does not uniformly provide |
| Soundness flavor | Knowledge soundness is required, not plain soundness alone | P2 folding needs accepted base proofs to witness a real decrypt-share relation, not only acceptance without extractability |
| Simulation-soundness | **Not required for the baseline sequential-composition claim** | P2 LatticeFold+ consumes prover-generated P1 proofs and does not rely on simulated accepting P1 transcripts being re-used adversarially; the required property is extraction from accepted base proofs, not simulation-extractability. If a later P2 design simulates accepting P1 transcripts before adversarial continuation, this row must be upgraded explicitly across both P1 and P2. |
| Zero-knowledge target | NIZK target remains standard zero knowledge; no downgrade to HVZK | Public verifiers and non-interactive transcripts remove the honest-verifier restriction from the deployment model |
| Extractor model | Rewinding extractor | Baseline lattice Fiat-Shamir PoK candidates most naturally support rewinding-based extraction; this is sufficient for the current sequential, non-UC claim |
| Straight-line extractor model | Not required in the baseline | Straight-line extraction would usually travel with stronger simulation-sound / UC-style machinery that the current P1 shortlist does not justify |
| Composability with P4 | Required: sequential composition with P4 T5 corruption interface and transcript semantics | P1 statements must bind the same `session_id`, participant identity, threshold, and blame/exclusion state exported by the P4 bundle |
| Composability with P2 | Required: P2 may fold only statements already fixed here | Prevents P2 from silently changing witness semantics, oracle model, or extractor assumptions when aggregating P1 proofs |
| Concrete FHE parameter exposure | Public statement must bind `q`, ring degree `N`, error bound / norm bound, and any challenge/statement domain separators | Prevents witness drift where a prover proves one modulus/ring/noise regime but P2/P3 verify another |

## Success Metrics

- The P1 research gate can mechanically confirm that the threat model artifact exists and fixes the adversary model, extractor model, and a dedicated Simulation-soundness row.
- The document remains consistent with `.sisyphus/research/p4/threat-model.md` and `.sisyphus/contracts/p4-to-p1-bundle.md` on threshold, corruption timing, rushing behavior, and sequential-composition semantics.
- The document states whether simulation-soundness is required and why, rather than leaving that dependency implicit.
- The document makes concrete FHE parameter exposure part of the public statement, rather than leaving `q`, ring degree, and error bounds as ambient engineering choices.

## Downstream Outputs

- **For P2:** fold only P1 proofs whose public statement binds `(session_id, participant_id, threshold, q, N, error bound)` and whose baseline security claim is ROM knowledge soundness with a rewinding extractor.
- **For P3:** on-chain verification may assume only the folded statement/proof exported by P2, not stronger hidden properties of the underlying P1 proof.
- **For P4→P1 sequential composition:** the corruption set, authenticated transcript identifiers, and blame/exclusion semantics remain inherited from P4 T5 without reinterpretation.
- **For future upgrades:** any move to adaptive corruption, QROM, simulation-extractability, or straight-line extraction must be declared as a cross-phase upgrade touching both P1 and P2/P4 documentation rather than a local P1 edit.
