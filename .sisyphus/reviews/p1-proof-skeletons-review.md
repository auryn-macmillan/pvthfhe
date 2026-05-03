# External Advisor Memo — P1 Proof Skeletons

**Reviewer**: Agent Self-Review acting as external-advisor draft
**Date**: 2026-05-03
**Artifact**: `docs/security-proofs/p1/proof-skeletons.md`

## Summary

The proof-skeleton package now states T1–T5 against the frozen SLAP primary stack using the exact P1 public statement and witness relation from the interface spec. Each theorem names the parameter tuple `(q, N, B_e, k)`, states the applicable assumption surface (M-LWE, M-SIS, ROM), and gives a theorem-specific reduction outline instead of generic appeals to “standard arguments”. The baseline package is internally consistent with the threat model: ROM is the default model, the extractor is rewinding-based, and simulation-extractability remains an optional upgrade rather than an overclaimed baseline property.

## T2 Extractor Soundness

The T2 section is structurally sound as a knowledge-soundness skeleton for Fiat–Shamir SLAP. It explicitly names the forking/re-winding extractor, identifies the decisive random-oracle query, and derives two accepting transcripts with the same first message and distinct challenges. The reconstruction step from affine responses to a candidate witness is clearly separated from the post-extraction validation step that checks both the RLWE equation and the inherited SHA-256 commitment binding. That separation is important: it makes explicit that an adversary can fail extraction either by inducing an M-SIS contradiction, by exploiting an M-LWE hiding failure in the concrete SLAP masking layer, or by violating the inherited commitment binding. The extraction probability is bounded with the usual quadratic forking loss and challenge-guess term, which is the correct baseline ROM claim.

## T3 Simulator Validity

The T3 skeleton correctly treats the theorem as a statement about the Fiat–Shamir transform applied to SLAP, not merely about HVZK of the underlying interactive protocol. The simulator first obtains an accepting interactive transcript from the HVZK simulator and then programs the random oracle at the exact Fiat–Shamir query point so the non-interactive verifier reconstructs the same challenge. The proof also isolates the two indispensable loss terms: HVZK indistinguishability for the underlying protocol and the random-oracle programming collision term. The uniform-challenge argument is present and correctly explains why programming the oracle with the simulator's challenge preserves the expected verifier distribution.

## T5 Batch Loss

The T5 skeleton states the exported amortization budget explicitly instead of hiding it inside prose. The failure probability is decomposed into the aggregation-combiner error `ε_agg` and the linear `m · ε_base-ext` carry-over from single-instance extraction. The reduction also identifies the exact extra proof burden introduced by batching: either random linear combination accidentally cancels a bad component, or a concrete component remains isolatable and therefore reducible to T2. This is the right downstream statement for P2, because it tells the next phase exactly how much soundness loss is paid when batched P1 proofs are folded.

## Open Questions

1. The final full proof will need the concrete SLAP response equations and challenge domain to justify the algebraic inversion step in T2 without leaving any hidden non-zero-divisor assumptions.
2. If the chosen SLAP instantiation uses an M-LWE-style masking layer only for zero knowledge, the full proof should separate that term sharply from the M-SIS extraction core so the assumptions table remains crisp.
3. If Phase P2 later changes the adversarial interface to expose simulated accepting P1 proofs, T4 must be promoted from an optional upgrade note into a real theorem with a stronger transform and a fresh loss bound.

VERDICT: APPROVE
