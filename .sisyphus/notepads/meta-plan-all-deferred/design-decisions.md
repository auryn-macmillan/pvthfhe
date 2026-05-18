# G.1-G.5: d_commitment Hash Chain — Design Decisions

**Status**: DESIGN COMPLETE (2026-05-18)
**Next**: Implementation (estimate: ~4 days)

## Decisions

| # | Question | Decision | Rationale |
|---|----------|----------|-----------|
| (1) | Scope of d_commitment | **Full**: bind all 10+ pipeline steps | Covers keygen, NIZK proofs, fold accumulators, compressed proof, ciphertext, plaintext |
| (2) | Circular binding fix | **Hybrid**: Interfold issues session nonce; prover must absorb it into d_commitment | Breaks circularity without 2-phase protocol; nonce is generated up-front when committee is requested |
| (3) | Share verification in Noir | **Schnorr signatures over BN254** verified in-circuit (~3K constraints/sig); combined_share_hash bound to d_commitment | Cheap in-circuit; signatures bind shares to party_ids registered at keygen |
| (5) | Share-to-sender binding | **Schnorr signatures** per share, verified in Noir circuit | ~3K constraints per sig × n=128 = ~384K, fits compressor budget |
| (4) | Threshold enforcement | **Exactly t+1 shares**, random selection in e2e demo | Circuit asserts `count(used) == t+1` |
| (6) | C7 + CycloFold composition | **Hash chain**: separate circuits, CycloFold absorbs `hash(C7_final_state)` as external input | ~1-2 days; on-chain verifier checks both proofs, cryptographically chained |
| (7) | IND-CPAD | **Heuristic argument**: document noise flooding bound, cite literature, note formal reduction as future work | ~2-3 hours |

## Implementation Order

1. G.16 — Hash chain between C7 and CycloFold (prerequisite for G.30)
2. G.1 — Canonicalize d_commitment hash (POSISEON bind_8_with_domain_native, domain 6)
3. G.4 — Add session_nonce absorption (Interfold placeholder until registry exists)
4. G.2 — Extend d_commitment field set to all pipeline steps
5. G.3/G.5 — End-to-end verification + Fiat-Shamir absorption
6. G.6/G.7/G.8 — Noir circuit constraints (party_ids binding, threshold enforcement, share sig verification)
7. G.12 — Schnorr signature infrastructure (keygen registration + per-share signing)
8. G.20 — Prover randomness / verifier challenge in C7 challenge derivation
9. G.30 — Counter consistency enforcement
10. G.26 — IND-CPAD heuristic documentation

## Prerequisite for G.12 (Signatures)

Before G.12 can be implemented:
- Each party needs a BN254 keypair registered during keygen
- The aggregator needs to verify signatures before accepting shares
- The Noir circuit needs Schnorr verification gadget (~3K constraints)
- `party_pk_hash` must be added to d_commitment (as part of pipeline binding in G.2)
