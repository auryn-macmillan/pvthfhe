# P1-T3 Full Zero-Knowledge Roadmap

**Created**: 2026-05-13
**Updated**: 2026-05-13 (proof docs improved with NIZK change log)
**Status**: OPEN (scope expansion — requires threat model decision)
**Paper reference**: §5 (P1), theorem P1-T3; claims-table footnote

## Implementation Status (2026-05-13)

P1-T3 remains a design question. The current threat model (`SECURITY.md`) accepts audit-field exposure (`secret_share_open`, `error_open`). NIZK improvements (sigma equation hardening, decrypt witness binding, dealer identity) do not change the ZK scope — they strengthen soundness, not zero-knowledge.

Milestone M1 (threat model analysis) is the gating decision: if audit-field exposure is acceptable for the PVTHFHE threat model, this plan reduces to a documentation task. If full ZK is required, milestones M2-M5 become implementation scope.

**No implementation is possible without the M1 decision.** This plan serves as a design discussion and documentation artifact.

## Goal

Expand the P1 zero-knowledge guarantee from the current projected SLAP core scope (covering only `t_bytes`, `z_s`, `z_e`) to full zero-knowledge covering all witness-derived fields in the serialized P1 proof, including `secret_share_open` and `error_open`.

## Current State

P1-T3 is currently PROVED for the projected SLAP core transcript only (`docs/security-proofs/p1/T3.md`, VERDICT: APPROVE). The audit fields `secret_share_open` (PVSS secret share opening) and `error_open` (full error vector opening) are explicitly excluded from the ZK claim and serialized in the P1 proof bytes for transparency. This is acceptable for the frozen P1→P2 interface (the P2 fold hashes over the opaque proof bytes and does not extract these fields), but a full ZK guarantee would be required for broader protocol composability.

## Blocked Dependencies

| Dependency | Status |
|-----------|--------|
| Audit transparency requirement | DESIGN choice — full ZK conflicts with auditability |
| P2 interface stability | Frozen — changing proof bytes format breaks P2 fold |
| Protocol scope decision | Open — is full ZK needed for the threat model? |

## Research Milestones

1. **M1: Threat model analysis** — Determine whether `secret_share_open` and `error_open` exposure violates the PVTHFHE security model. These fields are public in the current design by choice (audit transparency), not by oversight.

2. **M2: Redactable proof format** — Design a P1 proof serialization format that supports two modes:
   - Audit mode: includes `secret_share_open` and `error_open` (current)
   - ZK mode: replaces audit fields with zero-knowledge commitments or removes them

3. **M3: Extended ZK simulator** — Extend the HVZK simulator (`docs/security-proofs/p1/T3.md` Lemma 2) to cover the audit fields, either by:
   - Simulating commitment openings for the audit fields, or
   - Proving that the audit fields are independently simulatable from public data

4. **M4: P2 interface compatibility** — Ensure the redacted proof format is compatible with the P2 fold accumulator. May require versioned proof bytes or a separate proof type.

5. **M5: Formal proof** — Produce a self-contained proof of full ROM zero-knowledge for the complete P1 proof.

## Estimated Effort

~3–6 weeks. The design decision in M1 may make this unnecessary: if the threat model accepts audit-field exposure (as the current SECURITY.md does), this plan becomes a documentation task rather than an implementation task.

## Cross-references

- `docs/security-proofs/p1/T3.md` — Current P1-T3 proof (projected core only)
- `docs/security-proofs/p2/T3.md` — P2 ZK preservation (APPROVE, same scope)
- `SECURITY.md` §Threat Model — Current threat model assumptions
- `WARNING.md` — Known surrogates and limitations
