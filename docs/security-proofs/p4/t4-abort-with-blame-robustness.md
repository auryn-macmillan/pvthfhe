# P4-T4 Abort-with-Blame Robustness Skeleton

## Theorem

**Theorem (P4-T4 — Abort-with-Blame Robustness).** Let $\mathcal{A}$ be a static PPT adversary corrupting at most $t-1$ parties in a synchronous execution of P4. If a dealer or participant deviates from the protocol by publishing malformed dealing data, inconsistent openings, or conflicting authenticated messages covered by the blame predicates, then except with negligible probability the protocol either continues with a valid transcript or aborts while outputting an accepted `BlameProof` that names at least one guilty corrupted party. Moreover, except with negligible probability, no honestly generated transcript causes an honest party to be accepted as blamed by the public blame verifier.

## Proof

### Status

Status: Skeleton

### Proof Technique

Case analysis over deviation types, proving blame completeness for each detectable fault and non-frameability for honest parties.

### Reduction Target

Authentication integrity, transcript agreement, and soundness of the public consistency checks and blame-verification predicates.

### Strategy

1. Enumerate the covered deviation classes: malformed dealer publication, inconsistent opening/decryption, and equivocation across authenticated messages in one `KeygenSession`.
2. For each deviation class, show that honest observers can derive a transcript slice and evidence bundle that instantiate a valid `BlameProof` against the deviating identity.
3. Prove that if blame verification accepts against an honest party, then either authentication was forged, transcript agreement was broken, or a public proof/consistency predicate accepted false evidence.
4. Combine the case analyses to obtain attributable aborts rather than silent failure whenever a covered malicious action triggers abort.
5. Separate robustness from liveness by conditioning on the synchronous authenticated network assumptions already fixed in the threat model.

### Unresolved Lemmas

- **Unresolved Lemma 1 (Blame Completeness for Malformed Dealings).** Any malformed accepted-or-challenged dealer publication yields publicly replayable evidence sufficient for a valid `BlameProof`.
- **Unresolved Lemma 2 (Equivocation Detection under Authenticated Transcript).** Two conflicting authenticated messages from the same identity in one session imply a publicly verifiable blame condition.
- **Unresolved Lemma 3 (Non-Frameability of Honest Parties).** Any accepted `BlameProof` against an honest party implies a break of authentication, transcript agreement, or proof soundness.

### Open Questions

- Which deviation classes are explicitly in scope for the first blame verifier release versus deferred to later robustness work.
- Whether omission faults need a separate timeout lemma under partial synchrony, even though the baseline theorem is synchronous.
