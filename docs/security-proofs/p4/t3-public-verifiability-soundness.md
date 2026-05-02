# P4-T3 Public Verifiability Soundness Skeleton

## Theorem

**Theorem (P4-T3 — Public Verifiability Soundness).** Let $n$, $t$, and the P4 interface objects be as above. For every PPT adversary $\mathcal{A}$ controlling any dealer and any subset of participants of size at most $t-1$, the probability that $\mathcal{A}$ causes the public verification algorithm to accept a `PublicVerificationArtifact` and associated transcript that do not correspond to a valid dealing for the claimed dealer, session identifier, threshold, participant set, share commitments, and ciphertext formation constraints is negligible. Equivalently, except with negligible probability, acceptance by any verifier implies existence of an underlying witness making the dealing valid in the sense of the P4 threat model.

## Proof

### Status

Status: Skeleton

### Proof Technique

Soundness-by-extraction: from any accepting invalid transcript, extract a witness or derive a contradiction against commitment binding or proof-system soundness.

### Reduction Target

Binding/extractability of the commitment layer and soundness or knowledge soundness of the proof system embedded in `PublicVerificationArtifact`.

### Strategy

1. Formalize what it means for a public transcript to be accepting yet invalid: all deterministic checks pass, but no witness exists satisfying the share-distribution and ciphertext-consistency relations.
2. Construct an extractor that operates on an accepting transcript and recovers a candidate witness for the dealer statement, share commitments, and proof bytes.
3. Show that if the extracted witness is invalid, then either the commitments admit two inconsistent openings or the proof system accepted a false statement.
4. Reduce the first case to a binding failure and the second case to soundness/knowledge-soundness failure of the proof system.
5. Conclude that any accepting transcript must correspond to a valid dealing except with negligible probability.

### Unresolved Lemmas

- **Unresolved Lemma 1 (Transcript Extractor for Accepted Artifacts).** From any accepting `PublicVerificationArtifact`, one can extract witness data sufficient to test semantic dealing validity.
- **Unresolved Lemma 2 (Commitment Binding for Share Commitments).** No PPT adversary can open the same published commitment vector to two inconsistent share/dealing witnesses.
- **Unresolved Lemma 3 (Semantic Validity from Extracted Witness).** The extracted witness implies the exact validity condition required by the threat model, not merely syntactic consistency.

### Open Questions

- Whether the deployed proof object should be modeled as extractable NIZK, argument of knowledge, or Fiat-Shamir transformed sigma protocol.
- How much soundness slack is introduced when verification is public and non-interactive at $n=1024$ scale.
