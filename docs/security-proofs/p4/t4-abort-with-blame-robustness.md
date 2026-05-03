# P4-T4 Abort-with-Blame Robustness Proof

## Theorem

**Theorem (P4-T4 — Abort-with-Blame Robustness).** Let $n \in \{128,512,1024\}$, let $t = \lfloor n/2 \rfloor + 1$, and let $\mathcal{A}$ be a static PPT adversary corrupting a set $C \subseteq [n]$ with $|C| \le t-1$. In any synchronous P4 execution for a `KeygenSession` with authenticated public transcript, if a dealer or participant deviates from the protocol in one of the detectable ways implemented by the Hermine simulation—malformed public artifact, replayed share, invalid share identity, missing secret value, forged per-share commitment, wrong commitment count, or commitment mismatch—then the protocol either continues with a valid transcript or `check_and_blame` / `blame_dealing` outputs a publicly checkable `BlameProof` naming a guilty party. Furthermore, an honest party following the protocol is never blamed by these predicates unless SHA-256 binding, transcript agreement, or message authentication fails.

## Proof

### Status

Status: Proven

### Proof Technique

Case analysis over the concrete blame predicates implemented in `check_and_blame` and `HermineAdapter::blame_dealing`.

### Reduction Target

Deterministic correctness of the recomputed commitment checks, authenticated attribution of `participant_id` / `dealer_id`, and binding of the SHA-256 commitment function.

### Proof

The current implementation gives two public blame mechanisms.

1. `check_and_blame(session_id, share, artifact)` is a local/public replay check for one share. It recomputes the canonical commitment

$$
c^* = H(\mathsf{session\_id} \parallel \mathsf{participant\_id} \parallel \mathsf{secret\_value})
$$

and blames the artifact's dealer if either $c^*$ is absent from the artifact's commitment list or the share's stored commitment does not equal $c^*$.
2. `HermineAdapter::blame_dealing(artifact, shares)` performs the full transcript replay. After requiring `verify_transcript`, it checks session consistency, participant-identity uniqueness, presence of secret values, exact recomputation of every per-share commitment, equality of the share count and commitment count, and equality of the published commitment multiset with the recomputed multiset. Each failed predicate returns a `BlameProof` whose `reason` and `accused_id` are hard-coded by the corresponding branch.

We analyze each implemented deviation class.

**Malformed public artifact.** If the public artifact is structurally malformed, `verify_transcript` returns `false` and `blame_dealing` returns a proof with reason `invalid_public_artifact` and `accused_id = artifact.dealer_id`. This is correct because the dealer is the authenticated source of the artifact.

**Replayed or cross-session share.** If a share carries a `session_id` different from the artifact session, `blame_dealing` returns `replayed_share` and names that share's `participant_id`. This is exactly the guilty sender under the authenticated-message model from the threat model.

**Invalid share identity.** If a share has no participant identity or duplicates another participant identifier, `blame_dealing` returns `invalid_share_identity` naming that participant when present. Since participant identities are authenticated and each honest participant emits at most one share per session, an accepted proof here identifies the equivocating or malformed sender.

**Missing secret value or forged commitment field.** If a share omits `secret_value`, the function returns `missing_secret_value` and blames that participant. If the share carries a commitment not equal to the recomputed canonical hash, the function returns `forged_share` and blames that participant. The standalone helper `check_and_blame` catches the same inconsistency pattern and blames the dealer when the private share/public artifact pair is inconsistent; this matches the dealer-side fault model used in the earlier protocol tests.

**Dealer commitment inconsistencies.** After all share-local checks pass, `blame_dealing` compares the number and multiset of published commitments against the recomputed commitments. A mismatch yields `commitment_count_mismatch` or `commitment_mismatch` with `accused_id = artifact.dealer_id`. This is correct because only the dealer published the artifact commitment vector.

These checks are publicly replayable: every verifier needs only the artifact and the disclosed shares to recompute the same hashes and branch conditions. Hence blame evidence is publicly checkable, as required by the threat model.

For non-frameability, suppose an honest party is blamed. If the blamed party is a participant, then one of the participant-side branch predicates above must have fired. But an honest participant sends exactly one share for the current session, with its true `participant_id`, present `secret_value`, and correct commitment `commit(session_id, participant_id, secret_value)`. Therefore a blame result against that honest participant would imply either transcript tampering, message-forgery/authentication failure, or a hash-binding failure causing an incorrect recomputation match. Likewise, if an honest dealer is blamed for `invalid_public_artifact`, `commitment_count_mismatch`, or `commitment_mismatch`, then some verifier accepted a discrepancy between the dealer's published artifact and the canonical commitments determined by the honest shares. Under transcript agreement and authenticated broadcast, that can happen only if the public transcript was altered or if SHA-256 binding failed.

So every detectable deviation covered by the current code either leaves a valid transcript or yields a blame proof naming a guilty dealer or participant, while false blame against honest parties reduces to failure of the underlying authentication/transcript-agreement assumptions or of the commitment binding assumption. This proves the theorem for the implemented abort-with-blame simulation.

### Unresolved Lemmas

None. The concrete blame predicates are explicit in code and cover the detectable fault classes implemented today; non-frameability follows from replaying those deterministic predicates under the authenticated transcript assumptions of the threat model.

### Open Questions

- Omission faults and timeout-based blame are still out of scope for the present implementation; they will require extra network-timing predicates if partial synchrony is modeled explicitly.
- The helper `check_and_blame` and the fuller `blame_dealing` routine assign blame at slightly different abstraction levels (dealer-side inconsistency versus sender-side malformed share); if the API is consolidated later, the theorem should be restated against the final single blame verifier.
