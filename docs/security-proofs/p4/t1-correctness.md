# P4-T1 Correctness Skeleton

## Theorem

**Theorem (P4-T1 — Correctness of BFV Public-Key Derivation).** Let $n \in \{128,512,1024\}$, let $t = \lfloor n/2 \rfloor + 1$, and let $C \subseteq [n]$ satisfy $|C| \le t-1$. Consider a synchronous execution of the P4 PVSS key-generation protocol for a `KeygenSession` with participant set $[n]$, threshold $t$, accepted `Share` objects, accepted `PublicVerificationArtifact` objects, and no accepted `BlameProof` against any honest party. If every honest dealer and participant follows the protocol and every public verification check accepts on the common public transcript, then the transcript uniquely determines BFV key material $(\mathsf{pk}, \mathsf{sk})$ such that:

1. `BfvPublicKeyDerivation` applied to the accepted session data outputs a `BFVPublicKey` equal to $\mathsf{pk}$;
2. for every authorized set $H \subseteq [n]$ with $|H| \ge t$, reconstruction from the shares held by honest members of $H$ yields the unique secret-key contribution consistent with the accepted commitments and ciphertexts; and
3. the resulting public key is algebraically consistent with the combined honest-share secret embodied by the accepted transcript.

## Proof

### Status

Status: Skeleton

### Proof Technique

Reduction-style correctness argument from threshold reconstruction uniqueness plus completeness of the public verification checks.

### Reduction Target

No hardness reduction is needed for the core completeness claim; the skeleton reduces to algebraic consistency of the underlying threshold-sharing relation and completeness of the public proof system bound into `PublicVerificationArtifact`.

### Strategy

1. Fix an accepting transcript for a `KeygenSession` and isolate the session identifier, threshold, participant list, and transcript root that bind every accepted `Share` and `PublicVerificationArtifact`.
2. Use public-verification completeness to infer that every honest dealer artifact is witness-consistent with some underlying share polynomial and BFV derivation label.
3. Apply uniqueness of threshold reconstruction to show that any authorized set of at least $t$ honest shares determines the same reconstructed secret contribution.
4. Show that the derivation procedure consuming the accepted shares is transcript-bound, so any successful derivation must output the unique `BFVPublicKey` compatible with the reconstructed secret and transcript root.
5. Conclude that honest execution yields a well-formed BFV public key and consistent key material for all authorized reconstructions.

### Unresolved Lemmas

- **Unresolved Lemma 1 (Transcript-to-Witness Completeness).** Every accepted honest `PublicVerificationArtifact` implies existence of a witness matching the committed share polynomial, ciphertext formation relation, and BFV derivation label.
- **Unresolved Lemma 2 (Authorized Reconstruction Uniqueness).** Any two authorized sets of size at least $t$ that reconstruct from accepted honest shares obtain the same secret-key contribution.
- **Unresolved Lemma 3 (Adapter Soundness for BFV Derivation).** The `BfvPublicKeyDerivation` boundary preserves the algebraic relation between reconstructed secret material and the emitted `BFVPublicKey`.

### Open Questions

- Which exact algebraic assumptions on the ring/field instantiation are needed to express uniqueness without overcommitting to a final backend?
- Whether malformed but accepting mixed transcripts require a separate consistency lemma for honest/deviating dealer interleavings.
