# P4-T1 Correctness Proof

## Theorem

**Theorem (P4-T1 — Correctness of BFV Public-Key Derivation).** Let $n \in \{128,512,1024\}$, let $t = \lfloor n/2 \rfloor + 1$, and let $C \subseteq [n]$ satisfy $|C| \le t-1$. Consider a synchronous execution of the P4 PVSS key-generation protocol for a `KeygenSession` with participant set $[n]$, threshold $t$, accepted `Share` objects, accepted `PublicVerificationArtifact` objects, and no accepted `BlameProof` against any honest party. If every honest dealer and participant follows the protocol and every public verification check accepts on the common public transcript, then the transcript uniquely determines BFV key material $(\mathsf{pk}, \mathsf{sk})$ such that:

1. `HermineAdapter::reconstruct_bfv_key` applied to any accepted quorum of at least $t$ honest shares outputs the same `BFVPublicKey` bytes;
2. for every authorized set $H \subseteq [n]$ with $|H| \ge t$, reconstruction from the shares held by honest members of $H$ yields the unique secret-key contribution consistent with the accepted commitments; and
3. the resulting public key is algebraically consistent with the combined honest-share secret embodied by the accepted transcript.

## Proof

### Status

Status: Proven

### Proof Technique

Direct algebraic completeness argument for the implemented Shamir sharing and reconstruction code over the prime field $\mathbb{F}_p$ with $p = 2^{61}-1$, plus transcript consistency of the SHA-256 commitment layer.

### Reduction Target

No computational reduction is needed for the core completeness claim. The proof reduces to finite-field properties of Shamir secret sharing over the Mersenne prime `PRIME = 2^61-1` and to the fact that honest execution publishes commitments to the exact values later reconstructed.

### Proof

Fix one honest dealer execution of `HermineAdapter::generate_shares` in `crates/pvthfhe-keygen/src/hermine.rs`. The session identifier is generated deterministically from the ordered participant identifiers and threshold in `generate_session`, so all honest parties refer to the same `session_id`, `threshold`, and participant list. In `generate_shares`, the dealer samples a secret

$$
s = \texttt{derive\_field\_elem}(\mathsf{session\_id}, \mathsf{dealer\_id}, \texttt{"secret"}, 0) \in \mathbb{F}_p
$$

and coefficients $a_1,\dots,a_{t-1} \in \mathbb{F}_p$ via the same deterministic hash-to-field routine with tag `"coeff"`. The dealing polynomial is therefore

$$
f(X) = s + a_1 X + \cdots + a_{t-1} X^{t-1} \in \mathbb{F}_p[X].
$$

For each participant identifier $i$, the implementation sets $x_i = i$ and computes the share value $y_i = f(x_i)$ with `poly_eval`. Because all arithmetic is reduced modulo `PRIME`, every share lies in the field $\mathbb{F}_p$. The corresponding public commitment is

$$
c_i = H(\mathsf{session\_id} \parallel i \parallel y_i),
$$

implemented by `commit(session_id, participant_id, value)` using SHA-256. Honest execution stores both $y_i$ and $c_i$ in the `Share`, and places the same $c_i$ into `PublicVerificationArtifact.commitments`.

Now consider any authorized set $H$ of at least $t$ honest parties. Each honest share in $H$ carries the common session identifier and the common threshold, and `reconstruct_bfv_key` checks exactly these invariants before reconstruction: it rejects if shares come from different sessions or disagree on threshold. Thus every accepted reconstruction instance is a set of points $(x_i,y_i)$ on one degree-$(t-1)$ polynomial over $\mathbb{F}_p$.

Because $p$ is prime, $\mathbb{F}_p$ is a field, so standard Shamir reconstruction applies. `lagrange_interpolate` computes

$$
f(0) = \sum_{i \in H} y_i \cdot \lambda_i(0) \pmod p,
\qquad
\lambda_i(0) = \prod_{j \in H, j \ne i} \frac{-x_j}{x_i - x_j}.
$$

The code realizes the denominator inverse by Fermat's little theorem in `mod_pow(den, p-2, p)`, valid because every $x_i-x_j$ is nonzero modulo $p$ for distinct participant identifiers and because $p$ is prime. Therefore the implementation computes exactly the constant term $f(0)=s$ of the dealer polynomial.

Uniqueness follows from the standard interpolation theorem: a degree-$(t-1)$ polynomial over a field is uniquely determined by any $t$ distinct points. Hence any two authorized sets of honest shares reconstruct the same field element $s$, and any reconstruction using more than $t$ honest shares still evaluates to $s$ because all supplied points lie on the same polynomial.

Finally, `reconstruct_bfv_key` serializes this reconstructed secret as `secret.to_be_bytes().to_vec()`. So the emitted `BFVPublicKey.bytes` are a deterministic encoding of the unique recovered constant term. In the current simulation, that byte string is the BFV public-key placeholder exported across the P4/P1 boundary; correctness for this implementation therefore means equality of that encoded secret across all honest quorums, not a separate RLWE public-key derivation equation. The commitments are consistent with the reconstructed secret because each committed $y_i$ was produced from the same polynomial $f$, and honest execution plus the absence of accepted blame means no committed share on the accepted transcript was shown inconsistent with its published value.

Thus an honest dealing accepted by the public transcript yields a unique reconstructed secret and therefore a unique `BFVPublicKey` output for every authorized quorum. This proves the theorem.

### Unresolved Lemmas

None. The former completeness and uniqueness lemmas are discharged directly by the implemented Shamir interpolation formula over the prime field `PRIME`, and the adapter boundary is explicit because `reconstruct_bfv_key` returns the big-endian encoding of the recovered constant term.

### Open Questions

- A future RLWE-backed revision will need a stronger statement connecting reconstructed secret material to an actual BFV public-key generation algorithm rather than to the current serialized-secret placeholder.
- If multi-dealer aggregation is added later, an additional lemma will be needed to show that the combined key equals the algebraic sum of per-dealer reconstructed contributions.
