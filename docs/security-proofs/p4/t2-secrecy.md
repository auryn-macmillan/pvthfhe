# P4-T2 Secrecy Skeleton

## Theorem

**Theorem (P4-T2 — Secrecy of Secret-Key Material).** Let $n \in \{128,512,1024\}$, let $t = \lfloor n/2 \rfloor + 1$, and let $\mathcal{A}$ be a static PPT adversary corrupting a set $C \subseteq [n]$ with $|C| \le t-1$. In the P4 PVSS key-generation protocol, the joint view of $\mathcal{A}$—including corrupted-party states, all accepted `PublicVerificationArtifact` values, all accepted ciphertext-bearing `Share` values addressed to corrupted parties, the common transcript, and any accepted `BlameProof` objects—reveals no information about the honest parties' residual secret-key material beyond what is implied by the public transcript. More precisely, there exists a PPT simulator $\mathcal{S}$ such that the real view of $\mathcal{A}$ is computationally indistinguishable from the simulated view produced from only the public transcript, corruption set, and ideal outputs, assuming the underlying RLWE/Ring-LWE problem is hard.

## Proof

### Status

Status: Skeleton

### Proof Technique

Simulation-based privacy proof with hybrid games replacing honest encrypted shares and transcript-bound witness material.

### Reduction Target

Ring-LWE / RLWE hardness for the encryption layer, combined with threshold privacy of the sharing relation against sets of size at most $t-1$.

### Strategy

1. Define the real secrecy experiment exposing the full corrupt-party view for a fixed corruption set of size at most $t-1$.
2. Replace honest-share ciphertext payloads with encryptions of zeros or simulated placeholders while preserving the same public statement structure in `PublicVerificationArtifact`.
3. Argue that each replacement is indistinguishable under RLWE hardness and transcript-binding of the proof objects.
4. Use threshold privacy of the underlying sharing relation to show that even information-theoretically, corrupted parties lack enough shares to reconstruct honest secret-key material.
5. Assemble the hybrids into a simulator that outputs a transcript-consistent adversarial view without access to honest residual secrets.

### Unresolved Lemmas

- **Unresolved Lemma 1 (Hybrid Replacement for Encrypted Shares).** Replacing honest encrypted shares with simulated ciphertexts changes the adversary's advantage by at most an RLWE-negligible amount.
- **Unresolved Lemma 2 (Proof Simulation Compatibility).** The proof objects inside each accepted `PublicVerificationArtifact` remain indistinguishable when witness data for honest shares is simulated.
- **Unresolved Lemma 3 (Threshold Privacy over the Chosen Share Space).** Any coalition of at most $t-1$ corrupted parties learns no information about the honest secret-sharing polynomial beyond the public transcript.

### Open Questions

- Whether the simulator needs explicit programmability of transcript challenges in ROM/QROM variants.
- How to phrase secrecy when blame evidence reveals partial consistency relations after an abort.
