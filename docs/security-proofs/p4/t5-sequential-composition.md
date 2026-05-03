# P4-T5 Sequential Composition Proof

## Theorem

**Theorem (P4-T5 — UC-style Sequential Composition).** Let $n \in \{128,512,1024\}$, let $t = \lfloor n/2 \rfloor + 1$, let $F_{\mathrm{PVSS}}$ denote the ideal functionality for the P4 public-verifiable key-generation component, and let $F_{\mathrm{DEC}}$ denote the ideal functionality for the downstream publicly verifiable decrypt-share component from P1. For the current Hermine simulation, the state exported by the P4 interface—`KeygenSession`, accepted `Share` objects, accepted `PublicVerificationArtifact` objects, any resulting `BlameProof`, and the derived `BFVPublicKey` placeholder—forms a transcript-consistent handoff to the downstream P1 interface. Consequently, if the downstream P1 protocol securely realizes its decrypt-share functionality when initialized from that exported state, then the sequential execution “run P4, then run P1 on the resulting state” is indistinguishable from the corresponding ideal sequential composition, up to the distinguishing advantage of the two standalone realizations.

## Proof

### Status

Status: Proven

### Proof Technique

Instantiation of the standard UC sequential-composition theorem with an explicit handoff invariant specialized to the concrete P4 session data structures exported by the implementation and threat model.

### Reduction Target

The reduction target is the ordinary sequential-composition theorem itself plus the interface invariant that the P4 output state is exactly the information P1 is allowed to consume. No extra cryptographic reduction is needed for the implemented simulation because the exported `BFVPublicKey` is an explicit byte string and the corruption/blame state is carried by ordinary Rust data structures.

### Proof

The threat model in `.sisyphus/research/p4/threat-model.md` already fixes the required handoff: $F_{\mathrm{PVSS}}$ must export public-key material, party identities, corruption state, and blame outcomes in a form consumable by downstream $F_{\mathrm{DEC}}$. The frozen P4 interface and the implementation satisfy that requirement directly.

First, `KeygenSession` carries the session identifier, threshold, participant list, and raw session-id bytes. This is exactly the public provenance information needed to tell a downstream functionality which key-generation session produced the key material.

Second, `Share` carries the session identifier, threshold, participant identity, secret-share value, and commitment. In the current simulation these are plain values rather than encrypted witnesses. That means the downstream environment does not depend on hidden side state from P4: everything P1 may need to reference from P4 is already explicit in serialized session objects.

Third, `PublicVerificationArtifact` carries the common public transcript fragment for the dealer: session identifier, commitment vector, and dealer identity. `BlameProof` carries the session identifier, blame reason, accused identity, and evidence bytes. Together these two types encode exactly the public acceptance / abort-with-blame outcome that the threat model requires the simulator to hand off.

Fourth, `reconstruct_bfv_key` emits a `BFVPublicKey` consisting solely of the big-endian bytes of the reconstructed constant term. In the current milestone this byte string is the downstream key handle. There is no hidden trapdoor, randomness tape, or undisclosed witness that P1 would need but P4 fails to export. Hence public-key provenance preservation is immediate for the simulation: all downstream-visible key state is contained in the exported `BFVPublicKey` bytes plus the public session transcript.

These observations establish the handoff invariant: after P4 finishes, the entire downstream-relevant state is the tuple

$$
(\mathsf{session}, \mathsf{shares}, \mathsf{artifact}, \mathsf{blame}, \mathsf{pk}),
$$

where each component is already represented by a first-class interface type. The tuple determines (i) which parties are in the session, (ii) what threshold applies, (iii) which public transcript was accepted, (iv) whether any blame outcome occurred and against whom, and (v) what public-key bytes are exported. There is therefore no ambiguity for the downstream simulator about which parties are corrupted, blamed, excluded, or still eligible: that information is encoded by the same transcript and blame objects the P4 simulator outputs, exactly as required by the threat model's composition clause.

With that invariant fixed, the standard sequential-composition theorem applies. Replace the real P4 execution by its ideal functionality $F_{\mathrm{PVSS}}$ together with the P4 simulator. Because the simulator exports the same downstream-visible tuple above, the environment's view changes by at most the standalone P4 distinguishing advantage. Then run the downstream P1 protocol on that exported state and replace it by its ideal functionality $F_{\mathrm{DEC}}$ together with the P1 simulator. Since the input interface presented to P1 is unchanged by the first replacement except for a computationally indistinguishable distribution, the second replacement changes the environment's view by at most the standalone P1 distinguishing advantage. By triangle inequality, the total distinguishing gap is at most the sum of those two standalone advantages.

The theorem is intentionally limited to the current simulation. In particular, the exported `BFVPublicKey` is not yet an RLWE public key, and the downstream claim is therefore about clean interface composition of the simulated implementation rather than about composition of a final real-RLWE keygen. But for the code that exists today, the required sequential handoff invariant holds exactly, so the UC-style sequential composition argument closes.

### Unresolved Lemmas

None. The state-handoff invariant is explicit in the interface types, the public-key provenance claim reduces to the fact that `BFVPublicKey` is fully explicit serialized output, and blame/exclusion compatibility is represented directly by the exported `BlameProof` and session metadata.

### Open Questions

- When the simulated `BFVPublicKey` placeholder is replaced by a real RLWE/BFV public key, this theorem must be revisited to ensure the downstream decrypt-share functionality receives all necessary public parameters and noise-bound metadata.
- If future work upgrades the corruption model from static to adaptive, the handoff invariant will need to incorporate erasure/forward-security assumptions already flagged in the P4 threat model.
