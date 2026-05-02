# P4-T5 Sequential Composition Skeleton

## Theorem

**Theorem (P4-T5 — UC-style Sequential Composition).** Let $F_{\mathrm{PVSS}}$ denote the ideal functionality for the P4 public-verifiable key-generation component and let $F_{\mathrm{DEC}}$ denote the ideal functionality for the downstream publicly verifiable decrypt-share component. Assume the P4 real protocol securely realizes $F_{\mathrm{PVSS}}$ with a simulator that exports transcript-consistent public key material, corruption state, blame outcomes, and party eligibility metadata in the form required by the P1 interface. Assume further that the P1 decrypt-share protocol securely realizes $F_{\mathrm{DEC}}$ when initialized with such exported state. Then the sequential composition that first runs P4 to produce a `BFVPublicKey` and then runs P1 on the resulting key state UC-realizes the ideal sequential composition of $F_{\mathrm{PVSS}}$ followed by $F_{\mathrm{DEC}}$, up to negligible distinguishing advantage.

## Proof

### Status

Status: Skeleton

### Proof Technique

UC sequential-composition theorem instantiated with an explicit state-handoff invariant between the P4 and P1 simulators.

### Reduction Target

Security of the standalone realization of $F_{\mathrm{PVSS}}$, security of the standalone realization of $F_{\mathrm{DEC}}$, and correctness of the interface-handoff invariant connecting them.

### Strategy

1. Define the exported state of P4: `BFVPublicKey`, session identifier, participant identities, corruption set, blame outcomes, and downstream eligibility flags.
2. State the simulator handoff invariant ensuring that the P1 simulator receives exactly the same corruption interface and public-key provenance that the ideal-world composition exposes.
3. Apply the UC sequential-composition theorem to replace the real P4 subprotocol with $F_{\mathrm{PVSS}}$ while preserving the environment's view.
4. Apply the same theorem again to replace the downstream decrypt-share protocol with $F_{\mathrm{DEC}}$ on the handed-off state.
5. Bound the environment's overall distinguishing advantage by the sum of the standalone distinguishing advantages plus any handoff-invariant error term.

### Unresolved Lemmas

- **Unresolved Lemma 1 (State-Handoff Invariant).** The P4 simulator exports exactly the transcript-consistent corruption and eligibility state assumed by the P1 simulator.
- **Unresolved Lemma 2 (Public-Key Provenance Preservation).** The `BFVPublicKey` emitted by P4 is sufficient, without hidden side channels, to initialize the downstream decrypt-share functionality.
- **Unresolved Lemma 3 (Blame/Exclusion Compatibility Across Phases).** Parties blamed or excluded in P4 are represented consistently in the downstream sequential ideal functionality.

### Open Questions

- Whether the final statement should quantify over a stronger adaptive environment once corruption is extended beyond the current static baseline.
- How to model sequential aborts where P4 terminates with blame and P1 is never invoked, while keeping the composed ideal functionality simple.
