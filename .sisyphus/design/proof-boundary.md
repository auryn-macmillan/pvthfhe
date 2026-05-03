> ⚠️ FROZEN: This document is frozen as of Phase 2. Any change to the proof boundary requires a plan amendment.

# PVTHFHE Proof Boundary Freeze (T25)

## Status

- Phase: 2
- Architecture: B — Lattice PVSS + LatticeFold+ + MicroNova + UltraHonk
- Purpose: freeze exactly one primary enforcement layer per security property
- Source documents: T18 `spec-keygen.md`, T19 `spec-decrypt.md`, T22 `api-spec.md`, T24 `security-proofs.md`, and `arch-B-lattice-folding.md`

## High-level intuition

The proof boundary answers one question for every security claim in PVTHFHE: **where is the claim actually enforced?**

Architecture B spans four qualitatively different enforcement surfaces:

1. a lattice-native proof world for per-share statements,
2. Rust aggregation logic that can cheaply check transcripts and parameters,
3. a compact Noir/UltraHonk statement that binds the final public claim, and
4. the Solidity verifier that only sees public calldata and the compressed proof.

If the same property is treated as "checked everywhere," ownership becomes ambiguous and soundness-critical work tends to slip into glue code. If the property is forced into the wrong layer, either gas explodes, the prover becomes too expensive, or the protocol relies on a check the verifier cannot actually see. This document therefore assigns each property exactly one **primary** enforcement layer and treats every other check as secondary defense-in-depth.

The resulting rule is simple:

- use **D / Lattice-NIZK** for witness-heavy RLWE statements that are local to one share or to the folding accumulator,
- use **B / Rust aggregator** for transcript hygiene, replay checks, blame bookkeeping, and cheap algebra that is not worth proving on-chain,
- use **A / Inside Noir SNARK** for the final public statement that must remain succinct yet stronger than a mere parser check,
- use **C / Solidity** only for things the chain can and must validate from public calldata with very low gas.

This split is also how the Phase 2 cost envelope stays intact. T13 already spends about 3.65M gas on the KZG batch-128 verifier path, leaving only about 1.35M gas before the 5M target ceiling. Anything that can be handled in Rust or in the lattice proof world should not be re-expressed as a Solidity loop unless public verifiability strictly requires it.

## Enforcement layers

| Code | Layer | What it is good at | What it is bad at |
|------|-------|--------------------|-------------------|
| A | Inside Noir SNARK | Final succinct public statement, arithmetic consistency, threshold/public-input binding | Large per-party witness handling if it can stay outside |
| B | Outside-SNARK Rust check by aggregator | Transcript validation, epoch checks, cheap recomputation, blame evidence assembly | Public verifiability; cannot by itself convince the chain |
| C | Outside-SNARK on-chain Solidity check | ABI integrity, fixed public-parameter checks, final verifier invocation | Expensive loops, witness-heavy RLWE relations |
| D | Lattice-NIZK | Per-share RLWE well-formedness and folding-native statements | Currently exposed to Open P1/P2 soundness gaps |

## Scope of the frozen boundary

For Phase 2, the canonical proof-boundary ledger is the following exact set of 12 properties. Coverage is complete only when all 12 are assigned and none are left TBD or unassigned.

| ID | Property | Primary |
|----|----------|---------|
| PB-01 | Share well-formedness | D |
| PB-02 | NIZK correctness of each share | D |
| PB-03 | Threshold count | A |
| PB-04 | Aggregation linearity | D |
| PB-05 | Noise smudging applied correctly | B |
| PB-06 | Plaintext decoding correctness | A |
| PB-07 | Ciphertext freshness / replay prevention | B |
| PB-08 | Public key consistency | B |
| PB-09 | Blame identification | B |
| PB-10 | Proof binding | C |
| PB-11 | On-chain calldata integrity | C |
| PB-12 | Parameter consistency | C |

## Detailed property ledger

### PB-01
- Property: Share well-formedness
- Primary layer: D
- Secondary layers: B, A
- Security target: each partial decryption share must satisfy the RLWE relation shape expected by T19 before it can influence the folded proof.
- Cost vs soundness: this statement is witness-heavy and naturally local to one party share, so it belongs in the lattice-native proof layer instead of in Solidity or a global SNARK circuit.
- Why not a different primary layer: moving it to A would inflate the compressed circuit with per-share RLWE constraints, while C cannot inspect witness polynomials and B alone is not publicly sound.
- Status: OPEN — depends on P1 because lattice NIZK well-formedness soundness over the RLWE relation is not closed yet.
- Theorem linkage: T-DEC-SOUND and T-ROBUSTNESS.

### PB-02
- Property: NIZK correctness of each share
- Primary layer: D
- Secondary layers: B, A
- Security target: each party must prove that its published decryption share or keygen share is backed by a valid witness, not just structurally parseable bytes.
- Cost vs soundness: proof generation and verification are already modeled in the lattice proof stack; duplicating that witness relation inside UltraHonk would waste prover budget and violate the architecture boundary from `arch-B-lattice-folding.md`.
- Why not a different primary layer: B verifies the proof object but does not create soundness on its own, and C only sees the compressed end product rather than each party witness.
- Status: OPEN — also inherits P1 because per-share NIZK soundness is the unresolved cryptographic bottleneck.
- Theorem linkage: T-DEC-SOUND, T-PV-SOUND, and T-ROBUSTNESS.

### PB-03
- Property: Threshold count
- Primary layer: A
- Secondary layers: B, C
- Security target: the accepted public statement must imply that at least `t` valid shares were included, not merely that some proof blob was supplied.
- Cost vs soundness: binding the threshold claim inside the compressed SNARK keeps the final public statement succinct while avoiding a large on-chain loop over per-share witnesses.
- Why not a different primary layer: C can cheaply sanity-check `participantSet.length`, but only A can bind that count to the proof's accepted witness; B is not publicly verifiable.
- Status: CLOSED for boundary assignment, assuming the folded witness supplied to A is sound.
- Theorem linkage: T-DEC-SOUND and T-PV-SOUND.

### PB-04
- Property: Aggregation linearity
- Primary layer: D
- Secondary layers: A, B
- Security target: the aggregate share used for decryption must equal the prescribed linear combination of the included valid shares, with no hidden substitution by the aggregator.
- Cost vs soundness: the linear relation is native to the folding accumulator and should be discharged before compression rather than re-proved from scratch in Solidity.
- Why not a different primary layer: A can bind to the folded result, but the actual multi-share linearity argument is exactly the part that `security-proofs.md` calls out as `LatticeFold+ over RLWE (Open P2)`.
- Status: OPEN — depends on P2 because the folding soundness argument over RLWE aggregation is not yet proven.
- Theorem linkage: T-DEC-SOUND.

### PB-05
- Property: Noise smudging applied correctly
- Primary layer: B
- Secondary layers: D
- Security target: the accepted transcript must use the configured smudging envelope `σ_smudge = 2^40 · σ_err` and reject shares that are outside the agreed shortness/budget envelope.
- Cost vs soundness: exact sampling from a discrete Gaussian is not efficiently or cleanly made publicly verifiable here, so the practical enforcement point is Rust code that owns the epoch/config context and can reject out-of-policy shares before proving.
- Why not a different primary layer: D can prove existence of a short witness term, but it does not by itself certify that the witness was sampled from the ideal distribution; C has no visibility into the hidden error witness.
- Status: OPEN/PARTIAL — bounded-shortness is enforced, but exact distributional correctness remains an implementation assumption tied to T-IND-CPA's smudging lemma.
- Theorem linkage: T-IND-CPA and T-DEC-SOUND.

### PB-06
- Property: Plaintext decoding correctness
- Primary layer: A
- Secondary layers: C
- Security target: the published plaintext must be the correct rounding/decoding of `c0 + D mod q`, not an arbitrary message paired with an unrelated proof.
- Cost vs soundness: this is the canonical final arithmetic statement for the succinct proof, so it belongs inside the compressed SNARK where public inputs and witness-derived aggregate values meet.
- Why not a different primary layer: B can recompute it off-chain for debugging, but only A gives a succinct publicly checkable proof; C should merely verify the resulting UltraHonk proof rather than duplicate ring arithmetic.
- Status: CLOSED for boundary assignment.
- Theorem linkage: T-DEC-SOUND and T-PV-SOUND.

### PB-07
- Property: Ciphertext freshness / replay prevention
- Primary layer: B
- Secondary layers: none
- Security target: the aggregator must reject stale or duplicated share submissions and must bind an accepted decryption run to the intended epoch/nonce context from T19/T22.
- Cost vs soundness: freshness is transcript hygiene driven by local protocol state, making it cheap and precise in Rust while being awkward to encode in a purely stateless Solidity verifier.
- Why not a different primary layer: C does not have the full off-chain replay cache in the current API, and A should not absorb mutable protocol-state bookkeeping that does not need succinct public verification.
- Status: CLOSED for Phase 2, but only off-chain because the current on-chain ABI does not carry epoch state.
- Theorem linkage: T-ROBUSTNESS.

### PB-08
- Property: Public key consistency
- Primary layer: B
- Secondary layers: A
- Security target: the aggregate public key used by decryption must equal `Σ pk_i` over the accepted participant set from keygen.
- Cost vs soundness: recomputing the public-key sum is cheap deterministic algebra for the aggregator and any honest auditor, so proving it on-chain would spend gas with no security upside.
- Why not a different primary layer: C only receives the final aggregate key bytes, not the full keygen transcript, and D is aimed at per-share witness validity rather than cross-party key accumulation.
- Status: CLOSED for boundary assignment.
- Theorem linkage: T-IND-CPA, T-DEC-SOUND, and T-ROBUSTNESS.

### PB-09
- Property: Blame identification
- Primary layer: B
- Secondary layers: D
- Security target: when the protocol aborts, the system must be able to point to the cheating dealer, complaining party, silent party, or equivocating aggregator with concrete evidence.
- Cost vs soundness: blame assembly is transcript-centric and should live where full messages, timeouts, and complaint evidence are already available, namely the Rust aggregator / coordinator logic.
- Why not a different primary layer: C can potentially consume evidence later for slashing, but it should not be the first place where large blame transcripts are reconstructed; D only covers the cryptographic proof fragments used as evidence.
- Status: CLOSED for boundary assignment, with cryptographic sub-claims still inheriting P1 where blame depends on invalid NIZKs.
- Theorem linkage: T-ROBUSTNESS.

### PB-10
- Property: Proof binding
- Primary layer: C
- Secondary layers: A
- Security target: the final UltraHonk proof accepted by the verifier contract must be non-malleable and bound to one concrete public statement.
- Cost vs soundness: proof binding is only security-relevant at the acceptance boundary seen by third parties, so the canonical enforcement point is the Solidity verifier executing the BB-generated UltraHonk/KZG verification logic.
- Why not a different primary layer: A defines the statement, but binding is not useful unless the final verifier enforces it; B cannot replace a public verifier for T-PV-SOUND.
- Status: CLOSED under the stated KZG / UltraHonk assumptions from T24.
- Theorem linkage: T-PV-SOUND.

### PB-11
- Property: On-chain calldata integrity
- Primary layer: C
- Secondary layers: B
- Security target: `ctBytes`, `ptBytes`, `proof`, `aggPkBytes`, and `participantSet` must match the ABI and fixed byte-shape expected by `IPvthfheVerifier`.
- Cost vs soundness: Solidity can reject malformed lengths and encodings before invoking expensive verification, which is both cheap and exactly aligned with the public trust boundary.
- Why not a different primary layer: A assumes well-formed public inputs after decoding, and B may preflight them, but the chain must protect itself from malformed calldata independently.
- Status: CLOSED for boundary assignment.
- Theorem linkage: T-PV-SOUND and T-ROBUSTNESS.

### PB-12
- Property: Parameter consistency
- Primary layer: C
- Secondary layers: B, A
- Security target: the public verifier must interpret proofs under the canonical Phase 2 parameters `(N=8192, q≈174 bits over 3 limbs, t_plain=2^17, threshold=floor(n/2)+1)` and reject mismatched public inputs.
- Cost vs soundness: public-parameter checks are cheap, deterministic, and visible to all verifiers, so they should be enforced at the contract boundary rather than trusted to off-chain configuration alone.
- Why not a different primary layer: B should check configs early and A may bind selected params as public inputs, but C is the only layer every relying party necessarily executes.
- Status: CLOSED for boundary assignment.
- Theorem linkage: T-IND-CPA, T-PV-SOUND, and T-ROBUSTNESS.

## Boundary consequences

- The chain is intentionally thin: it checks ABI integrity, fixed public parameters, threshold-facing public inputs, and the final UltraHonk verification result, but it does not re-run RLWE algebra over all shares.
- The aggregator is intentionally strong on transcript hygiene: replay protection, aggregate-key recomputation, and blame evidence are not delegated to Solidity.
- The lattice proof layer carries the two critical open risks: P1 for share/NIZK well-formedness and P2 for RLWE-aware folding linearity.
- The compressed SNARK is intentionally reserved for the final succinct public claim: threshold binding plus plaintext decoding correctness.

## Open items explicitly not papered over

1. **P1 remains open.** Any claim that per-share RLWE well-formedness is fully resolved would overstate current evidence.
2. **P2 remains open.** The fold-level aggregation linearity argument over RLWE is still an active research dependency.
3. **Smudging exactness is only partially enforceable.** Phase 2 can enforce parameterized bounds and witness shortness, but not an externally auditable proof of exact Gaussian sampling.
4. **Replay protection is off-chain only in the present ABI.** If the contract later learns epoch state, the boundary should be amended through plan control rather than changed ad hoc.

## Freeze rule

Any movement of a primary property from one layer to another changes either the security theorem interface, the gas budget, or the trust model. That is a design change, not an editorial tweak. Therefore this ledger is frozen for Phase 2.


## Accumulator-to-SNARK Encoding

> ⚠️ CONDITIONAL ON MicroNova-lattice-encoding soundness (open research problem P3)

**Witness layout** (what the UltraHonk SNARK proves about the lattice accumulator):
- Folded accumulator commitment: `acc_commit: [u8; 32]`
- Fold count: `fold_count: u32` (= number of shares folded, ≤ n)
- Norm bound: `norm_bound: u64` (= β, the shortness bound)
- Per-share NIZK validity: `all_nizks_valid: bool` (checked inside circuit)

**Public inputs to the SNARK** (frozen — identical to the on-chain verifier inputs):
`(ciphertext_hash, plaintext_hash, aggregate_pk_hash, dkg_root, epoch, participant_set_hash, D_commitment)`

where `D_commitment = Keccak256(D)`, `D = Σᵢ∈S dᵢ`. The accumulator-internal fields `(acc_commit, fold_count, norm_bound)` are witness-derived values inside the SNARK circuit, not public inputs to the on-chain verifier.

**Soundness condition**: End-to-end soundness of the MicroNova compression step is conditional on the accumulator-to-SNARK encoding theorem (open research). Until proved, treat as a research conjecture.

The frozen SNARK public inputs are: `(ciphertext_hash, plaintext_hash, aggregate_pk_hash, dkg_root, epoch, participant_set_hash, D_commitment)`. These are the only values the on-chain verifier receives (besides the proof bytes).