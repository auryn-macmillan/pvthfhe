# P3-T1 — UltraHonk Knowledge Soundness over BN254

**Theorem ID**: P3-T1 (UltraHonk refinement)
**Status**: **DOCUMENTED — measurements deferred to post-p3-m3**
**Reduction target**: UltraHonk knowledge soundness over BN254 (Aztec Protocol security analysis)
**Replaces**: P3-T1 in `proof-skeletons.md` (SP1 + Groth16 variant)

---

## Statement

**Theorem P3-T1 (UltraHonk Knowledge Soundness over BN254).** Let `x = (ciphertext_hash, plaintext_hash, aggregate_pk_hash, dkg_root, epoch, participant_set_hash, D_commitment)` be the 200-byte `P3PublicInputs` blob fixed by the P2/P3 bundle. Let `π_uh` be an UltraHonk proof over BN254 produced by the Barretenberg proving backend. Let `VerifyP3_uh(x, π_uh)` denote the on-chain verification performed by the BB-generated `HonkVerifier.sol` contract, which evaluates the UltraHonk sumcheck and relates the seven public inputs to the committed witness through the UltraHonk algebra.

If `VerifyP3_uh(x, π_uh) = 1`, then there exists a satisfying witness `w` for the UltraHonk relation such that the embedded predicate (Option B: MicroNova verifier in Noir) accepts, and therefore a valid terminal P2 accumulator object `acc*` exists for the same session and ordered fold history such that the frozen P2 verifier accepts `acc*` on the same public statement with parameter tuple `(q=65537, N=1024, B_e=17)`.

Equivalently: an on-chain UltraHonk acceptance cannot certify any statement stronger or different than the folded P2 statement actually exported downstream, except with probability bounded by the UltraHonk knowledge-soundness error over BN254 plus the inherited P2 soundness failure probability (P2-T2).

## P3 Stack Context

The chosen P3 on-chain verifier stack is **Option B** from `.sisyphus/design/spec-real-p2p3.md` §6.4:

```
Cyclo accumulator → MicroNova compression → UltraHonk Noir circuit → HonkVerifier.sol
```

This is a two-layer compression chain. The UltraHonk proof is the outermost layer visible to the EVM. Soundness at this layer depends on:

1. **UltraHonk knowledge soundness** (this theorem).
2. **MicroNova soundness preservation** (P3-T2).
3. **P2 terminal accumulator soundness** (P2-T2, inherited).

The Noir circuit that UltraHonk proves is compiled via Nargo and verifies the MicroNova compressed proof as a private witness, emitting the seven public inputs as circuit outputs bound by the UltraHonk public-input wire layout.

## Proof Sketch

1. **UltraHonk knowledge soundness.** UltraHonk is a Honk-family proving system built by Aztec Protocol. It uses a multilinear polynomial IOP compiled to a SNARK via a polynomial commitment scheme (KZG over BN254). By the knowledge-soundness theorem for the Honk IOP (Aztec Protocol, 2024), any PPT adversary that produces an accepting `π_uh` can be rewound by a straight-line extractor to yield a satisfying assignment to the arithmetisation constraints. The extraction failure probability is bounded by the subgroup-security of BN254.

2. **Noir circuit encodes the Option B wrapper.** The Noir circuit compiled to UltraHonk accepts if and only if the MicroNova verifier predicate accepts the compressed proof. The circuit binds the seven public inputs byte-for-byte in the order specified by the P2/P3 bundle. This encoding fidelity is a design obligation verified by circuit audit.

3. **Subset of UltraHonk features.** The LatticeFold+ proofs consumed by this circuit use a subset of UltraHonk: no lookup arguments (Plookup/LogUp) are required because the MicroNova verifier predicate is expressed purely in R1CS-derived constraints. This absence of lookups removes a potential source of knowledge-soundness loss and may tighten the concrete bound relative to full UltraHonk.

4. **Public-input binding.** The UltraHonk verifying key commits to the exact public-input wire layout via the KZG CRS. Any `x'` differing from `x` that passes verification requires a distinct satisfying witness, which by step 1 implies a distinct valid P2 terminal accumulator.

5. **Conclusion.** An on-chain UltraHonk acceptance implies a valid P2 terminal accumulator for the exact same public statement, up to UltraHonk knowledge-soundness error over BN254 and inherited P2-T2 failure probability.

## Dependencies

| Dependency | Role |
|---|---|
| UltraHonk knowledge soundness over BN254 (Aztec Protocol) | Primary reduction target |
| BN254 KZG polynomial commitment binding | Underpins UltraHonk's extractability |
| Noir-to-UltraHonk compilation correctness | Faithful encoding of the Option B wrapper circuit |
| P2-T2 (folding knowledge soundness) | Inherited P2 soundness claim |
| P3-T2 (MicroNova soundness preservation) | Soundness of the compressed layer beneath UltraHonk |
| `.sisyphus/design/spec-real-p2p3.md` §6.2–6.4 | Option B stack specification |

## LatticeFold+ Subset Note

LatticeFold+ proofs use a **strict subset** of UltraHonk functionality. The Option B Noir circuit:

- Does **not** use UltraHonk lookup arguments (Plookup/LogUp).
- Does **not** use UltraHonk's RAM/ROM table features.
- Uses only gate constraints derived from the MicroNova R1CS verifier, plus Poseidon/Keccak hash gadgets.

Because the subset is smaller than full UltraHonk, the concrete knowledge-soundness error for this circuit may be a **factor of 2–4× tighter** than the generic UltraHonk bound published by Aztec. A precise constant-factor analysis requires the final Noir circuit's gate count and wire topology, which will be available after P3-M2.

## Open Gaps

- The concrete UltraHonk knowledge-soundness bound (ε_uh) for the specific Noir circuit size has not been computed numerically. This requires the final circuit's constraint count from P3-M2.
- The "faithful encoding" claim (step 2) requires a Noir circuit audit once the Option B wrapper circuit is implemented.
- UltraHonk uses KZG commitments. The ceremony risk is captured by P3-T3 (trusted-setup security); the UltraHonk variant of P3-T3 has not yet been drafted.
- The LatticeFold+ subset tightening factor is conjectural and needs empirical validation.

## Deferral Rationale

This document is marked **DEFERRED** because:

1. **P3-M2 (real proof generation)** has not yet produced an actual UltraHonk proof from the Option B Noir circuit. The theorem's soundness claim is structural but the concrete bound cannot be stated without the final circuit.
2. The Noir circuit implementing the MicroNova verifier has not been compiled to UltraHonk at the time of writing.
3. Without a real proof artifact, there is no verifying key to audit for public-input wire alignment.

Once P3-M2 delivers a functioning UltraHonk proof and the Noir circuit is frozen, this document will be updated to include the concrete knowledge-soundness bound, the circuit constraint count, and a reference to the verifying-key audit.

---

**References**

- Aztec Protocol. "Honk: A Multilinear Polynomial IOP for Plonkish Arithmetisation." 2024.
- `.sisyphus/design/spec-real-p2p3.md` §6.2–6.4 (Option B: Wrap MicroNova Proof in UltraHonk Noir Circuit).
- `.sisyphus/design/proof-boundary.md` (accumulator-to-SNARK encoding, public-input layout).
- `docs/security-proofs/p3/proof-skeletons.md` (original P3-T1 skeleton, SP1 + Groth16 variant).
