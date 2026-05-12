# Security Proof Note: Interfold-Equivalent PVSS (PVTHFHE)

This document provides a theorem sketch and security analysis for the Interfold-equivalent PVSS (Private-Verifiable Secret Sharing) construction in PVTHFHE. It maps the PVTHFHE relations to the Interfold C0–C7 guarantee surface and identifies current limitations.

## 1. Assumptions

The security of the PVSS construction relies on the following cryptographic assumptions:

1.  **RLWE/BFV Secrecy**: The Learning With Errors over Rings (RLWE) problem and the security of the BFV homomorphic encryption scheme (specifically, the hardness of recovering the secret key or distinguishing ciphertexts from random).
2.  **Binding Commitments**: All cryptographic commitments (Ajtai-style lattice commitments and polynomial commitments) are computationally binding.
3.  **Proof Soundness**: The NIZK proofs (Cyclo-companion Ajtai D2 sigma protocol and lattice-native BFV sigma protocol) satisfy computational soundness in the Random Oracle Model (ROM).
4.  **Fiat-Shamir Model**: The Fiat-Shamir heuristic is used to transform interactive protocols into non-interactive proofs, assuming a random oracle.
5.  **Threshold Corruption Bound**: At most $t-1$ out of $n$ parties are corrupted by a Probabilistic Polynomial Time (PPT) adversary.
6.  **Binding of Public Anchors**: The `DkgAnchorSet` root digest and session-bound identifiers (session ID, epoch, participant set hash) are correctly enforced by verifiers to prevent replay and mix-and-match attacks.

## 2. Theorem Sketch: DKG Transcript Validity to Decryption-Share Soundness

**Theorem (Informal):** Given a valid DKG transcript $T$ and a set of verified decryption shares $S$, the recovered aggregate secret key and the resulting threshold decryption of a ciphertext $C$ are sound with respect to the committed DKG parameters.

**Proof Sketch:**
1.  **DKG Consistency**: A valid DKG transcript (Batch C.1/C.3) ensures that every participant $P_i$ has committed to a secret key share $sk_i$ and a set of smudging noise slots $e_{sm, i, j}$. The `DkgAnchorSet` root digest binds these commitments into a single public value.
2.  **Share Aggregation Soundness**: The aggregation relation (Batch E.2) proves that the public aggregate commitments (C4/C5 equivalent) are exactly the sum of individual shares from the accepted participant set.
3.  **Decryption Binding**: The threshold decryption NIZK (Batch F.1) proves that a partial decryption share $d_i$ is computed correctly from a ciphertext $C$, an aggregate secret key share $sk_i$, and a committed smudging noise slot $e_{sm, i, j}$.
4.  **Freshness and One-Time Use**: Public anchor checks (Batch H.3) and the `SmudgeSlotRegistry` (Batch C.2) ensure that each smudging slot is used exactly once for a specific ciphertext, preventing noise reuse attacks.
5.  **Conclusion**: By the binding property of the DKG anchor and the soundness of the decryption NIZK, the aggregate decryption share recovered by the verifier corresponds to the unique secret key material established during the DKG phase.

## 3. Smudge-Slot One-Time-Use Lemma

**Lemma (Smudge-Slot Freshness):** A smudging noise polynomial $e_{sm, i, j}$ committed during the DKG phase provides effective hiding for a partial decryption share if and only if it is never reused across different ciphertexts.

**Justification:**
- In the `committed_smudge_pvss` mode (Batch B.3), the noise $e_{sm}$ is fixed at DKG time.
- If $e_{sm}$ were reused for two different partial decryptions $d_1 = c_1 \cdot sk_i + e_{sm}$ and $d_2 = c_2 \cdot sk_i + e_{sm}$, an adversary could compute $d_1 - d_2 = (c_1 - c_2) \cdot sk_i$.
- Since $(c_1 - c_2)$ is known, this reduces to a system of linear equations that directly reveals the secret key share $sk_i$ (or an LWE instance with significantly reduced noise).
- PVTHFHE prevents this by binding each slot $j$ to a tuple $(session\_id, epoch, ciphertext\_hash, decrypt\_round)$ and enforcing a strict no-reuse policy in the on-chain `SessionRegistry`.

## 4. Limitations and Open Problems

### 4.1 BFV Share-Encryption Relation (D.1 Blocker) — C3 Structural Gap

The current `v3` share encryption proofs (Batch D.1) lack a verifier-checkable BFV encryption relation. While the prover validates the relation (secret key share encryption) using its private witness, the verifier only checks an algebraic Sigma proof over the committed-share representation.

**Structural gap (C3)**: The algebraic sigma proof proves a hash-preimage statement — that the prover knows a preimage of the SHA-256 share commitment — rather than the full Shamir / BFV encryption structure. Specifically:

- The verifier checks $H(\text{share}, \text{session}) = \text{commitment}$ (D2-preimage binding).
- The verifier does **not** check that the ciphertext $u$ is a valid BFV encryption of $\text{share}$ under $\text{recipient\_pk}$.
- The algebraic committed-share proof and hash bindings are adversary-recomputable around arbitrary ciphertext bytes.
- The current D.1 containment fails closed after the algebraic proof verifies, returning `LatticeBindingVerificationFailed`.

**What's needed**: A non-leaking verifier-checkable BFV encryption relation proving $\text{ct}_0 = \text{pk}_0 \cdot u + e_0 + \Delta m$ and $\text{ct}_1 = \text{pk}_1 \cdot u + e_1$ without revealing witness polynomials. This requires either public quotient/reduction terms from the FHE backend or a Noir circuit emulating BFV ring arithmetic in a SNARK-friendly field.

- **Impact**: The verifier cannot independently confirm that the ciphertext $u$ actually encrypts the committed share.
- **Status**: The verifier currently fails closed for these proofs to prevent forgery.
- **Cross-reference**: See `.sisyphus/design/interfold-equivalence.md` §C3 for the full gap analysis.

### 4.2 Distributional Sampling of $e_{sm}$
If only the boundedness (norm) of the smudging noise $e_{sm}$ is proved, rather than its exact distribution (e.g., discrete Gaussian), the statistical hiding guarantee is weakened.
- **Limitation**: Current relations primarily enforce norm bounds. If a malicious prover samples $e_{sm}$ from a non-Gaussian distribution that still satisfies the bound, the resulting share might leak information in a statistical sense, though it may remain hard to invert in an honest-but-curious (computational) model.

### 4.3 Prototype and Audit Status
- **Audit Findings**: Two audits (2026-05-08/09) identified numerous findings. While automatable remediations are complete, three open cryptographic problems (P1, P2, P3) remain.
- **Non-Audited**: This documentation does not constitute a formal audit or a claim of production-ready security.

### 4.5 P2/P3 Structural Gap — CycloFoldStepCircuit Proves Hash-Accumulate, Not Ajtai Fold

The Sonobe Nova IVC compressor uses `CycloFoldStepCircuit` (`crates/pvthfhe-compressor/src/sonobe/mod.rs`) which folds 3 hashed field elements — `(commitment_hash, norm, fold_count)` — derived from SHA-256 of Cyclo accumulator commitments. It does **not** perform full Ajtai commitment folding over `R_{q_commit}` within the IVC step.

- **P2 gap**: Full Ajtai folding inside a lattice-native folding scheme (LatticeFold+/Cyclo Lemma 9) remains OPEN. Sonobe Nova substitutes for lattice-native folding, but the substitution folds hashed accumulator state, not the raw Cyclo accumulator witness.
- **P3 gap**: The compressed proof (Sonobe Nova IVC) verifies hash-state consistency — that the hashed accumulator state transitions correctly — but does not verify the full Cyclo accumulator relation (Ajtai commitment check over `a=13` ring elements, norm-bound range checks for `β_T=1344`, sum-check transcript verification of ~60 KB of `F_{q^e}` elements).
- **Current flow**: Cyclo accumulator verification runs off-chain via `fold::verify_fold`. Only the state digest (SHA-256 of commitment bytes) enters the IVC as a pre-hashed public input. The on-chain verifier ultimately checks an UltraHonk proof of the Sonobe IVC state, not the raw Cyclo proof.
- **Impact**: A malicious prover who can compute a valid SHA-256 preimage of the accumulator commitment (but not a valid Cyclo accumulator) could produce a compressing proof that passes the current pipeline. This is mitigated by the assumption that SHA-256 is collision-resistant and the Cyclo `verify_fold` check is performed before compression.
- **Resolution**: Requires closing P2 (lattice-native folding) and implementing the full Cyclo accumulator verifier inside the P3 compression circuit (Cyclo → MicroNova → UltraHonk per `spec-real-p2p3.md` §6.2/§6.4).

Cross-reference: `.sisyphus/design/spec-real-p2p3.md` §5.1 P2/P3 gap note, `.sisyphus/design/interfold-equivalence.md` §C7.

## 4.6 Sigma Masking Seeds: Fresh Per Proof

As of 2026-05-12, the sigma masking seeds used in proof generation (both the algebraic sigma proof in `build_algebraic_proof` and the BFV encryption sigma proof in `build_bfv_encryption_proof`) are no longer deterministic. They are now seeded with `OsRng` (`ChaCha20Rng::from_rng(&mut OsRng)`) to provide fresh, non-deterministic randomness per proof.

## 5. Interfold Equivalence Summary

| Feature | Comparable to Interfold? | Differences / Unresolved Issues |
|---|---|---|
| **Guarantee Surface** | Yes (C0–C7 mapped) | D.1 verifier relation is missing. |
| **Commitment Binding** | Yes (Ajtai/Polynomial) | Interfold uses recursive Noir circuits; PVTHFHE uses folding. |
| **Smudging Mode** | Yes (`committed_smudge_pvss`) | `legacy_local_smudge` is non-equivalent (hiding only). |
| **Public Anchors** | Yes (H.1/H.2/H.3) | On-chain registry enforces one-time slot use. |
| **Performance** | No (Not apples-to-apples) | PVTHFHE targets $O(\text{polylog } n)$ but lacks fair metrics (I.1). |

**Conclusion**: PVTHFHE achieves a comparable guarantee surface to Interfold by treating smudging noise as a first-class committed object. However, complete functional equivalence is blocked by the D.1 verifier-side BFV relation gap and the research prototype status of the repository.
