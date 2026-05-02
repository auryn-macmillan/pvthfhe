# Assumptions Ledger: PVTHFHE

This document lists the cryptographic assumptions required for the Publicly Verifiable Threshold FHE scheme.

## RLWE (Decision)
- **Formal statement**: For a secret s sampled from a distribution χ and a uniform a in Rq, the distribution of (a, a·s + e) is computationally indistinguishable from the uniform distribution over Rq × Rq, where e is a small noise term.
- **Parameter regime**: Power-of-two cyclotomic rings, large modulus q, Gaussian or centered binomial noise, 128-bit security level.
- **What breaks if violated**: Indistinguishability under chosen-plaintext attacks (CPA-security) of the FHE scheme fails.
- **Replacement candidates**: LWE (non-ring), NTRU-based assumptions.
- **Used by**: T8, T9, T10, T15 (Ciphertext Indistinguishability)

## RLWE (Search)
- **Formal statement**: Given (a, a·s + e) where a is uniform in Rq and e is a small error, it is computationally hard to find the secret s.
- **Parameter regime**: Same as Decision RLWE; security depends on the ratio of noise to modulus and the ring dimension.
- **What breaks if violated**: Total recovery of the secret key and decryption of all ciphertexts.
- **Replacement candidates**: Search LWE, SIS (in some contexts).
- **Used by**: T15, T16 (Key Recovery Security)

## Module-LWE
- **Formal statement**: Generalization of LWE to modules over a ring. Given a matrix A and a vector b = A·s + e, it is hard to distinguish (A, b) from uniform.
- **Parameter regime**: Module rank k ≥ 2, ring dimension n, modulus q.
- **What breaks if violated**: Security of the key generation and certain compact ciphertext variants.
- **Replacement candidates**: Standard RLWE, LWE.
- **Used by**: T8 (Architecture A), T24 (Key Generation)

## SIS (Short Integer Solution)
- **Formal statement**: Given a uniform matrix A in Zq^(n×m), find a non-zero vector x such that A·x = 0 (mod q) and ||x|| ≤ β for some small bound β.
- **Parameter regime**: m > n log q, bound β significantly smaller than q.
- **What breaks if violated**: Collision resistance of commitments and binding property of lattice-based proofs.
- **Replacement candidates**: Ring-SIS, M-SIS.
- **Used by**: T9 (Architecture B), T16 (Commitment Binding)

## knLWE (Knowledge-of-noise LWE)
- **Formal statement**: Given an LWE sample, it is hard to perform operations that depend on the specific noise value without knowing the secret, or to prove knowledge of noise without revealing the secret (ePrint 2024/1984).
- **Parameter regime**: Specific to noise-aware threshold protocols and extraction-based proofs.
- **What breaks if violated**: Simulation-extractability of threshold decryption shares; adversary might inject malformed noise.
- **Replacement candidates**: Stronger NIZKs with straight-line extraction.
- **Used by**: T10 (Architecture C), T15 (Threshold Security)

## DDH on Grumpkin
- **Formal statement**: Given (g, g^a, g^b, g^c) for a generator g of the Grumpkin curve, it is hard to distinguish if c = ab or c is random.
- **Parameter regime**: Grumpkin curve (cycles with BN254), standard 128-bit elliptic curve security.
- **What breaks if violated**: Soundness of non-post-quantum components in Noir/Barretenberg proofs.
- **Replacement candidates**: Other EC-based assumptions (DLP), though Grumpkin is required for the specific cycle.
- **Used by**: T16 (Verifier Soundness), T24 (Noir Circuits)

## KZG Polynomial Commitment (SDH)
- **Formal statement**: Given a structured reference string, it is hard to produce a commitment and an evaluation proof for a point without knowing the polynomial (q-Strong Diffie-Hellman).
- **Parameter regime**: BN254 curve, SRS size proportional to maximum polynomial degree.
- **What breaks if violated**: Binding property of polynomial commitments; a prover could open a commitment to multiple values.
- **Replacement candidates**: FRI-based (STARK) commitments (post-quantum), IPA/Bulletproofs.
- **Used by**: T8, T9 (UltraHonk Backend)

## Random Oracle Model (ROM)
- **Formal statement**: Cryptographic hash functions are modeled as a perfectly random function available to all parties as an oracle.
- **Parameter regime**: SHA-256, Poseidon, or Keccak-256 with sufficient output length.
- **What breaks if violated**: Soundness of the Fiat-Shamir transform, allowing adversaries to forge proofs by predicting challenges.
- **Replacement candidates**: Standard model NIZKs (rarely practical), Correlation Intractable hashes.
- **Used by**: T15, T16 (NIZK Security)

## QROM (Quantum Random Oracle Model)
- **Formal statement**: Same as ROM, but the adversary can query the oracle with quantum superpositions of inputs.
- **Parameter regime**: Required for post-quantum security of Fiat-Shamir.
- **What breaks if violated**: Post-quantum soundness of the NIZKs used in the threshold transcript.
- **Replacement candidates**: Dual-mode commitments, Unruh's transform.
- **Used by**: T8, T9, T10 (Long-term Verifiability)

## AGM (Algebraic Group Model)
- **Formal statement**: Adversaries are "algebraic," meaning whenever they output a group element, they also output the linear representation of that element in terms of previously seen elements.
- **Parameter regime**: Idealized model for proving security of pairing-based protocols like KZG.
- **What breaks if violated**: Security proofs for KZG and some SNARK components might not hold against non-algebraic adversaries.
- **Replacement candidates**: Standard model proofs (often much larger/slower).
- **Used by**: T16 (Recursive Proof Soundness)
