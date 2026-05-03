# Security Proofs Guidelines

This document defines the standards for cryptographic proofs within the PVTHFHE program.

## Notation Conventions

We use standard lattice-based cryptography notation.

*   $\mathbb{Z}_q$: The ring of integers modulo $q$.
*   $R = \mathbb{Z}[X]/(X^n + 1)$: The ring of cyclotomic integers.
*   $R_q = R/qR$: The ring of cyclotomic integers modulo $q$.
*   Vectors are denoted in bold lowercase (e.g., $\mathbf{a}$).
*   Matrices are denoted in bold uppercase (e.g., $\mathbf{A}$).
*   $s \leftarrow \chi$: Sampling $s$ from a distribution $\chi$.
*   MLWE: Module Learning With Errors.
*   MSIS: Module Short Integer Solution.

## Security Model

*   **Baseline**: Random Oracle Model (ROM).
*   **Stretch Goal**: Quantum Random Oracle Model (QROM) where feasible.
*   **Security Level**: Target $\ge 120$-bit post-quantum security.
*   **Adversary**: Probabilistic Polynomial Time (PPT) adversary with access to relevant oracles.

## Proof Style

Proofs should follow one of these canonical styles:

1.  **Game-Based Proofs**: A sequence of games starting from the real experiment and ending at an experiment where the adversary has no advantage.
2.  **Simulation-Based Proofs**: Demonstrating the existence of a simulator that can produce a transcript indistinguishable from a real execution given only the authorized information.

Refer to Bellare and Rogaway (1993, 1996) for game-based foundations and Canetti (2001) for universal composability.

## Reduction Style Guidelines

*   **Explicit**: Reductions must be clearly defined, showing how an adversary for the construction can be transformed into an adversary for the underlying hard problem.
*   **Tightness**: Aim for tight reductions where the advantage and resources of the reduction are close to those of the original adversary.
*   **Bounded Loss**: Any tightness loss must be explicitly stated and bounded.

## Theorem-Proof Skeleton Format

Every proof skeleton must include these sections:

1.  **Theorem Statement**: Formal mathematical statement of the property (e.g., Soundness, Completeness, Zero-Knowledge).
2.  **Proof Technique**: Overview of the approach (e.g., "Reduction from MLWE using game-hopping").
3.  **Reduction Target**: The underlying hard problem or assumption (e.g., MLWE, MSIS).
4.  **Unresolved Lemmas**: List of lemmas that are stated but not yet proven.
5.  **Open Questions**: Any remaining theoretical uncertainties or potential optimizations.
