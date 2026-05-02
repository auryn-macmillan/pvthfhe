# Security

This document outlines the security model, assumptions, and limitations of the PVTHFHE research prototype.

## Threat Model

The PVTHFHE security model is evaluated across 6 axes:

1.  **Adversary**: Malicious, computationally bounded (PPT).
2.  **Corruption**: Honest-majority threshold $t = \lfloor n/2 \rfloor + 1$. Up to $n-t$ parties can be maliciously corrupted and collude.
3.  **Network**: Synchronous communication for DKG and decryption rounds.
4.  **Identity**: Authenticated channels; party identities are known and fixed for the duration of a protocol instance.
5.  **Liveness**: Guaranteed as long as $t$ honest parties participate.
6.  **Abort**: Abort-with-public-blame; malicious behavior is detected and the offending party is identified.

## Assumptions Ledger

The security of the system relies on the following cryptographic assumptions:

- **RLWE / Module-LWE**: Security of the underlying FHE scheme.
- **SIS / knLWE**: Hardness of finding short vectors, used in NIZK proofs.
- **DDH (Grumpkin)**: Used in the recursive SNARK layer.
- **KZG Binding**: Security of the polynomial commitment scheme.
- **AGM (Algebraic Group Model)**: Assumed for the security analysis of the proving system.

For a full list of formal assumptions, see [.sisyphus/design/security-proofs.md](.sisyphus/design/security-proofs.md).

## Known Limitations & Open Problems

This is a research prototype and contains components where formal soundness proofs are still being developed:

- **P1 (CRITICAL)**: **Lattice NIZK Soundness**. The NIZK used to prove well-formedness of decryption shares lacks a formal soundness argument over RLWE rings in the current literature.
- **P2 (HIGH)**: **LatticeFold+ Linearity**. The folding protocol for RLWE-based statements is simulated in this prototype.
- **P3 (MEDIUM)**: **MicroNova-lattice Encoding**. The encoding efficiency of lattice relations into MicroNova-compatible structures is an active area of research.

## Smudging

To prevent leakage from decryption shares, we use a conservative smudging parameter:
$\sigma_{\text{smudge}} = 2^{40} \cdot \sigma_{\text{err}}$.
This provides $> 100$ bits of statistical security against noise-based leakage, assuming the noise budget is sufficient (validated for $N=8192$).

## Responsible Disclosure

If you find a security vulnerability, please do not open a public issue. Instead, follow the standard research disclosure process by contacting the maintainers at `security@example.com` (placeholder).

## Disclaimer

This software is provided "as is" for research purposes only. It has not undergone a professional security audit. Use in production environments is strictly discouraged.
