# Security

> ⚠️  **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**
>
> This repository contains a **research implementation** of private-verifiable threshold FHE:
> - **on-chain verifier uses Sonobe substitution (off-chain Sonobe + on-chain commitment)**
> - **Noir circuits implement the real aggregation and wrapping logic**
> - **do not use for The Interfold or any production deployment**
>
> See [SECURITY-ADVISORY-001.md](SECURITY-ADVISORY-001.md) and [SECURITY.md](SECURITY.md) for details.

This document outlines the security model, assumptions, and limitations of the PVTHFHE research prototype.

## Implementation status

- **FHE backend**: real threshold BFV via `gnosisguild/fhe.rs`, under an **honest-but-curious** threat model.
- **Greco / well-formedness ZK proofs**: **not yet implemented**. The real FHE path therefore remains unproven against malicious share construction and ciphertext well-formedness attacks.
- **Folding accumulator**: implemented via Sonobe substitution.
- **On-chain verifier**: real UltraHonk verifier (committing to Sonobe state) + off-chain attestation.

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

- **P1 (CRITICAL)**: **Lattice NIZK Soundness**. P1 (CRITICAL): Per-share RLWE NIZK knowledge soundness is conditional on (a) Module-SIS hardness over R_{q_commit}, (b) Cyclo Theorem 3 soundness (ePrint 2026/359), and (c) collision resistance of SHA-256 for the P4 commitment domain. Formal joint-extractor proof (T2) is deferred. Any relying party must treat per-share proofs as computationally binding under these assumptions only.
- **P2 (HIGH)**: **LatticeFold+ Linearity**. Real — Cyclo LatticeFold+ over RLWE, T=10, Lemma 9 heuristic (conditional soundness). The active backend is `cyclo-rlwe-t10-lemma9-heuristic`; soundness remains conditional on M-SIS hardness over R_{q_commit}, Cyclo Theorem 3 (ePrint 2026/359), and the Lemma 9 invertibility heuristic, while the joint extractor (T2) remains a skeleton.
- **P3 (MEDIUM)**: **MicroNova-lattice Encoding**. Substitituted by off-chain Sonobe + on-chain commitment topology. The aggregator submits an UltraHonk proof of the Sonobe state commitment, which is checked on-chain alongside an off-chain attestation.

## Smudging

To prevent leakage from decryption shares, we use a conservative smudging parameter:
$\sigma_{\text{smudge}} = 2^{40} \cdot \sigma_{\text{err}}$.
This provides $> 100$ bits of statistical security against noise-based leakage, assuming the noise budget is sufficient (validated for $N=8192$).

### Smudging Modes

PVTHFHE supports two distinct smudging modes with different security guarantees:

| Mode | API | Noise source | Interfold-equivalent |
|------|-----|-------------|---------------------|
| `legacy_local_smudge` | `FheBackend::partial_decrypt` | Fresh Gaussian sampled per-decryption via local RNG | **No** — smudging noise is not committed, shared, or proved. |
| `committed_smudge_pvss` | `FheBackend::partial_decrypt_committed_smudge` | Committed `e_sm` polynomial from DKG transcript | **Yes** — matches Interfold C6 (`ThresholdShareDecryption`). |

**`legacy_local_smudge`** (default): Each party samples fresh Gaussian smudging noise
locally during `partial_decrypt`. The noise provides honest-but-curious LWE-based
hiding (prevents secret-key recovery from observed partial decryption shares), but
is NOT equivalent to the Interfold's guaranteed surface because the noise is not a
committed, shared PVSS object. This mode is maintained for backward compatibility
and testing.

**`committed_smudge_pvss`** (Interfold-equivalent): The smudging noise polynomial
`e_sm` is a first-class committed, shared, and proved PVSS object produced during
DKG (batch C in the Interfold-equivalence plan). At decryption time, the backend
adds the committed `e_sm` polynomial instead of sampling fresh noise. The
`DecryptionWitness` records `esm_committed: true` and the exact `e_sm` bytes used,
enabling public verification that the decryption share uses committed DKG material.

The committed-smudge path is the foundation for batch F (C6-equivalent threshold
decryption with committed smudging). See `.sisyphus/design/smudging.md` for the
full smudging parameter derivation and `.sisyphus/plans/interfold-equivalent-pvss.md`
for the equivalence roadmap.

## Responsible Disclosure

If you find a security vulnerability, please do not open a public issue. Instead, follow the standard research disclosure process by contacting the maintainers at `security@example.com` (placeholder).

## Disclaimer

This software is provided "as is" for research purposes only. It has not undergone a professional security audit. Use in production environments is strictly discouraged.
