# Security

> ⚠️  **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**
>
> This repository contains a **research implementation** of private-verifiable threshold FHE:
> - **On-chain verifier uses nova-snark IVC with transparent decider + UltraHonk state commitment**
> - **Noir circuits implement real aggregation and wrapping logic**
> - **Do not use for The Interfold or any production deployment**
>
> See [SECURITY-ADVISORY-001.md](SECURITY-ADVISORY-001.md), [WARNING.md](WARNING.md), and [docs/OPEN-PROBLEM-BLOCKERS.md](docs/OPEN-PROBLEM-BLOCKERS.md) for details.

This document outlines the security model, assumptions, and limitations of the PVTHFHE research prototype.

## Implementation Status

- **FHE backend**: Real threshold BFV via `gnosisguild/fhe.rs`.
- **Nova IVC Proofs**: Maliciously-secure folding via nova-snark (Microsoft Nova v0.71). The IVC proof chain provides soundness guarantees through transparent verification — no Groth16 trusted ceremony required.
- **NIZK proofs**: Ajtaï D2 sigma + BFV sigma with k-round parallel repetition. Greco quotient-witness verification strengthens soundness from modular to integer-lattice level.
- **On-chain verifier**: UltraHonk verifier (Solidity) with IVC binding. While proof metadata (proof_hash, vk_hash, pp_hash, z0/zi commitments, verification hashes) is bound into the on-chain commitment, the contract does **NOT** cryptographically verify the IVC proof itself. IVC mode is currently fail-closed (disabled) until a real decider is implemented.
- **No active surrogates on the default path** — all paths use real cryptographic proofs. The surrogate compressor is exclusively available behind `--features surrogate-compressor` (not in defaults).

## Threat Model

The PVTHFHE security model is evaluated across 6 axes:

1. **Adversary**: Malicious, computationally bounded (PPT).
2. **Corruption**: Honest-majority threshold t = ⌊n/2⌋ + 1. Up to n−t parties can be maliciously corrupted and collude.
3. **Network**: Synchronous communication for DKG and decryption rounds.
4. **Identity**: Authenticated channels; party identities are known and fixed for the duration of a protocol instance.
5. **Liveness**: Guaranteed as long as t honest parties participate.
6. **Abort**: Abort-with-public-blame; malicious behavior is detected and the offending party is identified.

## Assumptions Ledger

- **RLWE / Module-LWE**: Security of the underlying FHE scheme.
- **SIS / knLWE**: Hardness of finding short vectors, used in NIZK proofs (Ajtaï D2 commitment).
- **KZG Binding**: Security of the polynomial commitment scheme (BN254 + Grumpkin cycle).
- **Random Oracle Model**: Fiat-Shamir transform for NIZK and folding challenge derivation.

For full formal assumptions, see [.sisyphus/design/security-proofs.md](.sisyphus/design/security-proofs.md).

## Sigma Protocol Soundness

The ternary scalar challenge (`ch ∈ {−1,0,1}`) provides log₂(3) ≈ 1.58 bits of soundness per execution. With k-round parallel repetition (round-index binding via Fiat-Shamir), the soundness error is (2/3)^k:

| k | SIGMA_REPETITIONS | Soundness error | Effective bits | Constraint cost |
| --- | --- | --- | --- | --- |
| 1 | 1 | 2/3 (≈0.67) | ~1.58 | ~508K (baseline) |
| 10 | 10 | (2/3)^10 ≈ 0.017 | ~15.8 | ~5M |
| 45 | 45 | (2/3)^45 ≈ 2^−26 | ~71 | ~23M |
| **90** | **90** | **(2/3)^90 ≈ 2^−53** | **~142** | **~46M** (requires T4) |
| 128 | 128 | (2/3)^128 ≈ 2^−75 | ~203 | ~65M (requires T4) |

**Production target**: `SIGMA_REPETITIONS = 90` provides ~2^−53 soundness error per NIZK (≈2^−142 combined folding/SZ/NIZK budget). T4 JL random projection reduces norm-check dimensionality from 8192 to 256, keeping k=90 feasible at ~46M constraints. P1 is resolved; see `.sisyphus/plans/p1-sigma-repetition.md`.

## On-Chain Verification: IVC Binding (UNVERIFIED)

The `IvcBindingData` struct (11 fields: proof_hash, vk_hash, pp_hash, z0_commitment, zi_commitment, ivc_steps, share_verification_hash, decrypt_nizk_hash, dkg_transcript_hash, nova_final_state_commitment, `ivc_verify_result`) provides IVC proof binding for the on-chain verifier. However, **on-chain verification of the Nova IVC proof is NOT implemented**. The `ivc_verify_result` field is a placeholder; the Solidity verifier does not yet contain the cryptographic logic to validate the RecursiveSNARK. To prevent insecure usage, IVC mode is currently fail-closed.

## Known Limitations & Open Problems

### P1 (CRITICAL): Lattice NIZK Soundness

**Status**: OPEN (mitigated). Per-share RLWE NIZK knowledge soundness is conditional on Module-SIS hardness over R_{q_commit}, Cyclo Theorem 3 soundness, and SHA-256 collision resistance. The sigma protocol achieves computational ZK — fresh random masks per invocation, masked sigma transcript reveals nothing about the witness. Greco quotient-witness verification strengthens soundness from modular to integer-lattice level. P1 is mitigated via `SIGMA_REPETITIONS = 90` in production.

### P2 (HIGH): LatticeFold+ Linearity

**Status**: OPEN (documented). Cyclo LatticeFold+ over RLWE with Lemma 9 accepted as a documented protocol assumption. Soundness conditional on M-SIS hardness, Cyclo Theorem 3, and the Lemma 9 invertibility assumption. LatticeFold+ provides lattice-native folding in the current prototype.

### P4 (MEDIUM): On-Chain IVC Decider

**Status**: OPEN. The on-chain contract lacks a cryptographic decider for Nova IVC proofs. The system is currently fail-closed (disabled) for on-chain IVC verification.

### C5 (PK Aggregation Gap)

**Status**: OPEN. There is **NO** public proof that `pk_agg = Σ pk_i` for the accepted participant set. Aggregate key consistency is verified by runtime assertion only, providing no cryptographic guarantee against a malicious aggregator or coordinator.

### C2 (Encryption Correctness Gap)

**Status**: OPEN. Encryption is trusted; no verifiable proof of correct encryption against the aggregate key. Mitigated by semantic roundtrip check at the aggregate level.

### C7 (Final Aggregation Gap)

**Status**: OPEN. The Noir `aggregator_final` circuit proves only a **hash binding** (via in-circuit Poseidon R1CS Merkle verification), **NOT** the correctness of the threshold-decryption result. It does not cryptographically enforce that the aggregated shares correctly derive the plaintext.

### A1 (Cyclo Accumulator Gap)

**Status**: OPEN. Cyclo accumulator transcript verification is NOT implemented (see [A1](docs/OPEN-PROBLEM-BLOCKERS.md#a1--cyclo-accumulator-transcript-verification)). Nonzero accumulator bytes are rejected fail-closed; the accepted empty `acc_len=0` path is only a non-folded placeholder and is NOT fold verification.

## Trust Boundary: In-Circuit vs Native

Only the Noir `aggregator_final` circuit is verified on-chain (via HonkVerifier.sol). All other protocol proofs run natively and are NOT verifiable by the on-chain verifier directly. The `ivc_verify_result` field bridges this gap by binding the Nova IVC verification outcome.

| Protocol Proof | In-Circuit | Native-Only |
| --- | --- | --- |
| Threshold/Lagrange recombination | ✓ | — |
| Plaintext derivation | ✓ | — |
| BFV encryption sigma | — | ✓ |
| PVSS DKG NIZK | — | ✓ |
| Cyclo NIZK (lattice fold) | — | ✓ |
| Nova IVC fold soundness | — | ✓ (bound but NOT verified on-chain) |
| C7 decryption aggregation | ✓ (Hash binding only) | — |

## Post-Quantum Proving Stack

Post-quantum proving stack: LaZer (sigma) → Greyhound (commitments) → LatticeFold+ (folding) → UltraHonk (final proof).

## G7b Norm Enforcement

`CycloFoldStepCircuit` with state_len=8 tracks z_s_sq_acc/z_e_sq_acc accumulators to enforce norm bounds across fold steps. Defense-in-depth against unbounded norm growth.

## Parity-Check Proofs

RS polynomial verification with O(1) per-recipient DKG verification cost. Single parity proof replaces n separate NIZK proofs per party.

## Logging Hygiene

All FHE plaintext-slot logging is gated behind `trace-decrypt` feature, **disabled by default**. Must never be enabled in production, benchmarks with real plaintext, or any environment where plaintext confidentiality is required.

## Smudging

Conservative smudging parameter: σ_smudge = 2⁴⁰ · σ_err, providing >100 bits of statistical security against noise-based leakage (validated for N=8192). Two modes: `legacy_local_smudge` (local fresh Gaussian, non-committed) and `committed_smudge_pvss` (DKG-committed e_sm polynomial, the target committed mode with on-chain freshness enforcement via SessionRegistry).

## Responsible Disclosure

If you find a security vulnerability, please do not open a public issue. Contact maintainers at `security@example.com` (placeholder).

## Disclaimer

This software is provided "as is" for research purposes only. It has not undergone a professional security audit. Use in production environments is strictly discouraged.
