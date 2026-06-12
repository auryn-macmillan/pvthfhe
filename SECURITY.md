# Security

> ⚠️  **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**
>
> This repository contains a **research implementation** of private-verifiable threshold FHE:
> - **On-chain verifier uses LatticeFold+ folding with transparent accumulator + UltraHonk state commitment**
> - **Noir circuits implement real aggregation and wrapping logic**
> - **Do not use for The Interfold or any production deployment**
>
> See [SECURITY-ADVISORY-001.md](SECURITY-ADVISORY-001.md), [WARNING.md](WARNING.md), and [docs/OPEN-PROBLEM-BLOCKERS.md](docs/OPEN-PROBLEM-BLOCKERS.md) for details.

This document outlines the security model, assumptions, and limitations of the PVTHFHE research prototype.

## Implementation Status

- **FHE backend**: Real threshold BFV via `gnosisguild/fhe.rs`.
- **Verifiable FHE ops**: FHE Add and Mul verified in-circuit at production N=8192 (use `--features bfv-n4` for fast testing at N=4). Relinearize gated behind `real-relin` feature.
- **LatticeFold+ Folding**: Maliciously-secure lattice-native folding via Cyclo RLWE (Track B, sole backend). Track A (Nova SNARK BN254+Grumpkin) removed per P4 deprecation. The folding chain provides soundness guarantees through transparent lattice verification — no Groth16 trusted ceremony required, no elliptic curve assumptions.
- **NIZK proofs**: Ajtaï D2 sigma + BFV sigma with k-round parallel repetition. Greco quotient-witness verification strengthens soundness from modular to integer-lattice level. M7 fix (2026-06-05): zero-witness rejection via Ajtai commitment all-zeros check.
- **On-chain verifier**: UltraHonk verifier (Solidity) with folding binding. While proof metadata is bound into the on-chain commitment, the contract does **NOT** cryptographically verify the LatticeFold+ proof itself. Verification is currently fail-closed (disabled) until a real decider is implemented.
- **No active surrogates on the default path** — all paths use real cryptographic proofs. The surrogate compressor is exclusively available behind `--features surrogate-compressor` (not in defaults).
- **Latest audit**: MPC security audit 2026-06-08 v3 code-level verification (`.sisyphus/audit/MPC-AUDIT-2026-06-08-v3.md`) — 6 of 8 prior regressions confirmed FIXED in code. 2 partial fixes (fold challenge at 64-bit → 128-bit planned; LaZer binding injection planned). 3 new LOW/MEDIUM findings identified. See [`.sisyphus/plans/mpc-audit-2026-06-08-v3-remediation.md`](.sisyphus/plans/mpc-audit-2026-06-08-v3-remediation.md).
- **Previous**: MPC security audit 2026-06-07 v2 (`.sisyphus/audit/MPC-AUDIT-2026-06-07-FRESH-v2.md`) — 8 prior findings confirmed as regressions, all resolved. 5 new findings identified and resolved.

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
- **Ajtai Lattice Commitments**: Security of the Ajtai (SIS-based) commitment scheme over Z_q (q = Q_COMMIT ≈ 2^49). No elliptic curve assumptions. Replaces KZG commitments (BN254 + Grumpkin) from removed Track A.
- **Random Oracle Model**: Fiat-Shamir transform for NIZK and folding challenge derivation.
- **Schnorr Signatures (BN254)**: Existential unforgeability of Schnorr over BN254 G1, used for NonEquiv quorum signatures and rogue-key prevention (PoP).
- **SHA-256 Collision Resistance**: Hash-based commitments for NonEquiv message binding, AVID Merkle leaves, committee VRF, and leader election ranks. See [.sisyphus/design/spec-non-equiv.md](.sisyphus/design/spec-non-equiv.md).

## DKG Paper Integration (ePrint 2026/1159)

The DKG protocol integrates five building blocks from Abraham-Bacho-Stern 2026/1159:
- **Non-Equivocation** (§4.1): Quorum-intersection-based equivocation detection via Schnorr signatures.
- **Provable AVID** (§4.3): Merkle-tree-based information dispersal for efficient share distribution.
- **Committee-Based Sharing** (§4.2 ref): VRF-driven committee selection to reduce communication complexity.
- **Key Escrow** (§6): Ephemeral key generation for distributed decryption authorization.
- **Weak Leader Election** (§7): Deterministic aggregator selection with retroactive verifiability.

All techniques are adapted to pvthfhe's synchronous network model and lattice-first cryptographic stack.
See [`.sisyphus/plans/dkg-paper-integration.md`](.sisyphus/plans/dkg-paper-integration.md) for the full integration plan.

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

## On-Chain Verification: Folding Proof Binding (UNVERIFIED)

The LatticeFold+ accumulator state is bound to the on-chain verifier via Keccak256 hashing. However, **on-chain cryptographic verification of the LatticeFold+ proof is NOT implemented**. The Solidity verifier does not yet contain the logic to validate the folding accumulator. To prevent insecure usage, verification is currently fail-closed.

## Known Limitations & Open Problems

### P1 (CRITICAL): Lattice NIZK Soundness

**Status**: OPEN (mitigated). Per-share RLWE NIZK knowledge soundness is conditional on Module-SIS hardness over R_{q_commit}, Cyclo Theorem 3 soundness, and SHA-256 collision resistance. The sigma protocol achieves computational ZK — fresh random masks per invocation, masked sigma transcript reveals nothing about the witness. Greco quotient-witness verification strengthens soundness from modular to integer-lattice level. P1 is mitigated via `SIGMA_REPETITIONS = 90` in production.

### P2 (HIGH): LatticeFold+ Linearity

**Status**: OPEN (documented). Cyclo LatticeFold+ over RLWE with Lemma 9 accepted as a documented protocol assumption. Soundness conditional on M-SIS hardness, Cyclo Theorem 3, and the Lemma 9 invertibility assumption. LatticeFold+ provides lattice-native folding in the current prototype.

### P4 (MEDIUM): On-Chain Folding Proof Decider

**Status**: OPEN. The on-chain contract lacks a cryptographic decider for LatticeFold+ proofs. The system is currently fail-closed (disabled) for on-chain folding verification.

### C5 (PK Aggregation Gap)

**Status**: OPEN. There is **NO** public proof that `pk_agg = Σ pk_i` for the accepted participant set. Aggregate key consistency is verified by runtime assertion only, providing no cryptographic guarantee against a malicious aggregator or coordinator.

### C2 (Encryption Correctness Gap)

**Status**: OPEN. Encryption is trusted; no verifiable proof of correct encryption against the aggregate key. Mitigated by semantic roundtrip check at the aggregate level.

### C7 (Final Aggregation Gap)

**Status**: ✅ RESOLVED (2026-06-04). The Noir `aggregator_final` circuit now proves full Schwartz-Zippel threshold-decryption correctness (Lagrange recombination `sum(lambda_i * d_i(r)) = pt(r)`) plus in-circuit Poseidon Merkle PK binding. The old "hash binding only" limitation is removed — the circuit enforces the actual algebraic recombination. See [docs/paper-code-alignment.md](docs/paper-code-alignment.md#c7-threshold-decryption-correctness).

### A1 (Cyclo Accumulator Gap)

**Status**: ✅ RESOLVED (2026-06-04). Cyclo accumulator transcript verification is implemented via `accumulator_codec.rs` (618-line versioned wire format) and `verify_accumulator_transcript()` in the NIZK adapter. 21 tests cover codec validation, fail-closed checks, and adversarial scenarios. See [docs/paper-code-alignment.md](docs/paper-code-alignment.md#a1-cyclo-accumulator-transcript-verification).

## Trust Boundary: In-Circuit vs Native

Only the Noir `aggregator_final` circuit is verified on-chain (via HonkVerifier.sol). All other protocol proofs run natively and are NOT verifiable by the on-chain verifier directly. The folding accumulator state bridges this gap by binding the LatticeFold+ verification outcome.

| Protocol Proof | In-Circuit | Native-Only |
| --- | --- | --- |
| Threshold/Lagrange recombination | ✓ | — |
| Plaintext derivation | ✓ | — |
| BFV encryption sigma | — | ✓ |
| PVSS DKG NIZK | — | ✓ |
| Cyclo NIZK (lattice fold) | — | ✓ |
| LatticeFold+ fold soundness | — | ✓ (bound but NOT verified on-chain) |
| C7 decryption aggregation | ✓ (Full S-Z correctness) | — |

## Trusted Components

The following components are trusted without cryptographic proof of correctness:

| Component | Trust Assumption | Impact |
| --- | --- | --- |
| `fhe-math` NTT | NTT implementation is assumed correct. No independent proof of NTT correctness exists. | NTT bugs could produce valid-looking sigma proofs for malformed ciphertexts. The Schwarz-Zippel evaluation path sidesteps NTT in-circuit, but native proof generation/verification still depends on NTT for RNS polynomial arithmetic. |
| `fhe-math` RNS arithmetic | RNS limb arithmetic (modular reduction, limb decomposition) is assumed correct. | Arithmetic errors could affect commitment computation and equation checks, producing false proofs or false verifications. |

## BFV Sigma Caveats

BFV sigma proofs (`bfv_sigma.rs`) have the following documented limitations:

- **Computational ZK only**: BFV sigma proofs achieve computational zero-knowledge through noise drowning (witness-to-mask ratio ≥ 4.0), NOT statistical ZK.
- **No rejection sampling**: The Lyubashevsky rejection-sampling loop is not implemented. The response distribution is dominated by the masking term (B_Y = 2^30), providing computational ZK under the RLWE assumption.
- **No in-circuit verifier**: There is no Noir/R1CS verifier for BFV sigma proofs. BFV sigma proofs are outer-circuit only and cannot be used inside LatticeFold+ step circuits. For BFV ciphertext verification inside circuits, use the Schwarz-Zippel evaluation approach instead (`sigma.rs::compute_sigma_sz_data`).

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

## Accepted Research Limitations (MPC-AUDIT-2026-06-12)

### F12: Cross-Instance Abort Propagation

**Status**: ACCEPTED LIMITATION (research prototype)

The PVTHFHE protocol is designed for single-process sequential execution (simulator mode). In a real multi-party deployment where each party runs independently, there is no mechanism for one party's abort to trigger cleanup on other parties' instances. Each party detects protocol failure independently through timeout or invalid-message rejection.

**Production path**: A real deployment would use a consensus-broadcast channel (e.g., Ethereum event logs) for abort signaling. This is out of scope for the research prototype.

### F13: Wire Coefficient Domain Validation

**Status**: ACCEPTED LIMITATION (research prototype)

FHE wire types (`KeygenShareV1`, `PublicKeyV1`, `DecryptShareV2`) validate length bounds but do not validate that polynomial coefficient bytes represent valid field elements. Invalid coefficients are caught during cryptographic operations. Full coefficient-domain validation deferred to production hardening.

### F1 PoP: Schnorr PoP Session Independence

**Status**: DESIGN DECISION

Schnorr Proof-of-Possession is intentionally session-independent because keys are long-term (reused across DKG sessions). PoP demonstrates knowledge of `sk` for a given `pk` — cross-session replay of the same PoP does not grant new capabilities. If keys become session-scoped in future, PoP must bind session_id.

## Responsible Disclosure

If you find a security vulnerability, please do not open a public issue. Contact maintainers at `security@example.com` (placeholder).

## Disclaimer

This software is provided "as is" for research purposes only. It has not undergone a professional security audit. Use in production environments is strictly discouraged.
