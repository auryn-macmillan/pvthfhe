# Interfold Threat Model & Attack Matrix

This document defines the threat model and attack matrix for The Interfold protocol, built on the Private-Verifiable Threshold FHE (PVTHFHE) architecture.

## 1. Overview

The Interfold is a decentralized protocol for executing threshold FHE operations on the EVM. It uses a committee of $N$ parties to manage an aggregate public key and perform threshold decryption.

PVTHFHE provides the cryptographic core for Interfold, including:
- **Hermine PVSS**: A lattice-based Publicly Verifiable Secret Sharing scheme for distributed key generation (DKG).
- **LatticeFold+**: An $O(n) \to O(\text{polylog } n)$ folding scheme for aggregating per-party decryption proofs.
- **MicroNova**: A recursive SNARK layer that compresses the folded proof for on-chain verification.

This threat model covers the cryptographic, protocol, and on-chain layers of the system.

## 2. Security Goals

The Interfold protocol aims to satisfy these primary security properties (cited from `security-proofs.md`):

| Property | Definition | Target |
|----------|------------|--------|
| **T-IND-CPA** | Confidentiality against chosen-plaintext attacks. Plaintexts remain hidden from any adversary controlling $< t$ parties. | Secrecy |
| **T-DEC-SOUND** | Decryption soundness. An aggregator cannot force the network to accept an incorrect decryption result. | Integrity |
| **T-PV-SOUND** | Public-verifiability soundness. On-chain verification is cryptographically robust; only valid proofs are accepted. | Integrity |
| **T-ROBUSTNESS** | Abort-with-public-blame. Malicious behavior is detectable, and the offender is uniquely identified (slashed). | Liveness |

## 3. Attack Matrix

This matrix enumerates specific attack scenarios, their mitigations, and current evidence pointers.

| # | Adversary Type | Capability | Targeted Asset | Mitigation | Evidence Pointer | Residual Risk |
|---|----------------|------------|---------------|------------|-----------------|---------------|
| **A1** | Passive Eavesdropper | Observe all P2P/broadcast traffic | Plaintext data | RLWE hardness + T-IND-CPA | `security-proofs.md §T-IND-CPA` | Traffic analysis (timing/volume) |
| **A2** | Corrupt Dealer (DKG) | Distribute malformed or biased shares | Collective public key | Hermine PVSS (T7) + Blame Protocol | `t11.8-adversary-model.md §1.3` | NIZK soundness (P1) |
| **A3** | Corrupt Minority (< t) | Withhold decryption shares | Protocol liveness | Threshold $t = \lfloor n/2 \rfloor + 1$ | `t11.6-withholding-griefing.md §H1` | Silent withholding attribution |
| **A4** | Sybil Aggregator | Submit duplicate shares to meet threshold | Integrity of sum | `party_id` deduplication (T11.6) | `t11.6-withholding-griefing.md §C1` | None |
| **A5** | Malicious Prover | Forge proof of incorrect decryption | On-chain state | LatticeFold+ Soundness (P2) + T-PV-SOUND | `security-proofs.md §T-PV-SOUND` | Open Problems P1, P2, P3 |
| **A6** | Replay Adversary | Replay old DKG or decryption transcripts | `SessionRegistry` state | `epoch` tracking + `markEpochConsumed` (T4) | `t11.7-liveness.md §L1` | None |
| **A7** | Side-Channel Observer | Measure timing of NIZK verification | Secret share bits | Constant-time comparisons (T11.5) | `t11.5-side-channel-audit.md §1-5` | Micro-architectural leaks |
| **A8** | Byzantine Node | Submit malformed shares (norm > $B_e$) | Noise budget (DoS) | `check_share_shortness` (T8) | `t11.6-withholding-griefing.md §L1` | Integration into `verify_share_set` |
| **A9** | Oracle Adversary | Observe error messages to extract key | Secret key | Uniform `FheError::Backend` sentinels | `t11.5-side-channel-audit.md §22` | None |
| **A10** | Deadlock Adversary | Stall DKG to block `dkgRoot` | Protocol liveness | `abortSession` (T11.7) | `t11.7-liveness.md §L1` | Session expiry (future work) |

## 4. T11.8 Adversary Model Cross-walk

Maps the adversary classes defined in the T11.8 Adversary Model to their corresponding rows in the Attack Matrix.

| T11.8 Class | Description | Attack Matrix Row(s) |
|-------------|-------------|----------------------|
| 1.1 | Passive Network Adversary | A1 |
| 1.2 | Active Network Adversary | A6 |
| 1.3 | Corrupt Minority Committee | A2, A3, A4, A8 |
| 1.4 | Corrupt Majority Committee | Out of Scope (Requires $t > n/2$) |
| 1.5 | Malicious On-Chain Prover | A5 |
| 1.6 | Side-Channel Adversary | A7, A9 |

## 5. Trust Assumptions

The security of Interfold relies on these foundational assumptions:

- **Cryptographic Assumptions**:
  - Hardness of RLWE and Module-LWE for the chosen parameters ($N=8192, \log_2 q \approx 174, B_e=16$).
  - Binding of KZG polynomial commitments on BN254.
  - Soundness of the Fiat-Shamir heuristic in the Random Oracle Model (ROM).
- **Protocol Assumptions**:
  - Honest majority: At least $t$ parties follow the protocol and keep their secret shares private.
  - Synchronous network: Messages for DKG and decryption rounds are delivered within a known time bound $\Delta$.
  - Authenticated channels: Every message can be uniquely attributed to its sender (verified via signatures or on-chain `msg.sender`).
- **Infrastructure Assumptions**:
  - EVM Integrity: The Ethereum Virtual Machine correctly executes the `SessionRegistry` and `PvtFheVerifier` bytecode.
  - Trusted Setup (P3): The universal SRS for the recursive SNARK layer was generated honestly.

## 6. Open Problems & Residual Risks

These items represent known gaps where full cryptographic security is not yet formally proven or implemented in the research prototype.

- **P1: Lattice NIZK Soundness**: Per-share RLWE NIZK knowledge soundness is conditional. The formal joint-extractor proof (T2) is a skeleton. See `docs/security-proofs/lemma9.md`.
- **P2: LatticeFold+ over RLWE**: The folding scheme over polynomial rings relies on the **Lemma 9 Invertibility Heuristic**. It is unproven if biased ternary challenge differences are always invertible for $X^{256}+1$.
- **P3: Full On-Chain Soundness**: The production verifier key (VK) cannot be emitted as a fully Barretenberg-generated Solidity verifier due to a format mismatch. Current `P3RealVerifier.sol` is a placeholder for the final production verifier.
- **C9: Conjecture 9**: The formal statement of Lemma 9 remains a conjecture until the T2 extractor is completed.

## 7. Out of Scope

The current PVTHFHE implementation and threat model do not address:

- **Corrupt Majority**: Attacks involving $t$ or more colluding parties.
- **Network-Level DoS**: Generic P2P flooding or Ethereum-level censorship.
- **Micro-architectural Side Channels**: Cache-timing attacks, Specter/Meltdown-class vulnerabilities.
- **Traffic Analysis**: Identifying participants or message types based on packet metadata.
- **Governance**: Malicious upgrade of the `SessionRegistry` or `PvtFheVerifier` contracts.
