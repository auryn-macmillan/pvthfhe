# Paper Claims (T6)

Extracted from: `paper/main.tex`, `README.md`, `ARCHITECTURE.md`, `paper/claims-table.md`.

| # | Source file:line | Exact quote | Claim type | Construction |
|---|---|---|---|---|
| 1 | paper/main.tex:23-24 | `achieving $O(n)$ per-party work and $O(\text{polylog}\, n)$ verifier cost` | performance | general |
| 2 | paper/main.tex:27 | `We prove correctness, soundness, and zero-knowledge for all` | security/correctness | general |
| 3 | paper/main.tex:35 | `with publicly verifiable proofs, each computation step becomes auditable by any observer` | correctness | general |
| 4 | paper/main.tex:38-39 | `achieves $O(n)$ per-party work during the setup phase and $O(\text{polylog}\, n)$ on-chain verification cost, making it practical for blockchain deployment` | performance | general |
| 5 | paper/main.tex:45 | `Our P3 on-chain verifier builds on EVM proof verification techniques` | novelty | P3 |
| 6 | paper/main.tex:57 | `The P4 sub-protocol implements a publicly-verifiable secret sharing (PVSS) distributed key` | correctness | P4 |
| 7 | paper/main.tex:59 | `and the dealer's commitment is verified via SHA-256` | correctness | P4 |
| 8 | paper/main.tex:83 | `Any artifact accepted by \texttt{verify\_transcript}, together with transcript shares passing` | security (soundness) | P4 |
| 9 | paper/main.tex:87 | `Follows from SHA-256 collision resistance` | security | P4 |
| 10 | paper/main.tex:116-117 | `Any accepting P1 prover yields a straight-line extractor recovering the opened witness for the implemented relation, except with probability bounded by the SHA-256 binding failure probability` | security (soundness) | P1 |
| 11 | paper/main.tex:129 | `\texttt{pvss\_commitment} is binding on domain $\mathrm{SHA256}(\mathit{session\_id} \;\|\; \ldots)$` | security (binding) | P1 |
| 12 | paper/main.tex:137 | `on-chain verification cost from $O(n)$ to $O(\text{polylog}\, n)$` | performance | P2/P3 |
| 13 | paper/main.tex:141 | `Honest P1 proofs fold into an accepting accumulator under the frozen verifier equation` | correctness | P2 |
| 14 | paper/main.tex:147 | `SHA-256 binding failure probability` | security | P2 |
| 15 | paper/main.tex:158 | `The accumulator commitment is binding under RingSIS/M-SIS at the frozen P2 parameters` | security (binding) | P2 |
| 16 | paper/main.tex:163 | `The final accumulated proof targets Solidity/Yul verification within bounded gas and proof size` | performance | P2 |
| 17 | paper/main.tex:170 | `The P3 on-chain verifier is a Solidity contract that accepts the accumulated P2 proof` | correctness | P3 |
| 18 | paper/main.tex:174 | `Any on-chain acceptance of the P3 verifier implies acceptance of the exact frozen P2 terminal accumulator statement on the same public inputs` | security (soundness) | P3 |
| 19 | paper/main.tex:180 | `Any recursive or compressed wrap used by P3 preserves soundness of the wrapped P2 terminal relation` | security | P3 |
| 20 | paper/main.tex:186-187 | `Trusted-setup assumptions are explicit: setup compromise breaks P3 soundness if a setup-based verifier path is chosen, and is N/A otherwise` | security | P3 |
| 21 | paper/main.tex:192 | `The deployed on-chain verifier halts within $\leq 5{,}000{,}000$ gas for all accept/reject paths` | performance | P3 |
| 22 | paper/main.tex:244-245 | `The main open question is the tightness of the P1 soundness reduction: the current proof achieves straight-line extraction under SHA-256 binding but does not achieve simulation` | security (gap) | P1 |
| 23 | paper/main.tex:251-252 | `We have presented PVTHFHE, a complete four-layer construction for private-verifiable threshold FHE with $O(n)$ per-party setup and $O(\text{polylog}\, n)$ verification. All sub-protocols` | novelty/performance | general |
| 24 | README.md:7 | `PVTHFHE targets private-verifiable threshold FHE with $O(n)$ per-party work and $O(\text{polylog } n)$ verifier cost. It enables a set of parties to jointly perform FHE operations where each step is publicly verifiable without revealing secret shares` | performance/correctness | general |
| 25 | README.md:15 | `Open Problem P1: Lattice NIZK well-formedness soundness is not formally proven` | security (gap) | P1 |
| 26 | ARCHITECTURE.md:13 | `A Solidity verifier checks the final proof, ensuring the decryption result is correct` | correctness | P3 |
| 27 | ARCHITECTURE.md:59 | `IND-CPA-PV: Ciphertext indistinguishability under chosen-plaintext attack with public verifiability` | security | general |
| 28 | ARCHITECTURE.md:60 | `Decryption-Soundness: No adversary can force an incorrect decryption result to be accepted by the verifier` | security (soundness) | general |
| 29 | ARCHITECTURE.md:61 | `Public-Verifiability: Any third party can verify the correctness of the protocol execution` | correctness | general |
| 30 | ARCHITECTURE.md:67 | `P1: Lattice NIZK well-formedness soundness` (listed as open problem) | security (gap) | P1 |
| 31 | paper/claims-table.md:17 | `On-chain Soundness: any on-chain acceptance of the P3 verifier implies acceptance of the exact frozen P2 terminal accumulator statement on the same public inputs` | security (soundness) | P3 |
| 32 | paper/claims-table.md:19 | `Trusted-Setup Explicitness: trusted-setup assumptions are explicit; setup compromise breaks P3 soundness if a setup-based verifier path is chosen` | security | P3 |
| 33 | paper/claims-table.md:20 | `Gas Bound: the deployed on-chain verifier halts within ≤5,000,000 gas for all accept/reject paths, preventing gas-based denial of service` | performance | P3 |

## Summary counts
- Novelty claims: 2 (rows 5, 23)
- Performance claims: 8 (rows 1, 4, 12, 16, 21, 23, 24, 33)
- Security claims: 15 (rows 2, 8, 9, 10, 11, 14, 15, 18, 19, 20, 22, 25, 27, 28, 32)
- Correctness claims: 8 (rows 3, 6, 7, 13, 17, 24, 26, 29, 31)

> **NOTE for T13**: Claims #18 and #31 (P3 on-chain soundness "implies acceptance of exact frozen P2 accumulator") directly contradict the T1 vacuity evidence: `P3RealVerifier.sol` does `ecrecover` only — it does not check any P2 accumulator. These will be classified `contradicted` in T13.
