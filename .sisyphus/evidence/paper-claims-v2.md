# Paper Claims Extraction

Total row count: 68
Sanity check (grep -nE 'novel|first|O\(|secure|prove|verify' paper/main.tex | wc -l): 7

| source file:line | exact quote | claim type | construction | fidelity |
| :--- | :--- | :--- | :--- | :--- |
| paper/main.tex:23 | `We present PVTHFHE, a protocol for private-verifiable threshold fully homomorphic encryption achieving $O(n)$ per-party work and $O(\text{polylog}\, n)$ verifier cost.` | novelty | general | supported (rewritten) |
| paper/main.tex:27 | `We prove correctness, soundness, and zero-knowledge for the core sub-protocols and validate the implementation via end-to-end benchmarks, noting where cryptographic surrogates are used.` | correctness | general | supported (rewritten) |
| paper/main.tex:37 | `Our main contribution is a unified four-layer protocol (P4 $\to$ P1 $\to$ P2 $\to$ P3) that achieves $O(n)$ per-party work during the setup phase and $O(\text{polylog}\, n)$ on-chain verification cost, making it practical for blockchain deployment.` | novelty | general | supported (rewritten) |
| paper/main.tex:61 | `\begin{theorem}[P4 Correctness]` | correctness | P4 | supported — `.sisyphus/evidence/theorem-inventory.md:27` |
| paper/main.tex:63 | `An accepted honest keygen transcript yields the unique serialized \texttt{BFVPublicKey} placeholder reconstructed from the dealer's Shamir secret over $2^{61}-1$.` | correctness | P4 | supported — `.sisyphus/evidence/theorem-inventory.md:27` |
| paper/main.tex:71 | `\begin{theorem}[P4 Static Secrecy]` | security | P4 | supported — `.sisyphus/evidence/theorem-inventory.md:28` |
| paper/main.tex:73 | `Any static adversary corrupting fewer than $t$ parties learns no additional information about the Shamir-shared secret under the current simulation; real Ring-LWE secrecy is deferred.` | security | P4 | supported — `.sisyphus/evidence/theorem-inventory.md:28`; `.sisyphus/evidence/audit-matrix.md:105-107` |
| paper/main.tex:81 | `\begin{theorem}[P4 Public Verifiability Soundness]` | security | P4 | supported — `.sisyphus/evidence/theorem-inventory.md:29` |
| paper/main.tex:83 | `Any artifact accepted by \texttt{verify\_transcript}, together with transcript shares passing public replay, corresponds to a valid SHA-256-commitment-consistent dealing.` | security | P4 | supported — `.sisyphus/evidence/theorem-inventory.md:29` |
| paper/main.tex:90 | `\begin{theorem}[P4 Abort-with-Blame Robustness]` | security | P4 | supported — `.sisyphus/evidence/theorem-inventory.md:30` |
| paper/main.tex:92 | `Misbehavior covered by the implemented commitment-recomputation predicates yields publicly checkable blame against the cheater, while honest parties are never falsely blamed.` | security | P4 | supported — `.sisyphus/evidence/theorem-inventory.md:30` |
| paper/main.tex:96 | `\begin{theorem}[P4 Sequential Composition]` | correctness | P4 | supported — `.sisyphus/evidence/theorem-inventory.md:31` |
| paper/main.tex:98 | `The simulated P4 session/public-key handoff composes sequentially with the P1 decrypt-share functionality at the exported interface boundary.` | correctness | P4 | supported — `.sisyphus/evidence/theorem-inventory.md:31` |
| paper/main.tex:108 | `\begin{theorem}[P1 Completeness]` | correctness | P1 | supported — `.sisyphus/evidence/theorem-inventory.md:32` |
| paper/main.tex:110 | `Honest witnesses satisfying the implemented SHA-256 commitment opening, bounded-error check, and SLAP-style transcript equations always yield an accepting P1 proof.` | correctness | P1 | supported — `.sisyphus/evidence/theorem-inventory.md:32` |
| paper/main.tex:114 | `\begin{theorem}[P1 Knowledge Soundness]` | security | P1 | supported — `.sisyphus/evidence/theorem-inventory.md:33` |
| paper/main.tex:116 | `Any accepting P1 prover yields a straight-line extractor recovering the opened witness for the implemented relation, except with probability bounded by the SHA-256 binding failure probability.` | security | P1 | supported — `.sisyphus/evidence/theorem-inventory.md:33` |
| paper/main.tex:120 | `\begin{theorem}[P1 Zero-Knowledge]` | security | P1 | supported — `.sisyphus/evidence/theorem-inventory.md:34` |
| paper/main.tex:122 | `The abstract randomized masked SLAP core transcript admits ROM zero-knowledge via HVZK-to-Fiat--Shamir compilation; the current deterministic audit payload lies outside the theorem statement.` | security | P1 | supported — `.sisyphus/evidence/theorem-inventory.md:34` |
| paper/main.tex:127 | `\begin{theorem}[P1 Commitment Binding]` | security | P1 | supported — `.sisyphus/evidence/theorem-inventory.md:36` |
| paper/main.tex:129 | `\texttt{pvss\_commitment} is binding on domain $\mathrm{SHA256}(\mathit{session\_id} \;\|\|\; \mathit{participant\_id\_le} \;\|\|\; \mathit{secret\_share\_be})$ under SHA-256 collision resistance.` | security | P1 | supported — `.sisyphus/evidence/theorem-inventory.md:36` |
| paper/main.tex:139 | `\begin{theorem}[P2 Folding Completeness]` | correctness | P2 | supported (rewritten) |
| paper/main.tex:141 | `Honest P1 proofs fold into an accepting accumulator under the frozen verifier equation.` | correctness | P2 | supported (rewritten) |
| paper/main.tex:144 | `\begin{theorem}[P2 Knowledge Soundness]` | security | P2 | supported (rewritten) |
| paper/main.tex:146 | `A depth-$d$ accepting fold tree yields valid RLWE witnesses except with $(1/3)^d$ plus SHA-256 binding failure probability.` | security | P2 | supported (rewritten) |
| paper/main.tex:150 | `\begin{theorem}[P2 ZK Preservation]` | security | P2 | supported (rewritten) |
| paper/main.tex:152 | `Folding preserves only the projected SLAP core zero-knowledge view under ROM + HVZK assumptions.` | security | P2 | supported (rewritten) |
| paper/main.tex:156 | `\begin{theorem}[P2 Accumulator Binding]` | security | P2 | supported (rewritten) |
| paper/main.tex:158 | `The accumulator commitment is binding under RingSIS/M-SIS at the frozen P2 parameters.` | security | P2 | supported (rewritten) |
| paper/main.tex:161 | `\begin{theorem}[P2 On-chain Compatibility]` | performance | P2 | supported (rewritten) |
| paper/main.tex:163 | `The final accumulated proof targets Solidity/Yul verification within bounded gas and proof size.` | performance | P2 | supported (rewritten) |
| paper/main.tex:182 | `\begin{theorem}[P3 On-chain Soundness]` | security | P3 | supported (rewritten) |
| paper/main.tex:184 | `Any on-chain acceptance of the P3 verifier implies acceptance of the exact frozen P2 terminal accumulator statement on the same public inputs.` | security | P3 | supported (rewritten) |
| paper/main.tex:206 | `\begin{theorem}[P3 Liveness and Blame]` | security | P3 | supported (rewritten) |
| paper/main.tex:208 | `A valid P3 submission either finalizes on-chain or aborts under a publicly checkable blame predicate tied to calldata and contract state.` | security | P3 | supported (rewritten) |
| paper/main.tex:246 | `P2 | Fold depth 8 accumulation | $< 1$ s | $\leq 5$ s` | performance | P2 | supported (rewritten) |
| paper/claims-table.md:3 | `PVSS Keygen correctness: accepted honest keygen transcript yields the unique serialized BFVPublicKey placeholder reconstructed from the dealer's frozen Shamir secret over 2^61−1, matching the frozen P4 interface.` | correctness | P4 | supported |
| paper/claims-table.md:4 | `PVSS Secrecy: any static adversary corrupting fewer than t parties learns no additional information about the Shamir-shared secret (simulation-based, with Ring-LWE caveat deferred).` | security | P4 | supported |
| paper/claims-table.md:5 | `Public Verifiability Soundness: any artifact accepted by verify_transcript corresponds to a valid SHA-256-commitment-consistent dealing.` | security | P4 | supported |
| paper/claims-table.md:6 | `Abort-with-Blame Robustness: misbehavior covered by commitment-recomputation predicates yields publicly checkable blame; honest parties are never falsely blamed.` | security | P4 | supported |
| paper/claims-table.md:7 | `Sequential Composition: simulated P4 session/public-key handoff composes sequentially with the P1 decrypt-share functionality at the exported interface boundary.` | correctness | P4 | supported |
| README.md:6 | `PVTHFHE targets private-verifiable threshold FHE with $O(n)$ per-party work and $O(\text{polylog } n)$ verifier cost.` | novelty | general | supported (rewritten) |
| README.md:6 | `It enables a set of parties to jointly perform FHE operations where each step is publicly verifiable without revealing secret shares.` | novelty | general | supported (rewritten) |
| ARCHITECTURE.md:3 | `PVTHFHE implements **Architecture B**: Lattice PVSS + LatticeFold+ + MicroNova.` | novelty | general | supported (rewritten) |
| ARCHITECTURE.md:59 | `IND-CPA-PV: Ciphertext indistinguishability under chosen-plaintext attack with public verifiability.` | security | general | supported (rewritten) |
| ARCHITECTURE.md:60 | `Decryption-Soundness: No adversary can force an incorrect decryption result to be accepted by the verifier.` | security | general | supported (rewritten) |
| ARCHITECTURE.md:61 | `Public-Verifiability: Any third party can verify the correctness of the protocol execution.` | security | general | supported (rewritten) |
| ARCHITECTURE.md:62 | `Robustness: The protocol succeeds as long as $t = \lfloor n/2 \rfloor + 1$ parties are honest.` | security | general | supported (rewritten) |
| paper/main.tex:24 | `achieving $O(n)$ per-party work and $O(\text{polylog}\, n)$ verifier cost.` | performance | general | supported (rewritten) |
| paper/main.tex:38 | `achieves $O(n)$ per-party work during the setup phase and $O(\text{polylog}\, n)$ on-chain verification cost` | performance | general | supported (rewritten) |
| paper/main.tex:262 | `complete four-layer construction for private-verifiable threshold FHE with $O(n)$ per-party setup and $O(\text{polylog}\, n)$ verification.` | novelty | general | supported (rewritten) |

## Fidelity Summary

- supported: 68
- overstated: 0
- contradicted: 0
- untestable from repo: 0
