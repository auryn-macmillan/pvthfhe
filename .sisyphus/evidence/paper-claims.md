# Paper Claims Extraction

Total row count: 68
Sanity check (grep -nE 'novel|first|O\(|secure|prove|verify' paper/main.tex | wc -l): 7

| source file:line | exact quote | claim type | construction |
| :--- | :--- | :--- | :--- |
| paper/main.tex:23 | `We present PVTHFHE, a protocol for private-verifiable threshold fully homomorphic encryption achieving $O(n)$ per-party work and $O(\text{polylog}\, n)$ verifier cost.` | novelty | general |
| paper/main.tex:27 | `We prove correctness, soundness, and zero-knowledge for all sub-protocols and validate the implementation via end-to-end benchmarks.` | correctness | general |
| paper/main.tex:37 | `Our main contribution is a unified four-layer protocol (P4 $\to$ P1 $\to$ P2 $\to$ P3) that achieves $O(n)$ per-party work during the setup phase and $O(\text{polylog}\, n)$ on-chain verification cost, making it practical for blockchain deployment.` | novelty | general |
| paper/main.tex:61 | `\begin{theorem}[P4 Correctness]` | correctness | P4 |
| paper/main.tex:63 | `An accepted honest keygen transcript yields the unique serialized \texttt{BFVPublicKey} placeholder reconstructed from the dealer's Shamir secret over $2^{61}-1$.` | correctness | P4 |
| paper/main.tex:71 | `\begin{theorem}[P4 Static Secrecy]` | security | P4 |
| paper/main.tex:73 | `Any static adversary corrupting fewer than $t$ parties learns no additional information about the Shamir-shared secret under the current simulation; real Ring-LWE secrecy is deferred.` | security | P4 |
| paper/main.tex:81 | `\begin{theorem}[P4 Public Verifiability Soundness]` | security | P4 |
| paper/main.tex:83 | `Any artifact accepted by \texttt{verify\_transcript}, together with transcript shares passing public replay, corresponds to a valid SHA-256-commitment-consistent dealing.` | security | P4 |
| paper/main.tex:90 | `\begin{theorem}[P4 Abort-with-Blame Robustness]` | security | P4 |
| paper/main.tex:92 | `Misbehavior covered by the implemented commitment-recomputation predicates yields publicly checkable blame against the cheater, while honest parties are never falsely blamed.` | security | P4 |
| paper/main.tex:96 | `\begin{theorem}[P4 Sequential Composition]` | correctness | P4 |
| paper/main.tex:98 | `The simulated P4 session/public-key handoff composes sequentially with the P1 decrypt-share functionality at the exported interface boundary.` | correctness | P4 |
| paper/main.tex:108 | `\begin{theorem}[P1 Completeness]` | correctness | P1 |
| paper/main.tex:110 | `Honest witnesses satisfying the implemented SHA-256 commitment opening, bounded-error check, and SLAP-style transcript equations always yield an accepting P1 proof.` | correctness | P1 |
| paper/main.tex:114 | `\begin{theorem}[P1 Knowledge Soundness]` | security | P1 |
| paper/main.tex:116 | `Any accepting P1 prover yields a straight-line extractor recovering the opened witness for the implemented relation, except with probability bounded by the SHA-256 binding failure probability.` | security | P1 |
| paper/main.tex:120 | `\begin{theorem}[P1 Zero-Knowledge]` | security | P1 |
| paper/main.tex:122 | `The abstract randomized masked SLAP core transcript admits ROM zero-knowledge via HVZK-to-Fiat--Shamir compilation; the current deterministic audit payload lies outside the theorem statement.` | security | P1 |
| paper/main.tex:127 | `\begin{theorem}[P1 Commitment Binding]` | security | P1 |
| paper/main.tex:129 | `\texttt{pvss\_commitment} is binding on domain $\mathrm{SHA256}(\mathit{session\_id} \;\|\; \mathit{participant\_id\_le} \;\|\; \mathit{secret\_share\_be})$ under SHA-256 collision resistance.` | security | P1 |
| paper/main.tex:139 | `\begin{theorem}[P2 Folding Completeness]` | correctness | P2 |
| paper/main.tex:141 | `Honest P1 proofs fold into an accepting accumulator under the frozen verifier equation.` | correctness | P2 |
| paper/main.tex:144 | `\begin{theorem}[P2 Knowledge Soundness]` | security | P2 |
| paper/main.tex:146 | `A depth-$d$ accepting fold tree yields valid RLWE witnesses except with $(1/3)^d$ plus SHA-256 binding failure probability.` | security | P2 |
| paper/main.tex:150 | `\begin{theorem}[P2 ZK Preservation]` | security | P2 |
| paper/main.tex:152 | `Folding preserves only the projected SLAP core zero-knowledge view under ROM + HVZK assumptions.` | security | P2 |
| paper/main.tex:156 | `\begin{theorem}[P2 Accumulator Binding]` | security | P2 |
| paper/main.tex:158 | `The accumulator commitment is binding under RingSIS/M-SIS at the frozen P2 parameters.` | security | P2 |
| paper/main.tex:161 | `\begin{theorem}[P2 On-chain Compatibility]` | performance | P2 |
| paper/main.tex:163 | `The final accumulated proof targets Solidity/Yul verification within bounded gas and proof size.` | performance | P2 |
| paper/main.tex:182 | `\begin{theorem}[P3 On-chain Soundness]` | security | P3 |
| paper/main.tex:184 | `Any on-chain acceptance of the P3 verifier implies acceptance of the exact frozen P2 terminal accumulator statement on the same public inputs.` | security | P3 |
| paper/main.tex:188 | `\begin{theorem}[P3 Wrap Soundness Preservation]` | security | P3 |
| paper/main.tex:190 | `Any recursive or compressed wrap used by P3 preserves soundness of the wrapped P2 terminal relation; N/A if no wrap is used.` | security | P3 |
| paper/main.tex:194 | `\begin{theorem}[P3 Trusted-Setup Explicitness]` | security | P3 |
| paper/main.tex:196 | `Trusted-setup assumptions are explicit: setup compromise breaks P3 soundness if a setup-based verifier path is chosen, and is N/A otherwise.` | security | P3 |
| paper/main.tex:200 | `\begin{theorem}[P3 Gas Bound]` | performance | P3 |
| paper/main.tex:202 | `The deployed on-chain verifier halts within $\leq 5{,}000{,}000$ gas for all accept/reject paths, preventing gas-based denial of service.` | performance | P3 |
| paper/main.tex:206 | `\begin{theorem}[P3 Liveness and Blame]` | security | P3 |
| paper/main.tex:208 | `A valid P3 submission either finalizes on-chain or aborts under a publicly checkable blame predicate tied to calldata and contract state.` | security | P3 |
| paper/main.tex:242 | `P4 | Keygen latency ($n=128$) | 0.09 ms | $\leq 10$ ms` | performance | P4 |
| paper/main.tex:243 | `P4 | Reconstruct latency ($n=128$) | 0.05 ms | $\leq 10$ ms` | performance | P4 |
| paper/main.tex:244 | `P4 | Share size ($n=128$) | 4096 B | $\leq 65536$ B` | performance | P4 |
| paper/main.tex:245 | `P1 | Proof generation | $< 100$ ms | $\leq 500$ ms` | performance | P1 |
| paper/main.tex:246 | `P2 | Fold depth 8 accumulation | $< 1$ s | $\leq 5$ s` | performance | P2 |
| paper/main.tex:247 | `P3 | On-chain gas (accept) | $\leq 5{,}000{,}000$ | $\leq 5{,}000{,}000$` | performance | P3 |
| paper/claims-table.md:3 | `PVSS Keygen correctness: accepted honest keygen transcript yields the unique serialized BFVPublicKey placeholder reconstructed from the dealer's frozen Shamir secret over 2^61−1, matching the frozen P4 interface.` | correctness | P4 |
| paper/claims-table.md:4 | `PVSS Secrecy: any static adversary corrupting fewer than t parties learns no additional information about the Shamir-shared secret (simulation-based, with Ring-LWE caveat deferred).` | security | P4 |
| paper/claims-table.md:5 | `Public Verifiability Soundness: any artifact accepted by verify_transcript corresponds to a valid SHA-256-commitment-consistent dealing.` | security | P4 |
| paper/claims-table.md:6 | `Abort-with-Blame Robustness: misbehavior covered by commitment-recomputation predicates yields publicly checkable blame; honest parties are never falsely blamed.` | security | P4 |
| paper/claims-table.md:7 | `Sequential Composition: simulated P4 session/public-key handoff composes sequentially with the P1 decrypt-share functionality at the exported interface boundary.` | correctness | P4 |
| README.md:6 | `PVTHFHE targets private-verifiable threshold FHE with $O(n)$ per-party work and $O(\text{polylog } n)$ verifier cost.` | novelty | general |
| README.md:6 | `It enables a set of parties to jointly perform FHE operations where each step is publicly verifiable without revealing secret shares.` | novelty | general |
| ARCHITECTURE.md:3 | `PVTHFHE implements **Architecture B**: Lattice PVSS + LatticeFold+ + MicroNova.` | novelty | general |
| ARCHITECTURE.md:59 | `IND-CPA-PV: Ciphertext indistinguishability under chosen-plaintext attack with public verifiability.` | security | general |
| ARCHITECTURE.md:60 | `Decryption-Soundness: No adversary can force an incorrect decryption result to be accepted by the verifier.` | security | general |
| ARCHITECTURE.md:61 | `Public-Verifiability: Any third party can verify the correctness of the protocol execution.` | security | general |
| ARCHITECTURE.md:62 | `Robustness: The protocol succeeds as long as $t = \lfloor n/2 \rfloor + 1$ parties are honest.` | security | general |
| docs/security-proofs/obligations.md:21 | `Simulation-extractability is not part of the frozen P1 baseline because P2 does not consume simulated accepting P1 transcripts; a stronger theorem is required only if that interface changes.` | scope | P1 |
| docs/security-proofs/p1/theorem-inventory.md:7 | `For every session transcript inherited from P4 and every honest witness \((s_i,e_i)\) for participant \(i\) such that \(C_i = H(\mathsf{session\_id}\|\|i\|\|s_i)\), \(d_i = c \cdot s_i + e_i \bmod q\), and \(\lVert e_i \rVert_\infty \le B_e\), the honest prover outputs a proof \(\pi_i\) accepted by the P1 verifier on public statement \((\mathsf{session\_id}, i, t, c, d_i, C_i, q, N, k, B_e)\).` | correctness | P1 |
| docs/security-proofs/p1/theorem-inventory.md:16 | `For every PPT prover \(\mathcal{P}^H\) that makes the Fiat-Shamir verifier accept \((x_i,\pi_i)\) with non-negligible probability, there exists a ROM extractor \(\mathcal{E}^{\mathcal{P},H}\) that rewinds on the hash challenge and outputs \((s_i',e_i')\) satisfying the same relation except with probability bounded by the reduction loss to the underlying Module-SIS/Module-LWE-style argument and the probability of breaking SHA-256 commitment binding.` | security | P1 |
| docs/security-proofs/p1/theorem-inventory.md:25 | `For the abstract randomized SLAP core transcript—obtained by publishing only \`t_bytes, z_s, z_e\` and sampling fresh prover masks for the masked sigma relation—there exists a PPT simulator \(\mathsf{Sim}^H\) that, without knowing \((s_i,e_i)\), outputs a non-interactive transcript whose distribution is computationally indistinguishable from an honestly generated Fiat-Shamir proof for any true statement in the P1 language.` | security | P1 |
| docs/security-proofs/p1/theorem-inventory.md:34 | `Under the current threat model, simulation-soundness / simulation-extractability is not a required P1 theorem obligation, because P2 consumes prover-generated P1 proofs and does not rely on adversarial reuse of simulated accepting transcripts.` | scope | P1 |
| docs/security-proofs/p1/theorem-inventory.md:43 | `Any accepted P1 proof binds the public commitment to a unique opened \`secret_share\` except with negligible probability.` | security | P1 |
| paper/main.tex:24 | `achieving $O(n)$ per-party work and $O(\text{polylog}\, n)$ verifier cost.` | performance | general |
| paper/main.tex:38 | `achieves $O(n)$ per-party work during the setup phase and $O(\text{polylog}\, n)$ on-chain verification cost` | performance | general |
| paper/main.tex:262 | `complete four-layer construction for private-verifiable threshold FHE with $O(n)$ per-party setup and $O(\text{polylog}\, n)$ verification.` | novelty | general |
