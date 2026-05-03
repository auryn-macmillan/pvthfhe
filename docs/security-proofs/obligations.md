# Proof Obligations Registry

<!-- 
This registry tracks the status of all theorem statements and their corresponding proofs 
for the four core problems: P4 (PVSS DKG), P1 (Lattice NIZK), P2 (LatticeFold+ over RLWE), 
and P3 (On-chain Verifier). 

Theorems are identified and added during the research phase for each problem.
-->

| Problem | Theorem-ID | Informal Statement | Status | Proof File Path | Paper Section |
|---------|------------|--------------------|--------|-----------------|---------------|
| P4 | P4-T1 | Accepted honest keygen transcript yields the unique serialized `BFVPublicKey` placeholder reconstructed from the dealer's Shamir secret over \(2^{61}-1\). | proven | docs/security-proofs/p4/t1-correctness.md | §P4-Correctness |
| P4 | P4-T2 | Any static adversary corrupting fewer than \(t\) parties learns no additional information about the Shamir-shared secret in the current simulated implementation; a real Ring-LWE secrecy proof is deferred. | proven | docs/security-proofs/p4/t2-secrecy.md | §P4-Secrecy |
| P4 | P4-T3 | Any artifact accepted by `verify_transcript`, together with transcript shares passing public replay, corresponds to a valid SHA-256-commitment-consistent dealing in the current simulation. | proven | docs/security-proofs/p4/t3-public-verifiability-soundness.md | §P4-PublicVerif |
| P4 | P4-T4 | Misbehavior covered by the implemented commitment-recomputation predicates yields publicly checkable blame against the cheater, while honest parties are never falsely blamed. | proven | docs/security-proofs/p4/t4-abort-with-blame-robustness.md | §P4-Robustness |
| P4 | P4-T5 | The simulated P4 session/public-key handoff composes sequentially with the P1 decrypt-share functionality at the exported interface boundary; real RLWE handoff claims are deferred. | proven | docs/security-proofs/p4/t5-sequential-composition.md | §P4-Composition |
| P1 | P1-T1 | Honest witnesses satisfying the bounded decrypt-share relation and inherited SHA-256 commitment always yield an accepting P1 proof. | skeleton | docs/security-proofs/p1/proof-skeletons.md | §P1-Completeness |
| P1 | P1-T2 | Any accepting P1 prover in the ROM admits a rewinding extractor recovering \((s_i,e_i)\) consistent with the public ciphertext, commitment, and parameter bounds. | skeleton | docs/security-proofs/p1/proof-skeletons.md | §P1-KnowledgeSoundness |
| P1 | P1-T3 | The interactive HVZK proof for the joint SHA-256/RLWE relation compiles via Fiat-Shamir into a ROM NIZK for the full public statement. | skeleton | docs/security-proofs/p1/proof-skeletons.md | §P1-ZK |
| P1 | P1-T4 | Simulation-extractability is not part of the frozen P1 baseline because P2 does not consume simulated accepting P1 transcripts; a stronger theorem is required only if that interface changes. | skeleton | docs/security-proofs/p1/proof-skeletons.md | §P1-SimExtractability |
| P1 | P1-T5 | If P1 amortizes proofs across multiple decrypt shares, batch acceptance still implies per-share witness validity up to the stated aggregation loss. | skeleton | docs/security-proofs/p1/proof-skeletons.md | §P1-BatchSoundness |
