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
| P1 | P1-T1 | Honest witnesses satisfying the implemented SHA-256 commitment opening, bounded-error check, and SLAP-style transcript equations always yield an accepting P1 proof. | PROVED | docs/security-proofs/p1/T1.md | §P1-Completeness |
| P1 | P1-T2 | Any accepting P1 prover yields a straight-line extractor recovering the opened witness for the implemented relation, except with probability bounded by SHA-256 binding failure. | PROVED | docs/security-proofs/p1/T2.md | §P1-Soundness |
| P1 | P1-T3 | The abstract randomized masked SLAP core transcript admits ROM zero-knowledge via HVZK-to-Fiat–Shamir compilation; the current deterministic audit payload lies outside the theorem statement. | PROVED | docs/security-proofs/p1/T3.md | §P1-ZK |
| P1 | P1-T4 | Simulation-extractability is not part of the frozen P1 baseline because P2 does not consume simulated accepting P1 transcripts; a stronger theorem is required only if that interface changes. | DEFERRED | docs/security-proofs/p1/T4.md | §P1-SimExtractability |
| P1 | P1-T5 | B.I.4 implementation-level theorem: `pvss_commitment` is binding on the domain `SHA256(session_id || participant_id_le || secret_share_be)` under SHA-256 collision resistance. | PROVED | docs/security-proofs/p1/T5.md | §P1-Binding |
| P2 | P2-T1 | Honest P1 proofs fold into an accepting accumulator under the frozen verifier equation. | skeleton | docs/security-proofs/p2/proof-skeletons.md | §P2-Completeness |
| P2 | P2-T2 | A depth-d accepting fold tree yields valid RLWE witnesses except with (1/3)^d plus SHA-256 binding failure. | skeleton | docs/security-proofs/p2/proof-skeletons.md | §P2-KnowledgeSoundness |
| P2 | P2-T3 | Folding preserves only the projected SLAP core zero-knowledge view under ROM + HVZK assumptions. | skeleton | docs/security-proofs/p2/proof-skeletons.md | §P2-ZKPreservation |
| P2 | P2-T4 | The accumulator commitment is binding under RingSIS/M-SIS at the frozen P2 parameters. | skeleton | docs/security-proofs/p2/proof-skeletons.md | §P2-AccumulatorBinding |
| P2 | P2-T5 | The final accumulated proof targets Solidity/Yul verification within bounded gas and proof size. | skeleton | docs/security-proofs/p2/proof-skeletons.md | §P2-OnchainCompatibility |
