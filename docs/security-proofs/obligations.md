# Proof Obligations Registry

<!-- 
This registry tracks the status of all theorem statements and their corresponding proofs 
for the four core problems: P4 (PVSS DKG), P1 (Lattice NIZK), P2 (LatticeFold+ over RLWE), 
and P3 (On-chain Verifier). 

Theorems are identified and added during the research phase for each problem.
-->

| Problem | Theorem-ID | Informal Statement | Status | Proof File Path | Paper Section |
|---------|------------|--------------------|--------|-----------------|---------------|
| P4 | P4-T1 | Accepted honest keygen transcript yields a valid BFV public key for the combined honest-share secret. | skeleton | docs/security-proofs/p4/t1-correctness.md | §P4-Correctness |
| P4 | P4-T2 | Any static adversary corrupting fewer than \(t\) parties learns no secret-key material beyond the public transcript, under Ring-LWE hardness. | skeleton | docs/security-proofs/p4/t2-secrecy.md | §P4-Secrecy |
| P4 | P4-T3 | Any accepting public verification transcript corresponds to a valid dealing, under binding and proof-of-knowledge style soundness. | skeleton | docs/security-proofs/p4/t3-public-verifiability-soundness.md | §P4-PublicVerif |
| P4 | P4-T4 | Misbehavior yields publicly checkable blame against the cheater, while honest parties are never falsely blamed. | skeleton | docs/security-proofs/p4/t4-abort-with-blame-robustness.md | §P4-Robustness |
| P4 | P4-T5 | The P4 ideal functionality composes sequentially with the P1 decrypt-share functionality in the UC setting. | skeleton | docs/security-proofs/p4/t5-sequential-composition.md | §P4-Composition |
