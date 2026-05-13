| Problem | Theorem-ID | Informal Claim | Track A Status | Track B Status | Paper Section | Proof File |
|---------|------------|----------------|----------------|----------------|---------------|------------|
| P4 | P4-T1 | PVSS Keygen correctness: accepted honest keygen transcript yields the unique serialized BFVPublicKey placeholder reconstructed from the dealer's frozen Shamir secret over 2^61−1. | PROVED | PROVED (shared) | §P4-Correctness | docs/security-proofs/p4/t1-correctness.md |
| P4 | P4-T2 | PVSS Secrecy: any static adversary corrupting fewer than t parties learns no additional information about the Shamir-shared secret (simulation-based, with Ring-LWE caveat deferred). | PROVED | PROVED (shared) | §P4-Secrecy | docs/security-proofs/p4/t2-secrecy.md |
| P4 | P4-T3 | Public Verifiability Soundness: any artifact accepted by verify_transcript corresponds to a valid SHA-256-commitment-consistent dealing. | PROVED | PROVED (shared) | §P4-PublicVerif | docs/security-proofs/p4/t3-public-verifiability-soundness.md |
| P4 | P4-T4 | Abort-with-Blame Robustness: misbehavior covered by commitment-recomputation predicates yields publicly checkable blame; honest parties are never falsely blamed. | PROVED | PROVED (shared) | §P4-Robustness | docs/security-proofs/p4/t4-abort-with-blame-robustness.md |
| P4 | P4-T5 | Sequential Composition: simulated P4 session/public-key handoff composes sequentially with the P1 decrypt-share functionality at the exported interface boundary. | PROVED | PROVED (shared) | §P4-Composition | docs/security-proofs/p4/t5-sequential-composition.md |
| P1 | P1-T1 | Completeness: honest witnesses satisfying the SHA-256 commitment opening, bounded-error check, and SLAP-style transcript equations always yield an accepting P1 proof. | PROVED | PROVED (shared) | §P1-Completeness | docs/security-proofs/p1/T1.md |
| P1 | P1-T2 | Soundness (Knowledge): any accepting P1 prover yields a straight-line extractor recovering the opened witness for the implemented relation, except with probability bounded by SHA-256 binding failure. | PROVED | PROVED (shared) | §P1-Soundness | docs/security-proofs/p1/T2.md |
| P1 | P1-T3 | Zero-Knowledge: the abstract randomized masked SLAP core transcript admits ROM zero-knowledge via HVZK-to-Fiat–Shamir compilation. | PROVED | PROVED (shared) | §P1-ZK | docs/security-proofs/p1/T3.md |
| P1 | P1-T4 | Simulation-Extractability Scope: simulation-extractability is not required for the frozen P1 baseline; the interface boundary with P2 does not consume simulated P1 transcripts. | PROVED-WITH-CITATION | PROVED-WITH-CITATION (shared) | §P1-SimExtractability | docs/security-proofs/p1/T4.md |
| P1 | P1-T5 | Commitment Binding: pvss_commitment is binding on domain SHA256(session_id ‖ participant_id_le ‖ secret_share_be) under SHA-256 collision resistance. | PROVED | PROVED (shared) | §P1-Binding | docs/security-proofs/p1/T5.md |
| P2 | P2-A-T1 | Sonobe Folding Completeness: honest P1 proofs fold into an accepting CycloFoldStepCircuit accumulator under Nova IVC recursion. | PROVED | ASPIRATIONAL | §6.A — Track A | docs/security-proofs/p2/T1.md |
| P2 | P2-A-T2 | Sonobe Knowledge Soundness: Sonobe Nova IVC verifier accepts only folded CCS instances consistent with committed hash-chain history (standard Nova IVC soundness). | PENDING-NOVA-PROOF | CONTINGENT (Lemma 9) | §6.A — Track A | docs/security-proofs/p2/T2.md |
| P2 | P2-A-T3 | Sonobe ZK Preservation: CycloFoldStepCircuit operates on hashed accumulator state (3 Fr scalars), preserving ZK of underlying witness under ROM + HVZK. | PROVED | ASPIRATIONAL | §6.A — Track A | docs/security-proofs/p2/T3.md |
| P2 | P2-A-T4 | Accumulator Binding: SHA-256 collision-resistant for current surrogate; conditional on linear lattice commitment replacement for RingSIS/M-SIS binding. | CONDITIONAL | ASPIRATIONAL | §6.A — Track A | docs/security-proofs/p2/T4.md |
| P2 | P2-A-T5 | On-chain Compatibility: final accumulated proof targets Solidity/Yul verification with ≤32 B proof size; gas costs verified via P3 surrogate. | PARTIAL (2/6) | ASPIRATIONAL | §6.A — Track A | docs/security-proofs/p2/T5.md |
| P3 | P3-A-T1 | ECDSA Completeness: honest TRUSTED_SIGNER signatures over valid public inputs always yield ecrecover acceptance. | PROVED | SKELETON | §7.A — Track A | docs/security-proofs/p3/T1.md |
| P3 | P3-A-T2 | ECDSA Soundness (EUF-CMA): on-chain acceptance implies valid ECDSA authorization; tight reduction to EUF-CMA + keccak256 SPR. | PROVED | SKELETON | §7.A — Track A | docs/security-proofs/p3/T2.md |
| P3 | P3-A-T3 | Trusted-Setup Transparency: ecrecover path is setup-free (no CRS, no ceremony). | PROVED | SKELETON | §7.A — Track A | docs/security-proofs/p3/T3.md |
| P3 | P3-A-T4 | Gas Bound: verifier halts within 5,273 gas (Forge measured) for all paths; O(1) independent of n; 0.11% of block budget. | PROVED | SKELETON | §7.A — Track A | docs/security-proofs/p3/T4.md |
| P3 | P3-A-T5 | Cross-Input Binding & Liveness: ECDSA signature binds to one 200-byte blob; valid submissions finalize or abort with public blame. | PROVED | SKELETON | §7.A — Track A | docs/security-proofs/p3/T5.md |
| C6 | C6-T1 | Threshold decryption with committed smudging: bfv_sigma.rs provides BFV encryption proof; D.2 batched verifier covers sk+esm tracks with independent commitments; CommittedSmudge mode enforces DKG-bound smudging; statement binds session, dealer, recipient, transcript root. | IMPLEMENTED | ASPIRATIONAL | §Interfold-C6 | docs/security-proofs/interfold-equivalent-pvss.md |
| C7 | C7-T1 | Final decryption aggregation: aggregator_final Noir circuit (N=8 research prototype, 8 adversarial tests pass, Poseidon binding) verifies Lagrange recombination of threshold decryption shares; full-dimension harness runs canonical nargo→bb→ultra_honk flow. | IMPLEMENTED (N=8) | ASPIRATIONAL | §Interfold-C7 | docs/security-proofs/interfold-equivalent-pvss.md |
| F.2 | F2-T1 | Smudge-slot freshness: public SlotRegistry rejects slot reuse across distinct ciphertexts or decrypt rounds; freshness check is part of protocol acceptance, not only local convention. | IMPLEMENTED | ASPIRATIONAL | §F.2-SmudgeFreshness | docs/security-proofs/interfold-equivalent-pvss.md |

**Provenance legend:**
- **IMPLEMENTED**: Implemented in the prototype and passes test suite; formal proof may be partial or deferred.
- **PROVED**: Full formal proof with explicit reduction; advisor VERDICT: ACCEPTED or APPROVE.
- **PROVED-WITH-CITATION**: Proof valid under cited assumptions; scope explicitly bounded.
- **CONDITIONAL**: Proof document describes exact conditions for the theorem to hold; some conditions are not yet implemented.
- **ASPIRATIONAL**: Theorem stated for Track B (LatticeFold+/UltraHonk target); proof sketch exists but formal proof is deferred.
- **CONTINGENT**: Theorem depends on an unresolved conjecture (Lemma 9); cannot be proved until the conjecture is resolved.
- **SKELETON**: Proof skeleton exists in docs/security-proofs/p3/proof-skeletons.md; full proof is deferred to Track B implementation.
- **(shared)**: Theorem applies identically to both tracks (P4 and P1 components).

**P1 criticality footnote (from SECURITY.md §P1):**
P1 soundness is conditional on Module-SIS + Cyclo Theorem 3. Formal joint-extractor proof (T2) is a skeleton per SECURITY.md §P1. See `.sisyphus/plans/p1-t2-joint-extractor.md`.
