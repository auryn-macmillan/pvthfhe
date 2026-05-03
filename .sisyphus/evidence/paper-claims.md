# Paper Claim Fidelity Classification (T13)

Input: `paper-claims.md` (33 claims) × `audit-matrix.md` (P1–P4 verdicts).

## Classification legend

- `supported`: claim matches code + proof + test reality
- `overstated`: claim exaggerates beyond what evidence supports
- `contradicted`: code or proof actively contradicts the claim
- `untestable`: claim is about external systems / future work / hypothetical instantiations

---

## Claim-by-claim classification

| # | Source | Claim (abbreviated) | Classification | Evidence |
|---|---|---|---|---|
| 1 | paper/main.tex:23-24 | `O(n) per-party work and O(polylog n) verifier cost` | **overstated** | P2 uses SHA-256 hash-chain surrogate (not O(polylog n) lattice folding). P3 is ECDSA check (not O(1) verifier). Actual asymptotic performance not demonstrated on any real construction. `p2-reachability.md`, `audit-matrix.md` §P2 |
| 2 | paper/main.tex:27 | `We prove correctness, soundness, and zero-knowledge for all` | **overstated** | P1 soundness is admitted open problem (README:15). P3-T1 proof proves ECDSA completeness, not FHE soundness. P2-T4 is conditional/GAP. `theorem-inventory.md`, `audit-matrix.md` |
| 3 | paper/main.tex:35 | `each computation step becomes auditable by any observer` | **overstated** | P3 is a trusted-signer check; third parties cannot audit correctness, only that a trusted party signed. `audit-p3-vacuity/SUMMARY.md` |
| 4 | paper/main.tex:38-39 | `O(n) per-party work … O(polylog n) on-chain verification cost, making it practical for blockchain deployment` | **overstated** | Same as #1. Additionally, P2 is never enabled in production builds. `p2-reachability.md` |
| 5 | paper/main.tex:45 | `Our P3 on-chain verifier builds on EVM proof verification techniques` | **contradicted** | P3 uses `ecrecover` only — ECDSA authentication, not a proof verification technique. `contracts/src/P3RealVerifier.sol:63`, `audit-p3-vacuity/SUMMARY.md` |
| 6 | paper/main.tex:57 | `The P4 sub-protocol implements a publicly-verifiable secret sharing (PVSS) distributed key` | **overstated** | PVSS is implemented for Shamir sharing over GF(2^61-1) but the FHE public key produced is a stub placeholder, not a real Ring-LWE key. `audit-matrix.md` §P4 |
| 7 | paper/main.tex:59 | `the dealer's commitment is verified via SHA-256` | **supported** | `hermine.rs` uses SHA-256 commitments and verify_transcript recomputes them. `docs/security-proofs/p4/t3-public-verifiability-soundness.md` |
| 8 | paper/main.tex:83 | `Any artifact accepted by verify_transcript … corresponds to a valid dealing` | **supported** | P4-T3 is PROVED-WITH-CITATION for the SHA-256 commitment model. `theorem-inventory.md` P4-T3 row |
| 9 | paper/main.tex:87 | `Follows from SHA-256 collision resistance` | **supported** | Honest acknowledgement of reduction target. |
| 10 | paper/main.tex:116-117 | `Any accepting P1 prover yields a straight-line extractor … except with SHA-256 binding failure` | **overstated** | Theorem is proved for the abstract SLAP-core transcript, but the actual `FhersBackend` is a MOCK that never runs the NIZK. The claim applies to a construction that is not deployed. `p1-reachability.md`, `audit-matrix.md` §P1 |
| 11 | paper/main.tex:129 | `pvss_commitment is binding on domain SHA256(…)` | **supported** | P1-T5 PROVED-WITH-CITATION. `docs/security-proofs/p1/T5.md` |
| 12 | paper/main.tex:137 | `on-chain verification cost from O(n) to O(polylog n)` | **overstated** | P2 hash-chain is not O(polylog n). P3 is ECDSA. `p2-reachability.md`, `audit-matrix.md` §P2/P3 |
| 13 | paper/main.tex:141 | `Honest P1 proofs fold into an accepting accumulator under the frozen verifier equation` | **overstated** | Proved for hash-chain surrogate, not a real LatticeFold+ accumulator. `theorem-inventory.md` P2-T1, `docs/security-proofs/p2/T4.md` |
| 14 | paper/main.tex:147 | `SHA-256 binding failure probability` | **supported** | Honest acknowledgement of reduction. |
| 15 | paper/main.tex:158 | `The accumulator commitment is binding under RingSIS/M-SIS at the frozen P2 parameters` | **contradicted** | Current accumulator is SHA-256 hash-chain, not a Ring-SIS commitment. P2-T4 Part B is explicitly conditional on obligations NOT MET. `docs/security-proofs/p2/T4.md` §Security obligation summary |
| 16 | paper/main.tex:163 | `The final accumulated proof targets Solidity/Yul verification within bounded gas and proof size` | **overstated** | Claim uses "targets" — technically honest, but implies proximity to delivery. Real proof is a SHA-256 hash chain. `p2-reachability.md` |
| 17 | paper/main.tex:170 | `The P3 on-chain verifier is a Solidity contract that accepts the accumulated P2 proof` | **contradicted** | P3 does not inspect P2 accumulator at all. `ecrecover` only. `contracts/src/P3RealVerifier.sol:63`, `audit-p3-vacuity/` |
| 18 | paper/main.tex:174 | `Any on-chain acceptance of the P3 verifier implies acceptance of the exact frozen P2 terminal accumulator statement` | **contradicted** | Directly contradicted by `P3VacuityProof.t.sol`: attacker-chosen content is accepted with valid ECDSA sig. `audit-p3-vacuity/forge-output.log` |
| 19 | paper/main.tex:180 | `Any recursive or compressed wrap used by P3 preserves soundness of the wrapped P2 terminal relation` | **untestable** | P3 uses no recursive or compressed wrap; this claim describes a hypothetical design not implemented. |
| 20 | paper/main.tex:186-187 | `Trusted-setup assumptions are explicit: setup compromise breaks P3 soundness if a setup-based verifier path is chosen, and is N/A otherwise` | **overstated** | P3 has no setup-based verifier path — it is purely ECDSA. "N/A otherwise" is the relevant branch, but the framing implies a choice exists that does not. |
| 21 | paper/main.tex:192 | `The deployed on-chain verifier halts within ≤5,000,000 gas` | **supported** | Gas benchmark confirmed for `ecrecover`-based path. `task-39-gas.log`. |
| 22 | paper/main.tex:244-245 | `The main open question is the tightness of the P1 soundness reduction` | **supported** | Honest self-disclosure of gap. |
| 23 | paper/main.tex:251-252 | `a complete four-layer construction … All sub-protocols [proved]` | **overstated** | P1 MOCK, P2 STUB/dead, P3 ECDSA-only. "Complete" and "all proved" is not consistent with the audit evidence. |
| 24 | README.md:7 | `O(n) per-party work and O(polylog n) verifier cost` | **overstated** | Same as #1. `p2-reachability.md`, `audit-matrix.md` |
| 25 | README.md:15 | `Open Problem P1: Lattice NIZK well-formedness soundness is not formally proven` | **supported** | Accurate self-disclosure consistent with audit findings. |
| 26 | ARCHITECTURE.md:13 | `A Solidity verifier checks the final proof, ensuring the decryption result is correct` | **contradicted** | Verifier checks ECDSA signature, not the decryption result. `P3RealVerifier.sol:63` |
| 27 | ARCHITECTURE.md:59 | `IND-CPA-PV: Ciphertext indistinguishability under chosen-plaintext attack with public verifiability` | **untestable** | Security property of target design; not demonstrated by current surrogate implementation. |
| 28 | ARCHITECTURE.md:60 | `Decryption-Soundness: No adversary can force an incorrect decryption result to be accepted by the verifier` | **contradicted** | Directly contradicted by P3 vacuity: any incorrect result signed by the trusted key is accepted. `audit-p3-vacuity/` |
| 29 | ARCHITECTURE.md:61 | `Public-Verifiability: Any third party can verify the correctness of the protocol execution` | **contradicted** | Third parties can verify ECDSA signatures only, not FHE computation correctness. `audit-p3-vacuity/SUMMARY.md` |
| 30 | ARCHITECTURE.md:67 | `P1: Lattice NIZK well-formedness soundness` (open problem) | **supported** | Accurate self-disclosure. |
| 31 | paper/claims-table.md:17 | `On-chain Soundness: any on-chain acceptance … implies acceptance of the exact frozen P2 terminal accumulator statement` | **contradicted** | Same as #18. `P3VacuityProof.t.sol`, `audit-p3-vacuity/forge-output.log` |
| 32 | paper/claims-table.md:19 | `Trusted-Setup Explicitness: trusted-setup assumptions are explicit` | **overstated** | No setup-based path exists; framing implies a design choice that isn't present. |
| 33 | paper/claims-table.md:20 | `Gas Bound: … halts within ≤5,000,000 gas` | **supported** | Gas measurement confirmed. |

---

## Summary

| Classification | Count | Notes |
|---|---|---|
| **supported** | 9 | Rows 7, 8, 9, 11, 14, 21, 22, 25, 30, 33 — mostly P4 Shamir proofs, gas bound, self-disclosures |
| **overstated** | 11 | Rows 1, 2, 3, 4, 6, 10, 12, 13, 16, 20, 23, 24, 32 — asymptotic claims, "complete", "all proved" |
| **contradicted** | 9 | Rows 5, 15, 17, 18, 26, 28, 29, 31 — P3 soundness claims, ARCHITECTURE "decryption correct", RingSIS binding |
| **untestable** | 2 | Rows 19, 27 — hypothetical/future design claims |

> **Key finding**: P3 soundness claims (#18, #31, #28) are machine-contradicted by `P3VacuityProof.t.sol`. The accumulator-binding claim (#15) is self-contradicted by the proof document. Eleven performance/completeness claims are overstated against surrogate implementations.
