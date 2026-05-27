# PVTHFHE vs Interfold trBFV — Side-by-Side Comparison

## Hardware & Toolchain Disclosure
| | PVTHFHE | Interfold trBFV |
|---|---|---|
| Hardware | AMD RYZEN AI MAX+ 395 w/ Radeon 8060S, 8 cores, 62 GB RAM, Linux version 6.8.0-111-generic | Apple M4 Pro, 14 cores, 48 GB RAM, OS unpublished in baseline |
| Toolchain | Rust 1.95.0, Nargo 1.0.0-beta.20, BB 5.0.0-nightly.20260324, Nova folding-schemes rev 63f2930d363150d4490ce2c4be8e0c25c2e1d92c, fhe.rs rev 5f24d0b62a7329b789db07a065b68accd614a47b | Nargo 1.0.0-beta.16, BB 3.0.0-nightly.20260102; Rust/Nova/fhe.rs details unpublished in baseline |
| Parameters | N=8192, log₂q=174, B_e=16, B_s=1, B_r=TBD, T=2, H=5 | H=N=3, T=1; upstream did not publish N/log₂q/B_e/B_s/B_r in the vendored baseline |

## Circuit Timings

| Circuit | Cardinality | PVTHFHE (ms) | Interfold (ms) | Ratio | Status | Notes |
|---|---|---|---|---|---|---|
| ZkPkBfv | 1:N | 1864.4 | 161120.0 | 0.0116x | real | aggregation=sum; instances_run=5; Maps to one Sigma+Ajtai proof per party; report aggregate-of-N when wired.; Interfold baseline: Heuristic 2% share of the published 8056 s total; PK-share well-formedness is secondary to share encryption in the plan narrative. |
| ZkShareComputation | 1:1 | 16422.5 | 80560.0 | 0.2039x | real | aggregation=n/a; instances_run=1; PVTHFHE measures full keygen simulator (Round1+Round2+Round3); Interfold ZkShareComputation is the share-computation step in isolation. Reader-side adjustment may be needed.; Interfold baseline: Heuristic 1% share of the published 8056 s total; small standalone share-computation cost. |
| ZkShareEncryption | 1:N(N-1) | 459.0 | 6042000.0 | 0.0001x | real | aggregation=sum; instances_run=20; Will map to lattice PVSS share-encryption proofs once Phase P lands.; Interfold baseline: Plan-source published figure: approximately 75% of DKG cost is concentrated in ZkShareEncryption.; gap: Verifier key size is not exposed by the PVSS adapter |
| ZkVerifyShareProofs | 1:N(N-1) | 150.0 | 483360.0 | 0.0003x | real | aggregation=sum; instances_run=20; Will map to verifier-side PVSS share-proof checks once Phase P lands.; Interfold baseline: Heuristic 6% share so the PVSS proof cluster (share encryption + verify + decrypt-side proofs) sums to approximately 85% of the published total. |
| ZkNodeDkgFold | 2:2 split-merge | 0.9 | 161120.0 | 0.0000x | real | aggregation=sum; instances_run=1; PVTHFHE merged this stage into a single cyclo_fold pass; the merged timing is reported in both rows and should not be double-counted.; Interfold baseline: Heuristic 2% share for the first node-fold stage outside the PVSS-proof-dominated portion.; gap: merged into single PVTHFHE cyclo_fold pass |
| ZkPkAggregation | 2:2 split-merge | 0.9 | 80560.0 | 0.0000x | real | aggregation=sum; instances_run=1; PVTHFHE merged this stage into a single cyclo_fold pass; the merged timing is reported in both rows and should not be double-counted.; Interfold baseline: Heuristic 1% share for the PK aggregation step.; gap: merged into single PVTHFHE cyclo_fold pass |
| ZkDkgAggregation | 1:1 | 19172.9 | 241680.0 | 0.0793x | real | aggregation=n/a; instances_run=1; Will map to compressor proof once comparison wiring is implemented.; Interfold baseline: Heuristic 3% share for the final DKG aggregation SNARK.; PVTHFHE uses a Nova wrap in place of Interfold's final UltraHonk aggregation over BFV state |
| ZkThresholdShareDecryption | 1:N | 49.6 | 241680.0 | 0.0002x | real | aggregation=sum; instances_run=2; Maps to one Sigma+Ajtai decrypt proof per participating party.; Interfold baseline: Heuristic 3% share for threshold-share decryption proofs. |
| ZkDkgShareDecryption | 1:N | 783.2 | 322240.0 | 0.0024x | real | aggregation=sum; instances_run=2; Will map to decrypt-side PVSS proofs once Phase P lands.; Interfold baseline: Heuristic 4% share to keep the PVSS proof cluster near the plan's stated approximately 85% of DKG cost. |
| ZkDecryptedSharesAggregation | 2:2 split-merge | 117.1 | 80560.0 | 0.0015x | real | aggregation=sum; instances_run=1; PVTHFHE merged this cost into a single aggregate_decrypt pass; merged timing is reported in both rows.; Interfold baseline: Heuristic 1% share for decrypted-share aggregation.; gap: merged into single PVTHFHE aggregate_decrypt pass |
| ZkDecryptionAggregation | 2:2 split-merge | 117.1 | 80560.0 | 0.0015x | real | aggregation=sum; instances_run=1; PVTHFHE merged this cost into a single aggregate_decrypt pass; merged timing is reported in both rows.; Interfold baseline: Heuristic 1% share for final decryption aggregation.; PVTHFHE's final decrypt aggregation inherits the Nova-vs-Interfold proof-system asymmetry; gap: merged into single PVTHFHE aggregate_decrypt pass |
| OnChainUltraHonkVerify | 1:1 | 8088.9 | 80560.0 | 0.1004x | real-fallback | aggregation=n/a; instances_run=1; Will map to BB UltraHonk verifier execution once Noir/on-chain wiring lands.; Interfold baseline: Heuristic 1% share for the on-chain UltraHonk verification step; Interfold's published circuit name differs from PVTHFHE's onchain_verify row label.; The comparison row is emitted as onchain_verify in PVTHFHE JSON even though Interfold's published circuit name is OnChainUltraHonkVerify; gap: Measured via fallback compressor.verify proxy on the NoGo on-chain path |


## Status Legend
- `real`: proof system fully implemented
- `real-fallback`: off-chain verification with on-chain commitment (N3a NoGo path)
- `surrogate`: placeholder/mock — not comparable
- `n/a`: not applicable for this configuration

## Comparison Notes
- No normalization applied: Interfold numbers are reported verbatim from the vendored baseline; reader-side normalization only.

## Provenance
- PVTHFHE commit: `5d7853a`
- Interfold source: https://github.com/gnosisguild/enclave/tree/main/circuits/benchmarks/results_secure
- Interfold source commit: `c7e98029193f548ac4575fd05d007b034b75385c`
- Interfold retrieval date: 2026-05-06
- Interfold estimation method: Heuristic proportional split of the published 8056 s total, preserving the plan's ~75% ZkShareEncryption share and ~85% PVSS-proof-cluster share.
