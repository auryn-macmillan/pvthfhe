DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY

- on-chain verification: UltraHonk verifier (Track A: deprecated hash-then-fold; Track B: norm-enforced production path; MicroNova heterogeneous IVC option available via PVTHFHE_COMPRESSOR=micronova)
- Noir circuits: real aggregation and wrapping logic; C0 keygen NIZK uses real BFV sigma proofs; C7 decryption aggregation is implemented via Nova C7DecryptAggregationCircuit and Merkle-tree folding
- do not use for The Interfold or any production deployment
- KZG trusted setup SRS (`bench/srs/bn254.srs`) is a text-only stub (52 bytes "DO NOT USE")
  — generated at runtime via `KZG::<Bn254>::setup()` for the research prototype only

See SECURITY-ADVISORY-001.md and SECURITY.md for details.
