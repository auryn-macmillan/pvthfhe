DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY

- on-chain verification: UltraHonk verifier (Track A: Sonobe attestation; Track B: MicroNova target)
- Noir circuits: real aggregation and wrapping logic
- do not use for The Interfold or any production deployment
- KZG trusted setup SRS (`bench/srs/bn254.srs`) is a text-only stub (52 bytes "DO NOT USE")
  — generated at runtime via `KZG::<Bn254>::setup()` for the research prototype only

See SECURITY-ADVISORY-001.md and SECURITY.md for details.
