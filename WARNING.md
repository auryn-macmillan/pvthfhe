DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY

- On-chain verification: UltraHonk verifier (norm-enforced production path with transparent IVC, on-chain IVC binding via `ivc_verify_result`)
- Noir circuits: real aggregation and wrapping logic; C0 keygen NIZK uses real BFV sigma proofs; C7 decryption aggregation implemented via Nova C7DecryptAggregationCircuit with in-circuit Poseidon Merkle folding
- Do not use for The Interfold or any production deployment
- KZG trusted setup: uses nova-snark test-utils SRS (`default_ck_hint()`, generated at runtime). Production requires a real MPC ceremony SRS via `PublicParams::setup_with_ptau_dir()` (e.g., Aztec Ignition SRS, already used by UltraHonk).
- Surrogate compressor only available via `--features surrogate-compressor` (not in defaults). Must set `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` to use.
- No active surrogates on the default path — all paths use real cryptographic proofs (nova-snark IVC + Poseidon R1CS + real sigma/BFV NIZK). All surrogate code is feature-gated behind `surrogate-compressor` (requires explicit opt-in) or `legacy-nova` (reference only).

See [SECURITY-ADVISORY-001.md](SECURITY-ADVISORY-001.md) and [SECURITY.md](SECURITY.md) for details.
