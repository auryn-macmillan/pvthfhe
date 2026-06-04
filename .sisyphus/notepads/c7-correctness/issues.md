# Issues: C7 Correctness Plan

## 2026-06-04 — Plan creation

No blocking issues. The plan is ready for execution.

### Known concerns (non-blocking)

1. **Prover.toml size**: With MAX_SHARES=128, the Prover.toml will contain two arrays of 128 field elements each plus one scalar. The file will be ~100KB. This is manageable but worth noting for CI performance.

2. **Schwartz-Zippel challenge point derivation**: The challenge point `r` must be derived from Fiat-Shamir on the transcript in a way that is verifiable both natively and in-circuit. The current `derive_challenge_point_r` function uses `hash_all_coeffs` which requires all share coefficient residues. The in-circuit derivation would need a different commitment (e.g., Poseidon over share evaluations). This is a design detail for T.1.

3. **R3 per-share relation**: The C7 circuit verifies that the Lagrange-recombined shares match the plaintext. It does NOT verify that each individual share satisfies the R3 relation (`d_i = c1 · sk_i + e_i + noise`). That's a separate trust gap (covered by the `decrypt_share` circuit, but that circuit currently operates on N=8 ring dimension, not N=8192). Full end-to-end correctness requires both per-share correctness AND Lagrange recombination correctness. This plan covers only the latter.

4. **HonkVerifier.sol regeneration**: After the circuit changes, the verification key (VK) changes. The Solidity verifier must be regenerated. This is a deployment concern, not a C7 design concern.
