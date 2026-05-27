## T8: prove_steps_share_verify - completed 2026-05-19

- ExternalInputs4 `prove_steps` already existed in the `NovaCompressor<CycloFoldStepCircuit<Fr>>` impl block (line 1514).
- `prove_steps_share_verify` is a thin wrapper that converts `ShareVerificationWitness` → `ExternalInputs4`, sets/clears thread-local `SHARE_COEFFS_DATA`, and delegates.
- `ShareVerificationWitness` fields: `coeffs: Vec<Fr>`, `sig_r_x: Fr`, `sig_s: Fr`, `pk_x: Fr`.
- ExternalInputs4 mapping: `(sig_r_x, sig_s, pk_x, Fr::from(1u64))`.
- `fr` field (index 3) uses constant 1 as a placeholder — the actual coefficient data comes via thread-local `SHARE_COEFFS_DATA`.
