# Learnings: BFV Encryption Sigma Gap Closure

## Architecture
- BFV encryption verification is added to CycloFoldStepCircuit (state_len 7→8)
- State[7] tracks bfv_encryption_verification_count
- Thread-local `BFV_ENCRYPTION_DATA` holds per-step witness data (flat Vec<Fr> format, 28 elements)
- S-Z batch across L=3 CRT moduli verifies relation Σ γ^l * (ct0[l] - pk0[l]*u - e0 - Δ[l]*m - q[l]*quot0[l]) == 0

## Nova Constraint Structure Constraint
- Nova requires identical constraint structure between preprocessing and proving
- BFV data must be set BEFORE NovaCompressor::new() for consistent constraint count
- When no data, `bfv_encryption_verify_step` returns `FpVar::one()` (Track A compatible, no constraints)

## Adversarial Verification
- Nova's prove_step does NOT fail on unsatisfiable constraints — it folds them silently
- Unsatisfiable constraints are detected at verification time via Nova::verify
- Tests confirm: tampered pk0, ct0, and norm-bound violations all detected by verify
