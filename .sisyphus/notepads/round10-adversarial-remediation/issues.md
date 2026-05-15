# Issues Encountered

## Task pseudo-code doesn't match actual function signatures

The task description contains pseudo-code that doesn't match the actual codebase:
- `verify_batched_share_computation` at share_computation.rs:155 takes `&BatchedShareComputationStatement`, not `(&[Vec<u8>], &[Vec<u8>], usize, &Params)`.
- `PvssError::ShareVerification` didn't exist — had to create it.
- `DecryptNizkMode::CommittedSmudge(CommittedSmudgeParams { ... })` syntax doesn't exist — it's a named-field variant: `CommittedSmudge { slot_id, decrypt_round, ... }`.
- `ctx.bfv_params` doesn't exist on `PvssContext`.
- `shares.nizk_proofs` should be `shares.proofs`.
- `DecryptionWitness` doesn't have `sk_agg_share`/`esm_agg_share` fields.

## EncryptedShares.share_bytes vs verify_batched_share_computation

The `verify_batched_share_computation` function requires both `sk` and `esm` tracks. The PVSS `EncryptedShares` only has plaintext share bytes for Shamir shares, not separate sk/esm tracks. The cross-share check was implemented as inline RS parity verification rather than calling the batched function.

## ark-bn254 dependency

`pvthfhe-aggregator` had `ark-bn254` only as a dev-dependency. Moving it to regular dependencies was needed for the commitment computation in A.4.

## Pre-existing test failure

`crates/pvthfhe-aggregator/tests/decrypt_real.rs` calls `aggregate_decrypt` with 8 arguments when the function takes 9 (missing `session_id: &str`). This is pre-existing and not caused by these changes.
