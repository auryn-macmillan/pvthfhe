# Round 10 Adversarial Remediation — Batch A Learnings

## A.1: Cross-share RS parity check in encrypt.rs

- `verify_batched_share_computation` at `share_computation.rs:155` takes a single `&BatchedShareComputationStatement` argument, NOT individual ciphertexts/proofs/threshold/BFV params as the pseudo-code in the task implies.
- The task pseudo-code was aspirational — implemented the cross-share check as an inline RS parity verification using the actual `share_bytes` plaintext data from `EncryptedShares`.
- The check verifies that for each Fr chunk, all n shares form evaluations of the same degree-(t-1) polynomial, preventing the share-poisoning attack.
- Added `PvssError::ShareVerification(String)` variant for this error path.
- Added helpers: `verify_share_rs_consistency`, `interpolate_bn254`, `eval_bn254_poly_coeffs`.
- Required `ark_ff::AdditiveGroup` import for `Fr::ZERO`.

## A.2: Decrypt byte cross-validation

- Straightforward: compare `payload.share.bytes.0` (the raw DecryptShare bytes) with `opened.statement.decrypted_share_bytes` from the NIZK proof.
- `payload.share` is `DecryptShare` (from `pvthfhe_fhe::types`), which has `bytes: ProtocolBytes` where `ProtocolBytes(pub Vec<u8>)`.
- Access via `.0` on the ProtocolBytes tuple struct.

## A.4: LegacyLocalSmudge → CommittedSmudge

- `partial_decrypt` receives a `DecryptionWitness` from the backend, NOT `DecryptNizkWitness`.
- `DecryptionWitness` has `esm_committed: bool` and `esm_noise_poly_bytes: Vec<u8>`, but NOT `sk_agg_share` or `esm_agg_share`.
- Used `witness.esm_committed` to decide between CommittedSmudge and LegacyLocalSmudge fallback.
- For `sk_agg_share`: used `expected_sk_agg_share` from `derive_party_binding(party_pk_bytes)`.
- For `esm_agg_share`: derived from SHA256 of `decryption_noise_bytes`.
- Required `ark-bn254` as a regular dependency in `pvthfhe-aggregator` (was dev-only).
- Required new imports: `compute_sk_aggregate_commitment`, `compute_esm_aggregate_commitment`, `compute_decrypt_ciphertext_hash`.

## A.3: Simulator stub documentation

- Expanded the NIZK stub comment in `generate_r1_msg` to document what a real NIZK would need to prove (3 properties: pk validity, commitment binding, encrypted shares correctness).
- Added round10-adversarial-remediation F3 reference.

## Build verification

- Full workspace builds successfully.
- All pvss and aggregator lib tests pass.
- Pre-existing: `decrypt_real.rs` integration test fails due to missing `session_id` argument — not caused by these changes.
