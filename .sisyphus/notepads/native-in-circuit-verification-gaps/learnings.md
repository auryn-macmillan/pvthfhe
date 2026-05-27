## 2026-05-17 — P1 native-vs-circuit gap pass
- aggregator_final already had G4/G6 slots in the current working tree; the Rust Prover.toml generator was still missing decrypt_nizk_hash and used SHA-256-style values that could exceed BN254 field modulus.
- nargo execute --package aggregator_final --prover-name <name> looks for circuits/aggregator_final/<name>.toml, so C7Prover generation must write C7Prover.toml rather than Prover.toml.
- bb prove --verifier_target evm-no-zk implies the verifier target/oracle hash; passing --oracle_hash at the same time is rejected.
- bb verify for evm-no-zk proofs must also use --verifier_target evm-no-zk; plain --oracle_hash keccak expects the ZK proof size.
- Solidity verifier generation must pass -t evm-no-zk for evm-no-zk proofs, otherwise HonkVerifier expects the larger ZK proof length.
- ciphertext_hash is bound through the challenge chain: ciphertext_hash -> r derivation -> eval_poly(participant_shares[i], r) -> recombination and d_commitment-bound share hashes.
## 2026-05-18 — Scalar sigma protocol pass
- sigma.rs now exposes verify_scalar as the canonical v2 verifier; verify delegates to it for current callers.
- Scalar challenge derivation uses Poseidon over BN254 after SHA-256 compression of large RNS fields, then maps Fr exactly by comparing against Fr::MODULUS/2.
- Adapter proof version is now 0x0002 and encodes sigma ch as a canonical 32-byte sign-extended ternary scalar; old v1 proofs are intentionally incompatible.
- PVSS share algebraic verification now delegates to sigma::verify_scalar instead of reconstructing the removed binary-polynomial challenge path.
## 2026-05-18 — G7 compressor sigma in-circuit pass
- CycloFoldStepCircuit is now state_len=5; state[4] is sigma_verification_count and verifier rejects unless fold_count == ring_verification_count == sigma_verification_count.
- Nova preprocessing and proving must see the same sigma witness allocation shape. c_ntt was allocated as a witness rather than a constant to keep setup independent of per-run NIZK values while still constraining the algebraic equation.
- In-circuit sigma uses NTT-domain limbs from pvthfhe_nizk::sigma::compute_sigma_ntt_data and adds quotient witnesses so the RNS equation is enforced modulo each q_i inside BN254.
- Full pipeline Track B extracts c_rns/d_rns/SigmaProof from NIZK proof bytes, converts to compressor SigmaWitness values, and populates set_sigma_data before NovaCompressor::new/prove.

## G-LAGRANGE and G-PLAINTEXT Closure (2026-05-18)

### Changes Made
1. **Replaced `lagrange_coeffs` with `committee_party_ids`**: Party IDs are now a public input. Lagrange coefficients are computed in-circuit using the formula `λ_i = Π_{j≠i} party_ids[j] / Π_{j≠i} (party_ids[i] - party_ids[j])`.

2. **In-circuit plaintext reconstruction**: Plaintext is now computed as `plaintext[j] = Σ λ_i · participant_shares[i][j]` for each coefficient j. This eliminates the prover's ability to fabricate plaintext.

3. **Removed old inputs**: `lagrange_coeffs`, `plaintext`, `plaintext_hash`, `z_q` are no longer circuit inputs.

4. **Removed Lagrange recombination check**: The challenge point `r`, `eval_poly` calls, `r_pow_n`, and `z_q` check are all removed since plaintext is now computed directly.

5. **New party ID validation**: Added `assert(party_id != 0)` for all active party IDs. Zero party IDs would cause one party to get all Lagrange weight (λ=1) and others get 0, defeating threshold security. The Lagrange sum check alone doesn't catch this.

6. **ciphertext_hash handling**: Kept as a public input, constrained via `assert(ciphertext_hash != plaintext_hash)` where plaintext_hash is Now computed in-circuit from the reconstructed plaintext.

### Key Decisions
- **Return values from main**: Noir 1.0.0-beta.21 supports `fn main(...) -> pub [Field; N]` which makes the computed plaintext a public output accessible to the verifier.
- **BB version differences**: `bb prove --verifier_target evm-no-zk` CANNOT be combined with `--oracle_hash keccak` in BB 5.0.0-nightly.20260517. The `--verifier_target` flag sets oracle_hash automatically to keccak.
- **VK generation**: `bb write_vk` needs `--verifier_target evm-no-zk` to match `bb prove --verifier_target evm-no-zk`. Without it, the VK size mismatch (3680 vs 1888) causes prove to fail.

### Verification Results
- `nargo test --package aggregator_final`: 9/9 tests pass
- `nargo execute --package aggregator_final --prover-name Prover_re`: succeeds, outputs plaintext [3, 0, ...]
- `bb write_vk --scheme ultra_honk --oracle_hash keccak` + `bb prove --verifier_target evm-no-zk`: succeeds
- `bb write_solidity_verifier --scheme ultra_honk --verifier_target evm-no-zk`: succeeds
- `forge test --root contracts --match-test test_real_proof_accepts`: PASSES
- Proof size: 7,776 bytes (was 16 for old dummy circuit)

### Test Changes
- `test_honest_lagrange_recombination`: Now uses `committee_party_ids = [1,2,3,...]` and checks returned plaintext
- `test_tamper_zero_party_id`: Tests that zero party IDs are rejected (new validation)
- `test_tamper_duplicate_party_ids`: Tests duplicate IDs cause division-by-zero failure
- `test_ciphertext_equals_plaintext_hash`: Tests that ciphertext_hash != plaintext_hash
- `test_tamper_wrong_threshold`: Tests threshold > n_participants
- `test_tamper_epoch_zero`: Tests epoch zero rejection
- `test_tamper_d_commitment_mismatch`: Unchanged core logic
- `test_collision_*`: Unchanged
