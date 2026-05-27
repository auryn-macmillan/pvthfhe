# Cryptographer Prompt Re-Audit — Post-Nova-Migration

**Status**: PLAN
**Date**: 2026-05-27

## Background

Original 4 cryptographer prompts were addressed before the Sonobe→Nova migration. This audit checks whether all fixes survived the migration.

### What SURVIVED ✅

| Concern | Original Prompt | Survived? | Evidence |
|---------|----------------|-----------|----------|
| C2: P(0) binding | DealerParityStepCircuit binds constant term | ✅ | `dealer_parity_circuit.rs:139` — `p0_var.enforce_equal(&external_inputs.1)` |
| C2: Real DKG shares | Replace synthetic `Fr::from(dealer*1000)` | ✅ | F4 audit fix — real transcript data |
| C0: BFV keypair NIZK | Replace `nizk: vec![0x00, 0x01]` | ✅ | `simulator.rs:572` calls `sigma::prove()` with real poly_commit |
| S-Z sigma | 3-point S-Z, poly_eval_mod, compute_sz_gamma | ✅ | `sigma.rs:775-938` — full implementation |
| Groth16 removal | Transparent IVC, no ceremony | ✅ | Nova-snark backend, ivc_snark_proof_hash |
| Lagrange in Nova | LagrangeFoldStepCircuit | ✅ | Ported to nova-snark StepCircuit |
| Noir C7 simplified | Remove in-circuit Lagrange | ✅ | 108 lines, `nova_final_plaintext` input |
| d_commitment | Real Poseidon over ciphertext | ✅ | `full_pipeline.rs:1631` |
| poly_commit | SHA-256 over secret_key_bytes | ✅ | `simulator.rs:453` |
| PK agg sigma | sigma_verify_step in sponge | ✅ | `pk_aggregation_circuit.rs` wired |
| Quotient range check | norm_range_check on r1_eval | ✅ | `nova/mod.rs` in sigma_verify_step |
| G1Affine on-curve | `is_on_curve()` check | ✅ | `schnorr.rs` |
| Rogue-key | commit-before-reveal nonce | ✅ | `simulator.rs` commitment_nonce |
| Sigma F-S d_commitment | poly_commit threaded through prove/verify | ✅ | `simulator.rs:572` |

### What NEEDS REMEDIATION

#### GAP 1 — C6: decrypt_nizk_hash is `!= 0` not bound to sigma fold hash

**Original prompt**: "change the decrypt_nizk_hash check from `!= 0` to `decrypt_nizk_hash == computed_sigma_fold_hash`"

**Current state** (`circuits/aggregator_final/src/main.nr:46`):
```noir
assert(decrypt_nizk_hash != 0, "decrypt_nizk_hash must be non-zero");
```

**Required**: Bind `decrypt_nizk_hash` to the share verification fold hash, which is the output of `ShareVerificationStepCircuit` folded through Nova. The sigma verification fold produces a Poseidon hash of the final state. This hash should be passed as a public input to the Noir circuit.

**Fix steps**:
1. After the share verification fold in `full_pipeline.rs`, extract the final Poseidon state hash from the Nova accumulator (`z_i[1]` — the share_chain_hash field)
2. Pass this hash as `decrypt_nizk_hash` to the Noir circuit (currently it's a SHA-256 of the NIZK proof bytes, which is wrong — it should be the sigma fold hash)
3. Change the Noir check to `decrypt_nizk_hash == expected_sigma_fold_hash` where `expected_sigma_fold_hash` is computed from the share coefficients already in the circuit

**Effort**: ~2 hours

#### GAP 2 — Missing test files

- `crates/pvthfhe-pvss/tests/share_computation_commitment_binding.rs` — requested by C2 prompt
- `crates/pvthfhe-pvss/tests/nizk_keygen.rs` — requested by C0 prompt

Both are low priority — the cryptographic fixes are in place, only the dedicated regression tests are missing.

**Effort**: ~1 hour

### Recommendation

GAP 1 is the only cryptographically significant remaining issue. GAP 2 is test coverage. The memo recommends fixing GAP 1 first.
