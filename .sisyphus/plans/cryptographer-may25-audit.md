# Cryptographer Remediation — May 2025 Audit

**Status**: PLAN
**Date**: 2025-05-30
**Branch**: main

## Audit Summary

32 findings across 6 layers. Priority clustered by the cryptographer:

| Priority | Cluster | Issues | Theme |
|----------|---------|--------|-------|
| **P0** | 1–4, 13–15 | 8 issues | BFV/Greco witness bounds + plaintext binding + decrypt relation |
| **P1** | 7, 9–12, 24–27 | 7 issues | Cyclo/Ajtai/sigma rounds + batched shares + on-chain binding |
| **P2** | 16–23, 29–31 | 10 issues | Fold + Nova encoding + composition |

## P0 — BFV/Greco + Witness Bounds + Decrypt (8 issues)

### P0.1 — No Greco on the enforced path
**Issue**: `bfv_greco.rs` not in `pvthfhe-nizk` module tree. Quotient/SZ attestation not compiled or verified. Share proofs are v4 + bfv_sigma only.
**Fix**: Port `bfv_greco.rs` from `feat/greco-e3-compute-provider` to main. Register in module tree. Wire into `bfv_sigma::verify`.
**Effort**: ~30 min (merge from feature branch)

### P0.2 — BFV witness bounds not verified
**Issue**: `bfv_sigma::verify` checks response norms (z_u, z_e0, z_e1, z_m) and two RNS equations, NOT that witness (u, e0, e1, m) lies in the intended BFV distribution.
**Fix**: Add explicit witness bounds in `bfv_sigma::verify`: `|u| <= B_U`, `|e0| <= B_E`, `|e1| <= B_E`, `|m| <= t_plain/2`. The response bounds IMPLY witness bounds but only if the sigma protocol is sound. Add direct checks as defense-in-depth.
**Effort**: ~1 hr

### P0.3 — t_plain unused for plaintext bound
**Issue**: `BfvSigmaStatement.t_plain` carried in proof blob but verify doesn't enforce `|m_i| < t/2`.
**Fix**: Add explicit check in `bfv_sigma::verify`: for each m_i coefficient, verify `|m_i| < t_plain/2`.
**Effort**: ~30 min

### P0.4 — Sigma does not tie plaintext to PVSS share
**Issue**: Prover maps share bytes to m locally. Verifier doesn't prove m is encryption of committed share.
**Fix**: Add `share_commitment` field to `BfvSigmaStatement`. In verify, check `Poseidon(m) == share_commitment`.
**Effort**: ~1 hr

### P0.5 — Weak share-algebra leg (e_i = 0)
**Issue**: Inner share sigma proved with e_i = 0. Only binds d = c·s, not full RLWE relation.
**Fix**: Generate proper error witness for inner sigma. Use `compute_sigma_ntt_data` with real error polynomial.
**Effort**: ~2 hrs

### P0.6 — Empty BFV proof on some prove paths
**Issue**: If `encrypt_with_witness` unavailable, prover emits empty BFV blob.
**Fix**: Return error instead of empty blob. Make `encrypt_with_witness` required.
**Effort**: ~15 min

### P0.7 — Cross-share consistency not in core API
**Issue**: `verify_batched_share_computation` not called from `verify_shares`. Only optional pipeline-extra-checks.
**Fix**: Call `verify_batched_share_computation` from `verify_shares` unconditionally.
**Effort**: ~30 min

### P0.8 — Decrypt NIZK is fake
**Issue**: Does not prove `partial_decrypt(ct, sk) = decrypted_share_bytes`. `expected_sk_agg_share` used for hash binding only.
**Fix**: Redesign `DecryptNizkProver::prove` to prove the decryption relation in sigma protocol. Add ciphertext and secret key commitment to statement. Verify: `decrypt(sk, ct) == share_bytes` modulo BFV plaintext modulus.
**Effort**: ~4 hrs (substantial circuit change)

## P1 — Cyclo/Ajtai/Sigma + On-Chain Binding (7 issues)

### P1.1 — Ajtai commitment not verified
**Issue**: 26,624-byte commitment stored and hashed into sigma binding. No algebraic Ajtai check on verify.
**Fix**: Implement `verify_ajtai_commitment` in `cyclo_adapter.rs`. Check that commitment = A · s mod q.
**Effort**: ~3 hrs

### P1.2 — Single-round sigma (2/3 soundness)
**Issue**: `SIGMA_REPETITIONS = 1` in default path. verify_multi exists but not default.
**Fix**: Set default to 90 rounds. Update pipeline to use prove_multi/verify_multi.
**Effort**: ~1 hr (already implemented on feature branch, merge)

### P1.3 — ciphertext_bytes / decrypt_share_bytes not in relation
**Issue**: Required non-empty in validate_statement but not used in verify equations.
**Fix**: Hash `ciphertext_bytes` / `decrypt_share_bytes` into the sigma challenge transcript.
**Effort**: ~30 min

### P1.4 — Batched shares not in verify_shares
**Issue**: `verify_batched_share_computation` is separate from `verify_shares`.
**Fix**: Same as P0.7 — already covered.

### P1.5 — On-chain Honk doesn't verify Nova/BFV/DKG
**Issue**: UltraHonk verifier only checks 7 public inputs. No Nove, BFV, decrypt, or DKG on-chain.
**Fix**: Add `nova_final_state_commitment`, `decrypt_nizk_hash`, `dkg_transcript_hash` as public inputs to the Noir circuit. The on-chain verifier checks these are non-zero AND bound to the IVC proof hash.
**Effort**: Already partially done (IvcBinding). Expand to include more fields.

### P1.6 — verifyWithIvc does not prove IVC
**Issue**: Requires non-zero IvcBinding + replay rules. Does not pass IVC/Nova data into Honk public inputs.
**Fix**: Pass `ivc_snark_proof_bytes` as calldata. Noir circuit verifies IVC proof in-circuit (Or, for now: verify that `IvcBinding.pp_hash == Poseidon(public_inputs)`).
**Effort**: ~2 hrs

### P1.7 — Circuit/contract public-input layout mismatch
**Issue**: Aggregator Noir has more/different public fields than 7-input Honk path.
**Fix**: Align Noir circuit public inputs with contract. Make pipeline responsible for consistent encoding.
**Effort**: ~1 hr

## P2 — Fold + Nova + Composition (10 issues)

### P2.1 — Native fold only (no ZKP that fold math is correct)
**Issue**: verify_fold checks accumulator consistency and norms. Fold soundness not carried into IVC.
**Fix**: Already partially addressed by FoldVerifierStepCircuit on feature branch. Merge to main.
**Effort**: ~2 hrs (merge)

### P2.2 — IVC operates on hashes, not R_q
**Issue**: Default compressor uses CycloFoldStepCircuit on 3 Fr fields (hashed accumulator).
**Fix**: Documented limitation. Full lattice folding is P2 open problem. Accept for now.

### P2.3 — DkgAggregationStepCircuit is hash arithmetic
**Issue**: Poseidon over field-encoded shares. Not BFV/RLWE in step circuit.
**Fix**: Same as P2.2 — Nova operates on Folding over Fr, not R_q. Acknowledge.

### P2.4 — Nova does not verify prior native checks
**Issue**: IVC success doesn't imply BFV sigma, decrypt NIZK, or verify_fold were valid.
**Fix**: Add cross-hash binding: each step circuit's state includes `Poseidon(all prior verification results)`. The final Nova state hash binds to ALL prior checks.
**Effort**: ~3 hrs

### P2.5 — FoldVerifierStepCircuit not default
**Issue**: Exists in tests, not wired as production compressor.
**Fix**: Make it default in e2e pipeline. Feature branch has this.
**Effort**: ~30 min (merge)

### P2.6 — Multiple compressors (C1/C4/C5/C7) easy to misread
**Issue**: Different step circuits for different pipeline stages.
**Fix**: Document in ARCHITECTURE.md which compressor applies where.

### P2.7 — No single verifier for full protocol
**Issue**: Layers are separate. Nothing forces "Honk pass → all native checks passed on same inputs."
**Fix**: Create `ProtocolVerifier` struct that chains all verification steps. Reject if any native check fails.
**Effort**: ~2 hrs

### P2.8 — Security depends on off-chain runners
**Issue**: full_pipeline runs many checks. A caller using only verify_shares + on-chain Honk gets less.
**Fix**: Same as P2.7 — ProtocolVerifier ensures all checks run.

### P2.9 — No standard third-party verify CLI
**Issue**: No mandatory wire format for independent re-verification.
**Fix**: Add `pvthfhe-cli verify-all --proof-file <path>` CLI command that runs all verification steps.
**Effort**: ~1 hr

### P2.10 — UltraHonk fixture stale in tests
**Issue**: `UltraHonkVerifier.t.sol` skips valid-proof test.
**Fix**: Regenerate fixture from current circuit. Un-skip test.
**Effort**: ~30 min

## Execution Waves

### Wave 1 — P0: BFV/Greco + Witness (highest priority)
- [ ] P0.1: Merge bfv_greco.rs from feature branch
- [ ] P0.2: Add explicit witness bounds to bfv_sigma::verify
- [ ] P0.3: Enforce t_plain bound on m coefficients
- [ ] P0.4: Bind plaintext to PVSS share commitment
- [ ] P0.5: Generate proper error witness for inner sigma
- [ ] P0.6: Reject empty BFV proof
- [ ] P0.7: Call verify_batched_share_computation from verify_shares
- [ ] P0.8: Redesign decrypt NIZK to prove decryption relation

### Wave 2 — P1: Cyclo + Sigma + On-Chain
- [ ] P1.1: Implement Ajtai commitment verification
- [ ] P1.2: Set SIGMA_REPETITIONS default to 90
- [ ] P1.3: Hash ciphertext bytes into sigma transcript
- [ ] P1.5–P1.7: Expand IvcBinding + align public inputs

### Wave 3 — P2: Composition + Completeness
- [ ] P2.1: Merge FoldVerifierStepCircuit from feature branch
- [ ] P2.4: Cross-hash prior verification results into Nova state
- [ ] P2.7: Create ProtocolVerifier
- [ ] P2.9: Add verify-all CLI command
- [ ] P2.10: Regenerate UltraHonk test fixture

## Success Criteria
- [ ] `cargo check --workspace` = 0 errors
- [ ] `just demo-e2e` ACCEPT
- [ ] bfv_greco registered in module tree
- [ ] Witness bounds enforced in bfv_sigma::verify
- [ ] Decrypt NIZK proves decryption relation
- [ ] Ajtai commitment verified on CycloNizkAdapter path
- [ ] SIGMA_REPETITIONS default = 90
- [ ] ProtocolVerifier chains all checks
- [ ] verify-all CLI exists
