# Deep Security Audit — Remediation Plan (May 21, 2026)

**Source**: 4 parallel audit agents (Noir constraints, native bypass, protocol binding, per-node/aggregator)  
**Scope**: 89 findings across all categories  
**Priority tasks**: 8 critical, 12 high, rest medium

## Tier 0 — CRITICAL (blocks protocol soundness)

### 0.1: bb verify failure ignored (Audit 1, finding 1.6)
`full_pipeline.rs:1604-1606`: bb verify exits non-zero but `noir_passed` is NOT set to false.
- [ ] Add `noir_passed = false` in the bb verify error path
- [ ] QA: `just demo-e2e 16 7 1` still ACCEPTS

### 0.2: C7 verification SKIPPED for n > 8 (Audit 1, finding 1.5)
`full_pipeline.rs:1312-1317`: Returns `true` without verification when share_coeffs > MAX_PARTICIPANTS.
- [ ] Return error instead of silently passing
- [ ] QA: `just demo-e2e 16 7 1` ACCEPTS (n=16 uses MAX_PARTICIPANTS=128 now)

### 0.3: Ajtai fold failure → Fr::zero() (Audit 1, finding 3A.1)
`full_pipeline.rs:620`: Falls back to zero instead of aborting.
- [ ] Change to `anyhow::bail!("Ajtai Phase 4 folding failed")` 
- [ ] QA: `just demo-e2e 16 7 1` ACCEPTS

### 0.4: d_commitment zero placeholders (Audit 1, finding 6A.1-6A.5)
5 locations use `[0u8; 32]` or `Fr::zero()` for d_commitment in sigma protocol.
- [ ] Compute real d_commitment from pipeline data
- [ ] Pass to sigma::prove, sigma::verify, bfv_sigma, C7 verification
- [ ] QA: `just demo-e2e 16 7 1` ACCEPTS

### 0.5: 6 dead cyclo_* Noir fields (Audit 2)
`main.nr:86-92`: cyclo_hash, cyclo_norm_acc, cyclo_ring_count, cyclo_sigma_count, cyclo_norm_zs, cyclo_norm_ze — never constrained.
- [ ] Remove from `main()` signature
- [ ] Remove from `build_c7_prover_toml` output
- [ ] Remove from test callers
- [ ] QA: `nargo test --package aggregator_final` — all pass

### 0.6: Encrypted shares not verified in per_node (Audit 4, P3)
`per_node.rs`: `adapter.deal()` called but `verify_shares()` never called.
- [ ] Add `adapter.verify_shares(&encrypted, &ctx)?` after each deal
- [ ] QA: `just per-node 16 7 1` completes

### 0.7: PipelineReport d_commitment_verified always None (Audit 1, 2.1)
- [ ] Implement actual d_commitment verification using the real value (from 0.4)
- [ ] Set `d_commitment_verified = Some(computed == noir_output)` 
- [ ] QA: demo-e2e report shows verified = true

### 0.8: G1Affine point-at-infinity panic (Audit 1, 4.1)
`full_pipeline.rs:1264-1274`: `.unwrap()` on G1Affine coordinates.
- [ ] Replace with `.context("G1 point")?` and propagate error

## Tier 1 — HIGH (enables active attacks, ~5 days)

### 1.1: Hash-chain gaps — nizk_verify → pvss_share_encrypt
- [ ] After NIZK verification, compute `all_nizk_hashes = Poseidon(all_nizk_proofs)` 
- [ ] Absorb into PVSS session binding (`dkg_root` or `session_nonce`)
- [ ] QA: `just demo-e2e 16 7 1` ACCEPTS

### 1.2: Hash-chain gaps — compressor_verify → partial_decrypt
- [ ] After compressor verify, compute `compressed_proof_hash`
- [ ] Bind into partial_decrypt session via `session_nonce` or d_commitment
- [ ] QA: `just demo-e2e 16 7 1` ACCEPTS

### 1.3: 8× duplicated verify block
- [ ] Extract `fn verify_compressed_inner<S, EI>(...)` generic function
- [ ] Replace all 8 copies with single call
- [ ] QA: `cargo test -p pvthfhe-compressor` — existing compressor tests pass

### 1.4: Missing tamper tests — Noir circuit
- [ ] `test_tamper_registered_share_hashes`: pass wrong hash → should REJECT
- [ ] `test_tamper_aggregate_pk_hash_zero`: pass 0 → should REJECT  
- [ ] `test_tamper_decrypt_nizk_hash_zero`: pass 0 → should REJECT
- [ ] `test_tamper_dkg_transcript_hash_zero`: pass 0 → should REJECT
- [ ] QA: `nargo test --package aggregator_final` — 4 new tests, all pass

### 1.5: PipelineReport field verification
- [ ] Add `verify_pipeline_report(pipeline_vars, noir_public_inputs)` function
- [ ] Check: `combined_share_hash` matches folded proof output
- [ ] Check: `dkg_verified` consistent with fold hashes
- [ ] Check: `sk_commitments` match NIZK pvss_commitment
- [ ] QA: `just demo-e2e 16 7 1` ACCEPTS, report shows all checks pass

## Tier 2 — MEDIUM (defense-in-depth, ~3 days)

### 2.1: Thread-local clearing on panic
- [ ] Implement Drop guard for CYCLO_RING_DATA, SIGMA_DATA, SIGMA_RESPONSE_DATA
- [ ] Clear on drop via `std::cell::RefCell` wrapper with Drop impl
- [ ] QA: unit test that panics mid-prove, verify data cleared

### 2.2: extract_cyclo_state unwrap_or zero fallback
- [ ] Change `unwrap_or([Fr::zero(); 7])` to return `Result` with error
- [ ] Propagate error to caller
- [ ] QA: `just demo-e2e 16 7 1` ACCEPTS

### 2.3: Delete stale Prover.toml
- [ ] Remove `circuits/aggregator_final/Prover.toml` (uses old param names)
- [ ] Remove `circuits/aggregator_final/Prover_re.toml` (replica)
- [ ] QA: `nargo execute --package aggregator_final --prover-name C7Prover` still works

### 2.4: dkg_root empty fallback audit
- [ ] Check `encrypt.rs:491` — when dkg_root empty, session_id used as fallback
- [ ] Either remove fallback or inject dkg_root from pipeline
- [ ] QA: `just demo-e2e 16 7 1` ACCEPTS

### 2.5: nizk_prove cross-party verify in per_node
- [ ] Change per_node to verify n-1 other parties' proofs (not just t-1 self-copies)
- [ ] Use synthetic party data for benchmark scaling
- [ ] QA: `just per-node 16 7 1` completes
