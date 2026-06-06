# MPC Audit Remediation Plan — 2026-06-05 Deep Pass

**Source**: MPC security audit by Sisyphus (2026-06-05, deep pass)
**Base**: Git HEAD post prior MPC audit remediation (all 19 findings remediated)
**Scope**: 10 new findings (2 CRITICAL, 4 HIGH, 2 MEDIUM, 2 LOW)
**Policy**: TDD — RED test before every implementation change
**Architecture principle**: Abort-with-public-blame. Only the verifier at each phase is trusted.

---

## P0 (Immediate): F1 — Empty Sigma Proof List Passes Vacuously : CRITICAL

**File**: `crates/pvthfhe-nizk/src/sigma.rs` (lines 507–525), `crates/pvthfhe-nizk/src/adapter.rs` (line 205)

**Fix**: Add explicit empty-rounds rejection in BOTH `sigma::verify_multi` AND the adapter boundary.

**sigma.rs patch** (lines 507–525):
```rust
pub fn verify_multi(
    session_id: &[u8],
    participant_id: u32,
    stmt: &SigmaStatement,
    proof: &SigmaMultiProof,
    d_commitment: &[u8; 32],
) -> Result<(), NizkError> {
    if proof.rounds.is_empty() {
        return Err(NizkError::VerificationFailed(
            "sigma multi-proof must have at least one round",
        ));
    }
    for (i, round_proof) in proof.rounds.iter().enumerate() {
        verify_scalar_round(session_id, participant_id, stmt, round_proof, d_commitment, i)?;
    }
    Ok(())
}
```

**adapter.rs patch** (after line 205, inside `verify()`):
```rust
let (d_rns, sigma_multi) = decode_sigma_section_multi(&sigma_section)?;

// Reject empty proof lists (defense-in-depth; also checked in sigma::verify_multi)
if sigma_multi.rounds.is_empty() {
    return Err(NizkError::VerificationFailed(
        "sigma multi-proof must have at least one round",
    ));
}
```

**RED tests**:
1. `sigma::tests::test_verify_multi_rejects_empty_rounds` — calls `verify_multi` with `SigmaMultiProof { rounds: vec![] }`, expects `Err`
2. `adapter::tests::test_verify_rejects_zero_round_nizk` — crafts NIZK proof bytes with `num_rounds=0`, calls `CycloNizkAdapter::verify`, expects `Err`

**Verification**: `cargo test -p pvthfhe-nizk` passes all tests including new RED→GREEN

---

## P0 (Immediate): F3 — `challenge_r` Not Session-Bound in `aggregator_final` Circuit : HIGH

**File**: `circuits/aggregator_final/src/main.nr` (lines 206, 274)

**Fix**: Derive `challenge_r` inside the circuit via Poseidon sponge on session-relevant public inputs. The challenge MUST bind: `ciphertext_hash`, `dkg_root`, `epoch`, `participant_set_hash`, `share_commitment_root`, `n_shares`. This eliminates the prover's ability to choose `challenge_r`.

**Noir patch** (replaces line 206 and adds derivation before S-Z check):
```noir
fn main(
    ...
    // challenge_r: pub Field,  // REMOVED — now computed in-circuit
    ...
) -> pub [Field; N] {
    ...
    // Derive challenge_r from session-binding transcript:
    let challenge_r = poseidon::poseidon::bn254::sponge([
        ciphertext_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        share_commitment_root,
        n_shares,
        protocol_constants::DOMAIN_SZ_CHALLENGE,
    ]);
    ...
}
```

**Protocol constants addition** (if using domain tag):
Add `DOMAIN_SZ_CHALLENGE` to `circuits/protocol_constants/src/lib.nr`.

**RED test**: `test_c7_challenge_r_not_bound_rejected` — provide honest inputs but supply a different `challenge_r` that's inconsistent with the Poseidon derivation. Before fix: accepts. After fix: MUST reject.

**Verification**: `(cd circuits/aggregator_final && nargo test)` passes all tests including new RED→GREEN

---

## P1 (Same Session): F2 — N=8 Circuit Coefficient Dimension Documentation : CRITICAL

**Files**: `docs/OPEN-PROBLEM-BLOCKERS.md`, `SECURITY.md`, `ARCHITECTURE.md`

**Fix**: This is NOT a code fix (N=8192 in-circuit requires `generic_const_exprs` or Noir specialization, which is a research task). The remediation is documentation and circuit-comment hardening:

1. Add `// ⚠️ PROTOTYPE: N=8 coefficient dimension. Production RLWE uses N=8192.` banner to ALL three production circuit `main.nr` files:
   - `circuits/aggregator_final/src/main.nr` (line 41, above `global N: u32 = 8`)
   - `circuits/decrypt_share/src/main.nr`
   - `circuits/nova_state_commitment/src/main.nr`

2. Add entry to `docs/OPEN-PROBLEM-BLOCKERS.md` as G-N8:
   ```markdown
   ### G-N8: N=8 Circuit Prototype vs Production N=8192 (CRITICAL)
   
   All three production circuits operate at polynomial dimension N=8.
   Production RLWE uses N=8192. The circuits prove correctness on
   8-coefficient data; the mapping from N=8192 to N=8 is in native
   Rust (`aggregate_decrypt_raw_result_poly`) and is not provably
   correctness-preserving.
   
   **Resolution**: Scale circuits to N=8192 (requires Noir `generic_const_exprs`
   or specialization) OR provide formal reduction from N=8192 correctness
   to N=8 verification.
   
   **Status**: OPEN. Target: T42 (pre-audit).
   ```

3. Update `SECURITY.md` §Trust Boundaries to note the N=8 truncation gap explicitly.

**Verification**: Manual review of documentation completeness.

---

## P1 (Same Session): F4 — Lyubashevsky Rejection Sampling Retry Exhaustion : HIGH

**File**: `crates/pvthfhe-nizk/src/sigma.rs` (lines 303–374)

**Fix**: Increase `max_retries` from 100 to 100,000 and regenerate with fresh masking samples (not the same sample) on each retry. Also, add a compile-time assertion that the fallback is impossible for the chosen parameters.

**sigma.rs patch** (lines 303–374):
```rust
// Before:
let max_retries = 100;
let mut last_result: Option<...> = None;
for _attempt in 0..max_retries {
    // sample y_s, y_e
    if sample < accept_prob { return Ok(proof); }
    last_result = Some((t_rns, z_s, z_e, ch));
}
// WARN + fallback

// After:
let max_retries = 100_000;
for _attempt in 0..max_retries {
    // REGENERATE fresh y_s, y_e on EACH retry:
    let (y_s, y_e) = sample_masking_polys(&mut rng, n, bound)?;
    // ... compute accept_prob ...
    if sample < accept_prob { return Ok(proof); }
}
// If we exhaust all retries, this is a PROTOCOL ERROR — the parameters
// were chosen so that acceptance probability is bounded below.
return Err(NizkError::ProofGenerationFailed(
    "sigma rejection exceeded max_retries — parameter selection failed",
));
```

**Key change**: Remove the `last_result` fallback entirely. Exhausting retries returns an error, not a potentially-leaking proof. The B_Y parameter must ensure acceptance probability is well above 1/100,000 for any witness within the norm bound.

**RED test**: `test_rejection_sampling_exhausts_retries_returns_error` — use a mock RNG that always returns rejection, verify the prover returns `Err` rather than a fallback proof.

**Verification**: `cargo test -p pvthfhe-nizk sigma` passes all tests including new RED→GREEN

---

## P2 (Next Session): F5 — `n_shares` Guard Does Not Bound G2 Merkle Loop : HIGH

**File**: `circuits/aggregator_final/src/main.nr` (lines 259–279)

**Fix**: Use `n_shares` to bound the G2 verification loop. Positions beyond `n_shares` must be all-zero (padding verified).

**Noir patch** (replaces lines 259–279):
```noir
    // G2: Per-share Merkle-bound commitment verification for active shares
    for i in 0..n_shares {
        let computed_commitment = vector_hash(share_polys[i], protocol_constants::DOMAIN_VECTOR_MERKLE);
        assert(computed_commitment == share_commitments[i], "share commitment mismatch");

        let computed_eval = eval_poly(share_polys[i], challenge_r);
        assert(computed_eval == share_evals[i], "share eval does not match polynomial evaluation");

        let computed_root = compute_merkle_root(share_commitments[i], merkle_paths[i], leaf_indices[i]);
        assert(computed_root == share_commitment_root, f"root mismatch at share {i}");
    }

    // Verify padding positions are zero (must not contribute to sums)
    let zero_poly = [0; N];
    for i in n_shares..MAX_SHARES {
        assert(share_evals[i] == 0, "padding share_evals must be zero");
        assert(lagrange_coeffs[i] == 0, "padding lagrange_coeffs must be zero");
        assert(share_polys[i] == zero_poly, "padding share_polys must be zero");
    }
```

**RED test**: `test_g2_padding_violation_rejected` — provide non-zero data in padding positions beyond `n_shares`. Before fix: may pass. After fix: MUST reject.

**Verification**: `(cd circuits/aggregator_final && nargo test)` passes all tests including new RED→GREEN

---

## P3 (Backlog): F6 — `ccs_instance_id` Lacks Epoch Binding : MEDIUM

**File**: `crates/pvthfhe-nizk/src/adapter.rs` (lines 463–473)

**Fix**: Add `stmt.epoch` to the CCS instance ID hash computation.

**adapter.rs patch** (line 466):
```rust
fn compute_ccs_instance_id(stmt: &NizkStatement) -> Result<[u8; 32], NizkError> {
    let mut h = Sha256::new();
    h.update(stmt.epoch.to_be_bytes());           // ← ADD epoch binding
    h.update(stmt.session_id.as_bytes());
    h.update(stmt.participant_id.to_be_bytes());
    h.update(stmt.params.0.to_be_bytes());
    // ... degree, error_bound ...
    h.update(b"cyclo-ajtai-d2/v1");
    Ok(h.finalize().into())
}
```

**RED test**: `test_ccs_instance_id_differs_by_epoch` — compute `ccs_instance_id` for two statements differing only in epoch, verify the IDs differ.

**WARNING**: This changes the proof format. All previously generated proofs will fail verification. This is acceptable since this is a pre-production system.

**Verification**: `cargo test -p pvthfhe-nizk` passes all tests including new RED→GREEN

---

## P3 (Backlog): F7 — Greyhound PCS Challenge Lacks Session Binding : MEDIUM

**File**: `crates/pvthfhe-compressor/src/nova/greyhound_pcs.rs`

**Fix**: Add `session_id` and `prover_id` to the Greyhound challenge hash inputs. (This is a re-check of prior-audit M5.)

**Action**: Verify whether prior-audit M5 was actually remediated (claimed COMPLETE but this audit found the gap still open). If NOT remediated:
```rust
// Add to challenge derivation:
h.update(stmt.session_id.as_bytes());
h.update(stmt.participant_id.to_be_bytes());
```

**RED test**: `test_greyhound_challenge_differs_by_session` — generate two Greyhound challenges differing only in session_id, verify they differ.

**Verification**: `cargo test -p pvthfhe-compressor` passes all tests

---

## P4 (Backlog): F8 — BFV Encryption Sigma Computational ZK Documentation : HIGH

**File**: `crates/pvthfhe-nizk/src/bfv_sigma.rs`

**Fix**: Documentation-only. Add a module-level doc comment and a `// SAFETY` comment explaining the ZK model.

**bfv_sigma.rs patch** (module header):
```rust
//! # BFV Encryption Sigma Protocol
//!
//! ## Zero-Knowledge Model
//!
//! This sigma protocol provides **computational** ZK under the RLWE assumption,
//! NOT statistical ZK. The protocol does NOT implement Lyubashevsky rejection
//! sampling. Instead, it uses noise drowning with mask width B_Y = 2^30,
//! achieving witness-to-mask ratio ≥ 4.0.
//!
//! **Soundness**: (1/2)^N ≈ 2^(-8192) per sigma instance (binary challenge over N coeffs).
//!
//! **ZK guarantee**: An RLWE adversary who can distinguish masking distribution
//! from shifted distribution breaks the RLWE assumption. For a PPT adversary
//! (current threat model), this is sufficient. For unconditional ZK, a
//! rejection-sampling variant must be implemented.
```

**Verification**: Manual review of documentation accuracy.

---

## P4 (Backlog): F9 — `participant_id` Type Inconsistency : LOW

**File**: Multiple (`lib.rs`, `fiat_shamir.rs`, `adapter.rs`)

**Fix**: Low-priority refactor. Standardize on `u16` for participant_id. Add `u16::try_from(u32).expect("participant_id out of u16 range")` with a compile-time check that the conversion is safe.

**Verification**: `cargo test` full workspace passes. No behavioral change.

---

## P4 (Backlog): F10 — `aggregate_decrypt` Doc Comment : LOW

**File**: `crates/pvthfhe-fhe/src/fhers.rs` (line ~1456)

**Fix**: Documentation-only. Add method doc comment explaining the trust model.

```rust
/// Aggregate threshold decryption from validated shares.
///
/// ⚠️ **Trust Model**: This method computes the plaintext via Lagrange
/// interpolation WITHOUT post-hoc verification. The result MUST be
/// re-verified through the C7 Noir circuit + IVC proof chain + on-chain
/// UltraHonk verification before being trusted in production.
///
/// This method is provided for:
/// - Test scenarios (no adversary modeled)
/// - Simulator/pipeline benchmarks
/// - As input to the `aggregator_final` circuit which independently
///   verifies correctness through Schwartz-Zippel identity checking
///
/// In production, the full verification pipeline (NIZK → Circuit → IVC → Honk)
/// MUST be executed after this method returns.
pub fn aggregate_decrypt(...) -> Result<Vec<u8>, FheError> {
```

---

## Implementation Order & Parallel Workstreams

| Stream | Priority | Findings | Estimated Effort | Can Parallelize? |
|--------|----------|----------|-----------------|------------------|
| S1: Empty-proof + retry | P0+P1 | F1, F4 | 30 min | Yes (with S2) |
| S2: Challenge binding | P0 | F3 | 30 min | Yes (with S1) |
| S3: Documentation | P1+P4 | F2, F8, F10 | 20 min | Yes (with S1, S2) |
| S4: Circuit loops | P2 | F5 | 20 min | After S2 |
| S5: CCS epoch + Greyhound | P3 | F6, F7, F9 | 30 min | Yes |

**Total estimated effort**: ~2 hours for all 10 findings (including TDD tests).

**Verification gate**: `just phase2-gate` (full CI) must pass after all changes.

---

## TDD Protocol

Every finding follows:
1. Write RED test that FAILS on current code (demonstrates vulnerability)
2. Apply fix
3. Verify test goes GREEN
4. Run `lsp_diagnostics` on modified files
5. Run `just phase2-gate` to verify no regressions
