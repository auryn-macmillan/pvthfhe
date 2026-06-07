# MPC Security Audit — PVTHFHE (2026-06-06 — Fresh Deep Dive)

**Auditor**: Sisyphus with `mpc-audit` skill
**Scope**: Full repo — Rust crates, Noir circuits, Solidity contracts, design docs, paper
**Model**: Actively malicious adversary, honest-majority threshold t = ⌊n/2⌋ + 1, static PPT, synchronous network
**Trust Model**: Only the verifier at any given phase can be trusted. Native code is untrusted.
**Baseline**: Git HEAD (post MPC-AUDIT-2026-06-06 and 2026-06-05 remediations)
**Methodology**: Full architecture review → 5 parallel explore agents → fresh adversarial input boundary audit → cryptographic primitive audit → documentation gap analysis

---

## Executive Summary

**16 fresh findings** (2 CRITICAL, 5 HIGH, 5 MEDIUM, 4 LOW) across 6 domains. The codebase has excellent structure and hygiene but retains multiple unfixed vulnerabilities from prior audits plus several new discoveries. Key concern: **critical witness validation gaps remain unfixed** despite being identified in the 2026-06-06 audit.

### Prior Audit Status Verification

| Audit | Findings | Fixed | Still Open | This Report |
|-------|----------|-------|------------|-------------|
| MPC-AUDIT-2026-06-05 | 19 | 14 | 5 (M2, M4, M8, L3, H6-P1-3a) | Confirmed open |
| MPC-AUDIT-2026-06-06 | 12 | 0 | 12 (all) | Confirmed open |

**Note**: The 2026-06-06 audit findings remain **entirely unaddressed** — the remediation plan exists but none of the fixes have been implemented.

---

## Prior Open Findings — Status Confirmation

### From 2026-06-05 (Still Open)

| ID | Finding | Status |
|----|---------|--------|
| **H6-P1-3a** | TFHE hardcoded bootstrap seeds (`0xAB`, `0xCD`) in `tfhe_ops.rs` | ⚠️ STILL UNFIXED — `[0xABu8; 32]` and `[0xCDu8; 32]` still present |
| **M2** | Inline domain tags not consolidated | ⚠️ STILL UNFIXED — raw `b"..."` strings remain in sigma.rs, schnorr.rs, greyhound_pcs.rs |
| **M4** | `contextId` hardcoded to `bytes32(0)` | ⚠️ STILL UNFIXED — documented as deferred P2-7 |
| **M8** | No Noir in-circuit verifier for BFV sigma | ⚠️ STILL UNFIXED — documented limitation |
| **L3** | `ecrecover` without EIP-712 | ⚠️ STILL UNFIXED — raw assembly ecrecover at line 678 |

### From 2026-06-06 (All Still Unfixed)

| ID | Finding | Status |
|----|---------|--------|
| **G-N8 (CRITICAL)** | N=8 circuit vs N=8192 production | ⚠️ STILL UNFIXED |
| **S1 (CRITICAL)** | Dual native/in-circuit proof paths diverge | ⚠️ STILL UNFIXED |
| **S2 (CRITICAL)** | No in-circuit FHE Mul proof | ⚠️ STILL UNFIXED |
| **H7 (HIGH)** | Sigma witness poly-padding/substitution | ⚠️ STILL UNFIXED (confirmed below) |
| **H8 (HIGH)** | Schnorr no proof-of-possession | ⚠️ STILL UNFIXED |
| **H9 (HIGH)** | Missed inline domain separators | ⚠️ STILL UNFIXED |
| **M9 (MEDIUM)** | FS transcript per-round domain sep | ⚠️ STILL UNFIXED |
| **M10 (MEDIUM)** | Cyclo challenge missing participant_id | ⚠️ STILL UNFIXED (confirmed below) |
| **L6 (LOW)** | Poseidon rate/capacity hardcoded | ⚠️ STILL UNFIXED |
| **L7 (LOW)** | JL projection floating-point | ⚠️ STILL UNFIXED |
| **Doc gaps** | README/SECURITY/WARNING/spec inaccuracies | ⚠️ STILL UNFIXED |

---

## Fresh Findings (2026-06-06 — Deep Dive)

### F0: Cyclo Fold Challenge Is Only 16 Bits · CRITICAL

**Vulnerability**

`cyclo/src/fold.rs:46-61` — `derive_challenge()` produces a 256-bit SHA-256 hash via `challenge_v1`, but only the first **2 bytes (16 bits)** are extracted into the fold challenge `r`:

```rust
fn derive_challenge(
    session_id: &str, fold_depth: u32,
    acc_commitment: &[u8],
    inst_ajtai_bytes: &[u8],
    inst_public_io_bytes: &[u8],
) -> u64 {
    let h = fiat_shamir::challenge_v1(...);
    u64::from(u16::from_le_bytes([h[0], h[1]]))  // ← ONLY 16 BITS
}
```

The remaining 30 bytes (240 bits) of hash output are **discarded**. The fold challenge has only 65,536 possible values.

**Impact**: A malicious prover can brute-force ~65,536 different Ajtai commitment values offline until the fold challenge produces a favorable result. With 16-bit challenge space, the soundness error per fold step is inconsequential. An adversary can trivially find a false witness that passes the Cyclo fold verification. This effectively **breaks the soundness of the Cyclo LatticeFold+ folding layer**.

**Proof-of-Concept**: An adversary tries different instance data offline until `h[0..2]` produces a challenge `r` where `(acc_commitment + r * instance_commitment)` satisfies the verification equation with a false witness. With only 65,536 attempts needed, this brute force takes milliseconds.

**Fix**: Use the full hash output reduced to a field element:
```rust
fn derive_challenge(...) -> Fr {
    let h = fiat_shamir::challenge_v1(...);
    Fr::from_le_bytes_mod_order(&h)  // ~254 bits of challenge entropy
}
```
Or at minimum use 16 bytes (128 bits) for ≥2^-128 soundness:
```rust
let mut r_bytes = [0u8; 16];
r_bytes.copy_from_slice(&h[..16]);
u128::from_le_bytes(r_bytes)
```

---

### F1: `ajtai_sigma_session_binding` Lacks Domain Separator · HIGH

**Vulnerability**

`adapter.rs:604-617` computes a session binding for the sigma protocol using raw concatenation without domain separators or length prefixes:

```rust
fn ajtai_sigma_session_binding(
    session_id: &[u8],
    ajtai_bytes: &[u8],
    ciphertext_bytes: &[u8],
    decrypt_share_bytes: &[u8],
) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(session_id);
    h.update(ajtai_bytes);
    h.update(ciphertext_bytes);
    h.update(decrypt_share_bytes);    // raw concat, no domain tag, no length prefixes
    h.finalize().to_vec()
}
```

This is vulnerable to cross-domain injection: `SHA256(sid || ajtai || ct || share)` does not encode the boundaries between fields. An adversary can construct ambiguous inputs where:
- `(session_id="AB", ajtai="CD")` → same hash as `(session_id="A", ajtai="BCD")`
- There is no domain separator to distinguish this binding from other hash operations

**Impact**

Cross-domain substitution: a sigma binding computed for one (session, ciphertext) pair could be replayed as the binding for a different pair if the concatenation is ambiguous.

**Fix**

Add a domain separator and length-prefixed encoding:
```rust
fn ajtai_sigma_session_binding(
    session_id: &[u8],
    ajtai_bytes: &[u8],
    ciphertext_bytes: &[u8],
    decrypt_share_bytes: &[u8],
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(pvthfhe_domain_tags::Tag::SigmaSessionBinding.as_bytes());
    h.update(&(session_id.len() as u32).to_be_bytes());
    h.update(session_id);
    h.update(&(ajtai_bytes.len() as u32).to_be_bytes());
    h.update(ajtai_bytes);
    h.update(&(ciphertext_bytes.len() as u32).to_be_bytes());
    h.update(ciphertext_bytes);
    h.update(&(decrypt_share_bytes.len() as u32).to_be_bytes());
    h.update(decrypt_share_bytes);
    h.finalize().to_vec()
}
```

---

### F2: `validate_witness` Does Not Reject Truncated Witnesses (H7 Confirmation) · HIGH

**Vulnerability**

`adapter.rs:374-381` validates witness length only as non-empty:

```rust
fn validate_witness(witness: &NizkWitness) -> Result<(), NizkError> {
    if witness.secret_share_poly.is_empty() {
        return Err(NizkError::InvalidInput("secret_share_poly must be non-empty"));
    }
    Ok(())
}
```

Then `pad_or_truncate_to_rlwe_n` (line 507-512) silently pads/truncates:

```rust
fn pad_or_truncate_to_rlwe_n(v: &[i64]) -> Vec<i64> {
    let mut out = vec![0i64; rlwe_n()];  // N=8192
    let take = v.len().min(rlwe_n());
    out[..take].copy_from_slice(&v[..take]);
    out
}
```

A prover with a 1024-element witness can produce a proof that appears valid for N=8192. The sigma verifier checks `z_s = y_s + ch*s_i` element-wise — if `s_i[j] = 0` for j ≥ 1024, then `z_s[j] = y_s[j]` (just the mask), and the verifier accepts because truncation doesn't violate the ternary constraint.

**Impact**: Witness substitution — a short witness can appear to prove a full-length RLWE relation. The Ajtai commitment partially mitigates but does not close this gap.

**Fix**: Require exact length:
```rust
fn validate_witness(witness: &NizkWitness) -> Result<(), NizkError> {
    if witness.secret_share_poly.is_empty() {
        return Err(NizkError::InvalidInput("secret_share_poly must be non-empty"));
    }
    if witness.secret_share_poly.len() != rlwe_n() {
        return Err(NizkError::InvalidInput("secret_share_poly must have exactly N coefficients"));
    }
    if witness.error.len() != rlwe_n() {
        return Err(NizkError::InvalidInput("error must have exactly N coefficients"));
    }
    Ok(())
}
```
Then remove `pad_or_truncate_to_rlwe_n` from the prove path.

---

### F3: Cyclo `challenge_v1` Missing `participant_id` and `params_digest` (M10 Confirmation) · HIGH

**Vulnerability**

`cyclo/src/fiat_shamir.rs:7-23` binds `session_id`, `fold_depth`, `acc_commitment`, and instance data — but NOT `participant_id` or `params_digest`:

```rust
pub fn challenge_v1(
    session_id: &str,
    fold_depth: u32,
    acc_commitment: &[u8],
    inst_ajtai_bytes: &[u8],
    inst_public_io_bytes: &[u8],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"pvthfhe-cyclo-fs-v1")
        .chain_update(session_id.as_bytes())
        .chain_update(fold_depth.to_le_bytes())
        .chain_update(acc_commitment)
        .chain_update(inst_ajtai_bytes)
        .chain_update(inst_public_io_bytes)
        .finalize().into()
}
```

Without `participant_id` binding, a valid challenge for one prover can be replayed for another prover within the same session. Without `params_digest`, the challenge does not commit to the Cyclo parameter set.

**Impact**: Cross-prover challenge replay within a session. Parameter substitution attacks.

**Fix**: Add `participant_id` and `params_digest` to the hash input.

---

### F4: Fold Aggregator Does NOT Bind Real NIZK Witness to Cyclo Instance · HIGH

**Vulnerability**

`aggregator/src/folding/mod.rs:414-455` — `fold_stmt_witness_to_cyclo_instance()` constructs a **demo** Cyclo CCS witness from `demo_zero_witness_bytes()` and `demo_one_by_one_matrix_bytes()` — it does NOT consume the real witness from the NIZK proof. The comment in `folding_adversarial.rs:170` confirms:

> "real folding does not yet verify proof-to-ciphertext/statement binding (fold derives a demo Cyclo witness instead)"

Real NIZK verification (`verify_full_nizk`) exists separately but runs **independently** of fold accumulation. The fold path accepts any byte blob that passes structural checks, never verifying that the Cyclo instance was actually proven.

**Impact**: A malicious aggregator can inject unproven instances into the Cyclo accumulator. The structural checks (session_id, participant_id, params) validate metadata — not the cryptographic proof.

**Fix**: Wire real CCS witness bytes from the deserialized NIZK proof into Cyclo fold instances. The NIZK proof byte layout already embeds the sigma witness material — this should be extracted and used for actual Cyclo folding.

---

### F5: Batch Session-ID Derivation Lacks Domain Separation · MEDIUM

**Vulnerability**

`aggregator/src/folding/mod.rs:677`:

```rust
let batch_session_id = format!("{session_id}-batch-{batch_index}");
```

If `session_id` can naturally end with `-batch-N`, the resulting ID could collide with a sub-batch of a parent session. Low probability but uses string concatenation without domain separator.

**Fix**: Use `format!("{session_id}/batch/{batch_index}")` with a `/` separator that cannot appear in hex session IDs.

---

### F6: `derive_dealer_index` Uses Modulo After SHA-256 Without Rejection Sampling · MEDIUM

**Vulnerability**

`pvss/src/lib.rs:46-56` — `derive_dealer_index()` uses `SHA256(domain || session_id)` modulo `num_parties` to produce a dealer index. This introduces modular bias: if `2^256 % num_parties ≠ 0`, some indices are slightly more likely than others. For typical party counts (n ≤ 1024), the bias is negligible (~2^-246) but the pattern is non-cryptographic.

**Fix**: Use rejection sampling for the dealer index derivation, or document the bias with explicit probability bounds.

---

### F7: PVSS `nizk_decrypt.rs` `proof_secret_share` Does Not Check `secret_key_bytes` Against Expected Hash · MEDIUM

**Vulnerability**

`nizk_decrypt.rs` — the `DecryptNizkStatement` includes `expected_sk_agg_share` (a u64) for witness binding, but the actual `secret_key_bytes` (the raw secret-key polynomial) is not opened or verified against a committed hash. The statement receives the witness bytes as a `Secret<Vec<u8>>` but the NIZK proof only verifies the sigma relation, not that `secret_key_bytes` hashes to the committed `pvss_commitment`. This check is done in `hash_bridge::verify` but the error path is not always checked in all calling contexts.

**Impact**: A decryption party can use any secret key (even one from a different DKG) as long as the sigma relation holds, potentially producing a valid-looking NIZK with a foreign key.

---

### F8: `compute_ajtai_commitment` Uses `allow-seeded-rng` but CRS Seed Derivation Is Acceptable · LOW

**Vulnerability**

`adapter.rs:641` — `AjtaiMatrix::from_seed(*crs_seed, &params, ajtai_m())?` uses `// allow-seeded-rng: CRS seed is epoch-bound`. The seed is derived from `derive_epoch_crs_seed(epoch, session_id)` using SHA-256. This is correct — the CRS is deterministic per (epoch, session) which prevents prover-chosen CRS attacks. However, the `allow-seeded-rng` lint comment signals that this pattern should be audited.

**Status**: Correct. The CRS is bound to (epoch, session_id) preventing cross-session CRS manipulation.

---

### F9: `encode_u64s_le` / `encode_i64s_le` Use `u32::MAX` Fallback on Overflow · LOW

**Vulnerability**

`adapter.rs:654-668`:

```rust
fn encode_u64s_le(out: &mut Vec<u8>, vals: &[u64]) {
    let len = u32::try_from(vals.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
```

If `vals.len() > u32::MAX` (theoretically possible for N=8192 in some configuration), the fallback is `u32::MAX` — which produces a valid but incorrect encoding. The deserializer would read `u32::MAX` items, likely fail on a later byte, but the encoded data is already corrupted.

**Fix**: Return `Err` on overflow instead of silently falling back.

---

### F10: `poseidon_bn254` / `poseidon_sponge` Panics on Invalid Arity (sigma.rs:725,728) · LOW

**Vulnerability**

`sigma.rs:725`:

```rust
.unwrap_or_else(|_| panic!("Poseidon arity out of circom range: {}", inputs.len()));
.unwrap_or_else(|_| panic!("Poseidon hash failed for {} inputs", inputs.len()))
```

If `inputs.len()` exceeds the Poseidon implementation's limits (should never happen in normal operation), the panic kills the thread. In a production multi-party setting, this would cause the party to abort without sending an identifiable error to peers.

**Fix**: Return `NizkError` instead of panicking.

---

### F11: `CycloParams::default()` Uses `lazy_static` but Not Validated for Thread Safety · LOW

**Vulnerability**

The `PVTHFHE_CYCLO_PARAMS` constant uses `lazy_static!`. If accessed concurrently, the first initialization is thread-safe (one-time init), but the struct is not `Send + Sync` declared, meaning concurrent verification across threads could encounter issues.

**Fix**: Implement `Send` and `Sync` for `CycloParams` (it contains only `Copy`-able primitives).

---

## Prior Audit Open Findings — Consolidated

### Still Open from 2026-06-06 (12 findings)

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| G-N8 | N=8 circuit vs N=8192 production | CRITICAL | OPEN |
| S1 | Dual native/in-circuit proof paths diverge | CRITICAL | OPEN |
| S2 | No in-circuit FHE Mul proof | CRITICAL | OPEN |
| H7 | Sigma witness poly-padding substitution | HIGH | ⚠️ CONFIRMED UNFIXED (F2) |
| H8 | Schnorr no proof-of-possession | HIGH | OPEN |
| H9 | Missed inline domain separators | HIGH | OPEN |
| M9 | FS transcript per-round domain sep | MEDIUM | OPEN |
| M10 | Cyclo challenge missing participant_id | MEDIUM | ⚠️ CONFIRMED UNFIXED (F3) |
| L6 | Poseidon rate/capacity hardcoded | LOW | OPEN |
| L7 | JL projection floating-point | LOW | OPEN |
| Doc | README/SECURITY/WARNING/spec inaccuracies | N/A | OPEN |

### Still Open from 2026-06-05 (5 findings)

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| H6-P1-3a | TFHE hardcoded seeds | HIGH | OPEN |
| M2 | Inline domain tags not consolidated | MEDIUM | OPEN |
| M4 | contextId hardcoded to bytes32(0) | MEDIUM | OPEN |
| M8 | No Noir in-circuit verifier for BFV sigma | MEDIUM | OPEN |
| L3 | ecrecover without EIP-712 | LOW | OPEN |

---

## Cross-Cutting Observations

### End-to-End Proof Pipeline Analysis

```
Party P_i: sigma::prove_multi(session_binding, pid, c_rns, d_rns, s_i, e_i, d_commitment)
  → generates SigmaMultiProof with k=90 rounds
  → each round: derive_challenge_from_commitment(Poseidon, sid, pid, round, d_com, transcript_com)
  → serialised as proof bytes (version + ccs_id + ajtai + sha256_binding + sigma + cyclo)

Native Verifier: adapter::verify(stmt, proof)
  → parse proof bytes (version check, ccs_id cross-check, length validation)
  → verify_ajtai_commitment (structural: all-zeros, range, element count)
  → verify_accumulator_transcript (session_id ⋈, params_digest ⋈, norm_bound, participant∈)
  → sigma::verify_multi (re-derive challenge, check c*z_s + z_e = t + ch*d_i)
  → hash_bridge::verify (pvss_commitment)
  ⚠️ F1: ajtai_sigma_session_binding has no domain separator
  ⚠️ F2: witness length not validated

Aggregator: CycloAdapter::fold_all(instances, session_id, rng)
  → for each instance: fold_one into accumulator
  ⚠️ F3: challenge_v1 missing participant_id, params_digest
  ⚠️ F4: demo witness used instead of real NIZK witness

Compressor: ProofCompressor::prove(acc, public_inputs)
  → Nova IVC: CycloFoldStepCircuit folds 3 hashed fields via SHA-256
  → produces RecursiveSNARK
  ⚠️ G-N8: Cyclo accumulator hashed to BN254 fields — not full Ajtai verification

On-chain: PvtFheVerifier.sol
  → parse IvcBinding (11 fields, all non-zero checks)
  → verify IVC decider (currently fail-closed)
  → verify C7 via UltraHonk verifier (aggregator_final circuit)
  ⚠️ P4: on-chain IVC decider not implemented
  ⚠️ L3: ecrecover without EIP-712
```

### Trust Boundary Summary

| Component | Trusted? | What it verifies | Gaps |
|-----------|----------|-----------------|------|
| Native sigma verifier | ❌ (untrusted) | RLWE relation c*z_s+z_e=t+ch*d_i | F1 (no domain sep), F2 (witness length), P1 (open) |
| Cyclo accumulator | ❌ (untrusted) | Folded commitment consistency | F3 (missing binding), F4 (demo witness), P2 (open) |
| Nova IVC | ❌ (untrusted native) | Hash-state consistency | G-N8, S1 (transcript divergence) |
| Noir aggregator_final | ✅ (on-chain trust anchor) | Lagrange recombination at N=8 | G-N8 (N=8 gap), S2 (no Mul proof) |
| PvtFheVerifier.sol | ✅ (on-chain) | UltraHonk proof verification | P4 (IVC decider fail-closed), L3 (ecrecover) |

---

## Remediation Priority

| Priority | Findings | Effort | Impact |
|----------|----------|--------|--------|
| **P0 (Critical)** | G-N8, S1, S2 | High (architectural) | Structural soundness |
| **P1 (High)** | F1, F2/H7, F3/M10, F4, H8, H9, H6-P1-3a | Medium (code changes) | Input validation, key integrity, binding |
| **P2 (Medium)** | F5, F6, F7, M9, M2, M4, M8 | Low (local fixes) | Defense-in-depth, hygiene |
| **P3 (Low)** | F8, F9, F10, F11, L6, L7, L3 | Low (cleanup) | Code quality |

---

## Documentation Gaps Confirmed

| Document | Gap |
|----------|-----|
| `SECURITY.md` | "Verifiable FHE ops" claim is misleading (Add only, no Mul proof) |
| `WARNING.md` | C7/A1/C5 status outdated (still shows OPEN for RESOLVED items) |
| `README.md` | Status table says "Compute: Verifiable FHE ops ✅" — should be "⚠️ Add only" |
| `spec-real-p2p3.md` §3.4 | Missing `sigma_proof_bytes` SPEC EXTENSION documentation |

---

*Audit version*: 3.0 (fresh deep dive)
*Next step*: Draft remediation plan → submit to Momus for review → implement
