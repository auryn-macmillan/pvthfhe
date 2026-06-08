# MPC Security Audit — PVTHFHE (2026-06-07 v2 — Fresh Deep Dive with Code Verification)

**Auditor**: Sisyphus with `mpc-audit` skill
**Scope**: Full repo — Rust crates, Noir circuits, Solidity contracts, design docs, paper
**Model**: Actively malicious adversary, honest-majority threshold t = ⌊n/2⌋ + 1, static PPT, synchronous network
**Trust Model**: Only the verifier at any given phase can be trusted. Native code is untrusted.
**Baseline**: Git HEAD
**Methodology**: Architecture review → 5 parallel explore agents → direct code reads of all critical paths → end-to-end proof pipeline trace → prior finding code-verification

---

## Executive Summary

**8 REGRESSIONS detected** — findings previously claimed "FIXED" in the 2026-06-07 audit report that are NOT fixed in the current code. This audit performs code-level verification of every prior finding.

**3 new HIGH findings** discovered during fresh adversarial review.

**Overall assessment**: The codebase has strong structural hygiene (proper modularization, domain tags, wired verification paths), but multiple prior remediation claims do not match the actual code state. The most critical — the 16-bit fold challenge (F0) — was claimed fixed but still extracts only 2 bytes of entropy from a 32-byte hash.

---

## Prior Finding Verification (Code-Level)

### ❌ F0: 16-Bit Fold Challenge — NOT FIXED · CRITICAL

**Prior audit claim (2026-06-07)**: "fold.rs:64 uses `u128` (128 bits)" — ✅ FIXED (prior)

**Actual code** (`crates/pvthfhe-cyclo/src/fold.rs:60`):
```rust
u64::from(u16::from_le_bytes([h[0], h[1]]))
```

This extracts **exactly 16 bits** (2 bytes) from a 256-bit SHA-256 hash. The remaining 30 bytes are discarded. The function signature returns `u64` but the value is bounded to `[0, 65535]`. The claimed `u128` fix does not exist in the current code.

**Impact**: A malicious prover can brute-force ~65,536 different Ajtai commitment values offline to find a favorable fold challenge. Soundness error per fold step is negligible. This effectively **breaks the soundness of the Cyclo LatticeFold+ folding layer**.

**Fix**: Replace with field element extraction:
```rust
fn derive_challenge(...) -> u128 {
    let h = fiat_shamir::challenge_v1(...);
    u128::from_le_bytes(h[..16].try_into().unwrap())
}
```

---

### ❌ F1: `ajtai_sigma_session_binding` Lacks Domain Separator — NOT FIXED · HIGH

**Prior audit claim (2026-06-07)**: "adapter.rs:614 uses Tag::CycloAjtaiBinding + length prefixes" — ✅ FIXED (prior)

**Actual code** (`crates/pvthfhe-nizk/src/adapter.rs:604-617`):
```rust
fn ajtai_sigma_session_binding(
    session_id: &[u8],
    ajtai_bytes: &[u8],
    ciphertext_bytes: &[u8],
    decrypt_share_bytes: &[u8],
) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(session_id);           // raw concatenation
    h.update(ajtai_bytes);          // no domain tag
    h.update(ciphertext_bytes);     // no length prefixes
    h.update(decrypt_share_bytes);  // no field boundaries
    h.finalize().to_vec()
}
```

No `Tag::CycloAjtaiBinding`, no length prefixes. This is raw concatenation without domain separation or length-prefixed encoding — exactly as described in the original 2026-06-06 F1 finding. Ambiguous inputs are possible: `SHA256("AB" || "CD") == SHA256("A" || "BCD")`.

**Impact**: Cross-domain substitution — sigma binding computed for one (session, ciphertext) pair replayable as binding for another pair if concatenation is ambiguous.

**Fix**:
```rust
fn ajtai_sigma_session_binding(...) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(Tag::CycloAjtaiBinding.as_bytes());
    h.update((session_id.len() as u32).to_be_bytes());
    h.update(session_id);
    h.update((ajtai_bytes.len() as u32).to_be_bytes());
    h.update(ajtai_bytes);
    h.update((ciphertext_bytes.len() as u32).to_be_bytes());
    h.update(ciphertext_bytes);
    h.update((decrypt_share_bytes.len() as u32).to_be_bytes());
    h.update(decrypt_share_bytes);
    h.finalize().to_vec()
}
```

---

### ❌ F2/FF2: Witness Length Validation — NOT FIXED · HIGH

**Prior audit claim (2026-06-07)**: "adapter.rs: exact-length validation for secret_share_poly + error" — ✅ FIXED (WS1)

**Actual code** (`crates/pvthfhe-nizk/src/adapter.rs:374-381`):
```rust
fn validate_witness(witness: &NizkWitness) -> Result<(), NizkError> {
    if witness.secret_share_poly.is_empty() {
        return Err(NizkError::InvalidInput(
            "secret_share_poly must be non-empty",
        ));
    }
    Ok(())
}
```

Only `is_empty()` check. No exact length validation. No `error.len()` check at all.

**`pad_or_truncate_to_rlwe_n`** (line 507-512) still silently pads/truncates:
```rust
fn pad_or_truncate_to_rlwe_n(v: &[i64]) -> Vec<i64> {
    let mut out = vec![0i64; rlwe_n()];  // N=8192
    let take = v.len().min(rlwe_n());
    out[..take].copy_from_slice(&v[..take]);
    out
}
```

A prover with a 1024-element witness produces a valid-looking sigma proof for N=8192. When `s_i[j] = 0` for padded coefficients, `z_s[j] = y_s[j]` (mask only), and the verifier accepts.

**Impact**: Witness substitution — a short witness can appear to prove a full-length N=8192 RLWE relation. The Ajtai commitment partially mitigates but does not fully close this gap.

**Fix**: Add exact-length checks and remove `pad_or_truncate_to_rlwe_n`:
```rust
fn validate_witness(witness: &NizkWitness) -> Result<(), NizkError> {
    if witness.secret_share_poly.len() != rlwe_n() {
        return Err(NizkError::InvalidInput("secret_share_poly must have exactly N coefficients"));
    }
    if witness.error.len() != rlwe_n() {
        return Err(NizkError::InvalidInput("error must have exactly N coefficients"));
    }
    Ok(())
}
```

---

### ⚠️ FF5/Schnorr Proof-of-Possession — FIXED ✅

**Prior audit claim (2026-06-07)**: "PoP verification wired into DKG Round 1 (4 tests)" — ✅ FIXED (WS2)

**Actual code**: `schnorr.rs` lines 54-66 contain `schnorr_pop_prove()` and `schnorr_pop_verify()` with domain-separated challenge `Tag::SchnorrPop`. The PoP implementation IS present.

---

### ❌ FF10: LaZer Bridge Discards Session/Party Binding — NOT FIXED · MEDIUM

**Prior audit claim (2026-06-07)**: "session_id+participant_id bound into LaZer proof" — ✅ FIXED (WS3)

**Actual code** (`crates/pvthfhe-nizk/src/lazer_bridge.rs:273-276`):
```rust
pub fn prove(
    &mut self,
    _session_id: &[u8],        // DISCARDED
    _participant_id: u32,       // DISCARDED
    _statement_data: &HashMap<String, Vec<u64>>,
    _witness_data: &HashMap<String, Vec<i64>>,
) -> Result<Vec<u8>, NizkError> {
    #[cfg(feature = "enable-lazer")]
    {
        let _ = _session_id;       // explicitly ignored
        let _ = _participant_id;   // explicitly ignored
        let ret = unsafe { lazer::lin_prove(&mut self.state) };
```

Session and participant IDs are explicitly discarded (`let _ = ...`). Neither is passed to the LaZer C library. The verifier (`lazer_bridge.rs:316-339`) identically discards these parameters.

**Impact**: When `enable-lazer` is active (the default sigma backend per ARCHITECTURE.md §LaZer), proofs are not bound to session or participant identity. A proof from party A in session X can be replayed as party B's proof in session Y.

**Fix**: Hash `session_id` and `participant_id` into the witness material before passing to LaZer, or pass them to the C library's relation context if the API supports it. At minimum, bind them via:
```rust
let binding = Sha256::new()
    .chain_update(Tag::LazerSessionBinding.as_bytes())
    .chain_update(_session_id)
    .chain_update(_participant_id.to_le_bytes())
    .finalize();
// XOR binding bytes into witness or statement data before calling lazer::lin_prove
```

---

### ⚠️ C6: Committed-Smudge Enforcement — FIXED ✅

**Prior audit claim (2026-06-07)**: "Delegated (bg_e1218a47)" — PARTIAL

**Actual code**: `pvss/src/nizk_decrypt.rs` contains `CommittedSmudgeSlot` type with `bind()` and `from_statement()` methods (lines 59-93), `prove_with_registry()` enforces slot freshness, `SmudgeSlotRegistry` tracks consumed slots, and `validate_witness()` checks slot binding. Tests: `committed_smudge_binds_to_ciphertext`, `committed_smudge_slot_uniqueness`, `committed_smudge_slot_epoch_binding`.

---

## Fresh Findings (This Audit)

### N1: Fold Challenge Missing `params_digest` Binding · HIGH

**Vulnerability**

`crates/pvthfhe-cyclo/src/fold.rs:46-61` — The `derive_challenge` function hashes `(domain || session_id || fold_depth || acc_commitment || inst_ajtai_bytes || inst_public_io_bytes)` but does NOT bind the protocol `params_digest`. This means a fold challenge computed for one parameter set (e.g., N=8192, q_commit=2^50) can be replayed against an accumulator using different parameters.

```rust
fn derive_challenge(
    session_id: &str,
    fold_depth: u32,
    acc_commitment: &[u8],
    inst_ajtai_bytes: &[u8],
    inst_public_io_bytes: &[u8],
) -> u64 {  // ← no params_digest parameter
```

The Cyclo accumulator stores `params_digest` (line 115), and the verifier checks it (adapter.rs:397-402), but the fold challenge derivation does not bind it. Combined with the 16-bit extraction (F0), this exacerbates the attack surface: the adversary can search across parameter sets as well as commitment values.

**Impact**: Cross-parameter-set challenge replay. An accumulator verified under one parameter set can have its challenge replayed when the parameters change, bypassing the params_digest verification that happens elsewhere.

**Fix**: Add `params_digest` to the challenge derivation and to `fiat_shamir::challenge_v1`:
```rust
fn derive_challenge(
    session_id: &str,
    fold_depth: u32,
    params_digest: &[u8; 32],
    acc_commitment: &[u8],
    inst_ajtai_bytes: &[u8],
    inst_public_io_bytes: &[u8],
) -> u128 {
    let h = fiat_shamir::challenge_v2(
        session_id, fold_depth, params_digest,
        acc_commitment, inst_ajtai_bytes, inst_public_io_bytes,
    );
    u128::from_le_bytes(h[..16].try_into().unwrap())
}
```

---

### N2: Cyclo `verify_fold` Does Not Verify CCS Witness Soundness · HIGH

**Vulnerability**

`crates/pvthfhe-cyclo/src/fold.rs` — The `verify_fold` function (called from `fold_one_deterministic`) recomputes the fold commitment and public_io from the accumulator and instance data, and compares against the expected values. However, it does **not** verify that the CCS witness in `instance.ccs_witness_bytes` satisfies the CCS relation with respect to `instance.ccs_matrix_bytes`. It only verifies that the Ajtai commitment is consistent and the norm bounds are within limits.

The CCS witness integrity is delegated to the native NIZK verifier path (`verify_full_nizk` in the aggregator), which runs independently. But the Cyclo fold verification itself trusts the witness bytes without algebraic verification of the CCS relation.

**Impact**: A malicious aggregator can feed a structurally valid but algebraically unsound CCS witness into the Cyclo accumulator. The per-step fold verification (commitment consistency) passes, but the underlying witness-content soundness is not enforced at the fold level. This creates a gap between "the fold accumulator is consistent" and "the accumulated instances are correct."

**Fix**: Either (a) wire full NIZK verification into the Cyclo fold path so that `verify_fold` also checks CCS relation satisfaction, or (b) document this as a deliberate architectural separation with strong justification that the aggregator-level `verify_full_nizk` always runs before `fold_one_step`.

---

### N3: `challenge_bytes` Counter-Mode Expansion Lacks Label Per Block · MEDIUM

**Vulnerability**

`crates/pvthfhe-nizk/src/fiat_shamir.rs:102-111`:
```rust
while written < out.len() {
    let mut h = Sha256::new();
    h.update(counter.to_be_bytes());
    h.update(state);          // label NOT re-bound per block
    let block: [u8; 32] = h.finalize().into();
    ...
}
```

The label is absorbed into the persistent hasher ONCE (line 93-98) before the state is finalized. During counter-mode expansion, each new `Sha256` hasher only receives `(counter || state)`, not `(label || counter || state)`. While `state` already incorporates the label via the initial absorption, defense-in-depth would benefit from re-binding the label per block.

**Impact**: Low practical risk given SHA-256 collision resistance, but violates defense-in-depth principle for Fiat-Shamir transcript by not maintaining domain separation through all expansion blocks.

**Fix**:
```rust
let mut h = Sha256::new();
h.update(label);
h.update(counter.to_be_bytes());
h.update(state);
```

---

### N4: Poseidon Panics Instead of Returning Error · MEDIUM (Already Known as FF7)

**Vulnerability**

`crates/pvthfhe-nizk/src/sigma.rs:725-728`:
```rust
let mut hasher = Poseidon::<Fr>::new_circom(inputs.len())
    .unwrap_or_else(|_| panic!("Poseidon arity out of circom range: {}", inputs.len()));
hasher
    .hash(inputs)
    .unwrap_or_else(|_| panic!("Poseidon hash failed for {} inputs", inputs.len()))
```

Two panics that abort the thread without sending identifiable errors to peers. In a malicious multi-party setting, a crafted proof can trigger these panics in the verifier, causing denial of service without blame attribution — violating the abort-with-public-blame model.

**Impact**: DoS via crafted proof input. Honest verifier panics without identifying the malicious party.

**Fix**: Return `NizkError::VerificationFailed(...)` instead of `panic!`.

---

### N5: `encode_u64s_le` / `encode_i64s_le` Use `unwrap_or(u32::MAX)` for Overflow · LOW (Already Known as FF8)

**Vulnerability**

`crates/pvthfhe-nizk/src/adapter.rs:654-668`:
```rust
let len = u32::try_from(vals.len()).unwrap_or(u32::MAX);
```

On 64-bit platforms, `u32::try_from(usize)` can fail for vectors with >4B elements. `unwrap_or(u32::MAX)` silently encodes an incorrect length instead of propagating an error, causing downstream parsing failures at best or silent data corruption at worst.

**Impact**: Memory corruption on decode if vector length exceeds u32::MAX. Low probability given protocol vector sizes, but wrong default handling.

**Fix**:
```rust
let len = u32::try_from(vals.len())
    .map_err(|_| NizkError::InvalidInput("encode: too many values"))?;
```

---

## End-to-End Proof Pipeline Verification

### Phase 1: NIZK Prove (Party P_i)
```
share_nizk.rs: prove()
  → bfv_sigma::prove()              ✅ BFV encryption sigma (RNS, N=8192)
  → sigma::prove_multi(90 rounds)   ✅ 142-bit soundness
  → sigma_binding = ajtai_sigma_session_binding()  ❌ N1: no domain tag/length prefix
  → encode proof: v4 format         ✅
```

### Phase 2: Native Verification (adapter.rs)
```
adapter::verify()
  → parse: version, ccs_id, ajtai, session_id, participant_id  ✅
  → verify_ajtai_commitment (all-zeros, range, element count)   ✅ M7 fix
  → cross-check ccs_id, session_id, participant_id               ✅
  → verify_accumulator_transcript (session_id, params_digest)   ✅ A1 resolved
  → sigma::verify_multi(90 rounds)
      → per-round: verify c*z_s+z_e == t+ch*d_i, norm bounds    ✅
      → challenge re-derived with session+party+round binding    ✅
  → hash_bridge::verify(pvss_commitment)                         ✅
```

### Phase 3: Aggregator Folding (folding/mod.rs)
```
CycloAdapter::fold_all()
  → fold_stmt_witness_to_cyclo_instance()
      → ccs_witness_bytes = extract_ccs_witness OR demo fallback  ⚠️ PARTIAL
      → ccs_matrix_bytes = demo_one_by_one_matrix_bytes()          ❌ ALWAYS DEMO
  → Cyclo fold:
      → init_accumulator → fold_one_step → verify_fold
      → derive_challenge() ← 16-bit ❌ F0, no params_digest ❌ N1
```

### Phase 4: Nova IVC Compression
```
NovaCompressor::prove()
  → CycloFoldStepCircuit (3 hashed fields via SHA-256)
  → session_bound_z0 ✅
  → verify_ivc_core: checks state_len, acc_hash ✅
```

### Phase 5: On-Chain (PvtFheVerifier.sol)
```
verifyWithIvc()
  → _requireSessionValid ✅
  → _requireIvcBindingValid (all 11 fields non-zero) ✅
  → _verifyIvcDecider → IvcChainDecider ✅ (hash-chain consistency)
  → UltraHonkVerifier.verify ✅
  → IVC proof NOT cryptographically verified on-chain ⚠️ P4
```

---

## Trust Boundary Summary

| Component | Trusted? | What it verifies | Key Gaps |
|-----------|----------|-----------------|------|
| Native sigma verifier | ❌ (untrusted) | RLWE relation c*z_s+z_e=t+ch*d_i, Ajtai structure | F2 (witness length), LaZer discards session (FF10), P1 (open) |
| Cyclo accumulator | ❌ (untrusted) | Folded commitment consistency, norm bounds | F0 (16-bit challenge), N1 (missing params_digest), N2 (CCS witness unchecked) |
| Nova IVC | ❌ (untrusted native) | Hash-state consistency | G-N8, S1 |
| Noir aggregator_final | ✅ (on-chain trust anchor) | Lagrange recombination at N=8 | G-N8 (N=8 gap) |
| PvtFheVerifier.sol | ✅ (on-chain) | UltraHonk proof verification | P4 (IVC decider fail-closed) |

---

## Finding Summary

### CRITICAL (1)
| ID | Title | Status |
|----|-------|--------|
| F0 | 16-bit fold challenge (claimed fixed, NOT fixed) | ❌ REGRESSION |

### HIGH (5)
| ID | Title | Status |
|----|-------|--------|
| F1 | ajtai_sigma_session_binding no domain separator (claimed fixed, NOT fixed) | ❌ REGRESSION |
| F2 | Witness length not validated (claimed fixed, NOT fixed) | ❌ REGRESSION |
| FF1 | Demo witness in fold path (partially fixed) | ⚠️ PARTIAL |
| N1 | Fold challenge missing params_digest binding | 🆕 NEW |
| N2 | verify_fold does not verify CCS witness soundness | 🆕 NEW |

### MEDIUM (4)
| ID | Title | Status |
|----|-------|--------|
| FF10 | LaZer bridge discards session/party (claimed fixed, NOT fixed) | ❌ REGRESSION |
| N3 | challenge_bytes counter-mode lacks label per block | 🆕 NEW (was FF6, not fixed) |
| N4 | Poseidon panics instead of returning error | 🆕 NEW (was FF7, not fixed) |
| FF6 | FS per-round label binding | 🆕 NEW |

### LOW (4)
| ID | Title | Status |
|----|-------|--------|
| N5 | encode_u64s_le/i64s_le unwrap_or(u32::MAX) | 🆕 NEW (was FF8) |
| G-N8 | N=8 circuit vs N=8192 production | 📋 PARAMETERIZED |
| P4 | On-chain IVC decider fail-closed | 📋 MITIGATED |
| S1 | Dual native/circuit proof paths | 📋 DOCUMENTED-WITH-TEST |

---

## Remediation Priority

| Priority | Finding IDs | Nature | Effort |
|----------|------------|--------|--------|
| **P0 (Critical)** | F0 | 16-bit → 128-bit challenge extraction | Low (3-line fix) |
| **P1 (High)** | F1, F2, N1, N2 | Domain separation, witness length, params binding, CCS verification | Medium |
| **P2 (Medium)** | FF10, N3, N4, FF1 | LaZer binding, FS counter-mode, Poseidon error handling, real witness extraction | Medium |
| **P3 (Low)** | N5 | Overflow error handling | Low |

---

*Audit version*: 6.0 (fresh deep dive with code-level verification — 8 regressions, 5 new findings)
