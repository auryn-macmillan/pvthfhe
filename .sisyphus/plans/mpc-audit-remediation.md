# MPC Audit Remediation Plan

**Status**: COMPLETE (14/14 findings addressed)
**Audit Source**: mpcsec.org/SKILL.md audit framework
**Date**: 2026-05-26

## HIGH Findings (6)

### H1 — S-Z Soundness ✅ FIXED (3-point S-Z, 2^-135)
### H2 — Rogue-Key: No Commit-Before-Reveal ✅ FIXED (commitment nonce + pk_i_hash binding)
### H3 — Synthetic Ajtai Commitment ✅ FIXED (SHA-256 over NIZK proof + ciphertext)

### H4 — Empty Proof List Passes Vacuously ✅ FIXED
### H5 — No G1Affine On-Curve Check ✅ FIXED
### H6 — C7 Challenge Missing Session Binding ✅ FIXED
**File**: `crates/pvthfhe-cli/src/full_pipeline.rs:2811-2818`
**Finding**: `derive_challenge_point_r` has no domain separator, no session_id, truncates to 32 bytes. Circuit uses different derivation. Cross-session replay possible.
**Fix**: Align with in-circuit derivation: `hash_all_coeffs(&[coeff_commitment, dkg_root_hash, d_commitment])`. Bind session_id. Remove truncation.

## MEDIUM Findings (4)

### M1 — Shamir Resharing Uses ~10-bit Seed
**File**: `crates/pvthfhe-fhe/src/fhers.rs:461-462`
**Fix**: Replace `StdRng::seed_from_u64(party_id)` with `OsRng` or seed from session entropy.

### M2 — Weak Post-Decryption Verification
**File**: `crates/pvthfhe-cli/src/full_pipeline.rs:1447-1469`
**Fix**: Add group-public-key consistency check after aggregate decryption.

### M3 — Field Element Barrel Reduction
**File**: `crates/pvthfhe-nizk/src/schnorr.rs:20,29,48`, `sigma.rs:571`, `ajtai.rs:66`
**Fix**: Replace `from_le_bytes_mod_order` with `from_bigint(BigInt::new(limbs))` returning Option; reject None.

### M4 — hash_bytes No Domain Separator
**File**: `crates/pvthfhe-aggregator/src/keygen/simulator.rs:66-72`
**Fix**: Pass domain tags to hash_bytes calls for participant_set_hash, dkg_root, transcript_hash.

## LOW Findings (4)
- L1: compute_ciphertext_v non-namespaced tag → register in domain-tags
- L2: bfv_sigma delegated binding → add first-class session_id/party_id
- L3: CycloTernaryTranscript no participant_id → add parameter
- L4: Malformed HE public key → add pk non-triviality check

## Execution Order
1. H4 (1 line fix)
2. H5 (2 sites, ~5 lines)
3. H6 (rewrite function, ~10 lines)
4. H1 (complex, redesign S-Z with multiple points)
5. M1, M3, M4 (targeted fixes)
6. H2, H3 (architectural changes)
7. L1-L4
