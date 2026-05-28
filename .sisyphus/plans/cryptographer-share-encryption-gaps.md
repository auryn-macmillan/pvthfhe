# Cryptographer Remediation Plan — Share Encryption Gaps

**Status**: COMPLETE
**Date**: 2026-05-28

## Findings

### G1 — On-chain doesn't verify share encryption correctness (HIGH)

The PVSS share proof (BFV sigma) is verified natively (off-chain) only. The on-chain UltraHonk proof does not include BFV sigma relation verification.

**Current state**: `nova_state_commitment/src/main.nr` binds IVC proof metadata (P4 fix) but doesn't include per-share BFV sigma verification results as public inputs.

**Fix**: Add a `share_verification_hash: pub Field` to the `nova_state_commitment` Noir circuit. This hash is the Poseidon chain over per-share BFV sigma verification results from the Nova accumulator. The on-chain verifier checks that this hash is non-zero and binds to the participant set hash.

**Files**: `circuits/nova_state_commitment/src/main.nr`, `crates/pvthfhe-cli/src/full_pipeline.rs`, `contracts/src/PvtFheVerifier.sol`

### G2 — Missing Greco/quotient-aware enforcement in PVSS share verifier (MEDIUM)

There is an untracked `bfv_greco.rs` file with Greco-style quotient/S-Z attestation logic that is not part of the branch.

**Fix**: Track `bfv_greco.rs` in git, wire `bfv_greco::verify` into the PVSS share verification pipeline. Ensure the Greco quotient witnesses are populated from the BFV sigma proof data and enforced in `verify_shares`. If `bfv_greco.rs` doesn't exist as a committed file, implement it based on the Greco construction from the Symphony paper (monomial embedding + quotient bounds).

**Files**: `crates/pvthfhe-nizk/src/bfv_greco.rs` (track or create), `crates/pvthfhe-pvss/src/nizk_share.rs`

### G3 — BFV sigma checks responses, not "bounded witness exists" (HIGH)

The current `bfv_sigma::verify` checks:
- Fiat-Shamir challenge binding
- Response bounds on `z_u`, `z_e0`, `z_e1`, `z_m`
- Two BFV RNS equations (ct0/ct1 legs)

It does NOT prove there EXISTS a BFV-valid witness `(u, e, m)` with small coefficients. This is a soundness gap — the sigma protocol is honest-verifier zero-knowledge but doesn't provide knowledge soundness without the Greco quotient construction.

**Fix**: Complement the existing `bfv_sigma::verify` with `bfv_greco::verify` (from G2) which enforces:
- Quotient witnesses `q0, q1` for the RNS equations
- Bound enforcement on `q0, q1` (they must be small because `u`, `e`, `m` are small)
- The Greco soundness theorem: if the sigma equations hold AND the quotients are bounded, then there exists a valid BFV witness

**Files**: `crates/pvthfhe-nizk/src/bfv_sigma.rs`, `crates/pvthfhe-nizk/src/bfv_greco.rs`

### G4 — Publicly verifiable pipeline incomplete (HIGH)

The on-chain UltraHonk proof binds the final C7 aggregator state, but there is no on-chain commitment that "all per-share PVSS share proofs passed BFV sigma verification." A malicious aggregator could submit valid shares to the off-chain verifier, skip verification, and the chain wouldn't detect it.

**Fix**: Add a `per_share_verification_hash` field to the `NovaStateCommitment` public inputs. This is computed as:
```
per_share_verification_hash = Poseidon(share_0_hash, share_1_hash, ..., share_{t-1}_hash)
```
where each `share_i_hash = Poseidon(party_id_i, sigma_verification_result_i, share_commitment_i)`.

The on-chain verifier checks this hash against the participant set hash and the decrypt NIZK hash.

**Files**: `circuits/nova_state_commitment/src/main.nr`, `crates/pvthfhe-compressor/src/nova/snark_bridge.rs`, `contracts/src/PvtFheVerifier.sol`

## Execution

### Phase 1 — Track bfv_greco.rs + wire into PVSS (G2)
- [ ] Verify `crates/pvthfhe-nizk/src/bfv_greco.rs` exists or create it
- [ ] If new: implement Greco quotient witness construction from BFV sigma proof
- [ ] Wire `bfv_greco::verify` into `verify_shares` pipeline

### Phase 2 — Add per-share verification hash to on-chain circuit (G1 + G4)
- [ ] Add `share_verification_hash: pub Field` to `nova_state_commitment/src/main.nr`
- [ ] Compute `share_verification_hash` from per-share BFV sigma results in `full_pipeline.rs`
- [ ] Wire into `IvcBindingData` in `snark_bridge.rs`
- [ ] Update `PvtFheVerifier.sol` to check `share_verification_hash != 0`

### Phase 3 — Complement bfv_sigma with Greco quotient bounds (G3)
- [ ] Add quotient witness extraction to `bfv_greco` (q0, q1 for each RNS limb)
- [ ] Add bound checks: `||q0||_infinity <= B_Q`, `||q1||_infinity <= B_Q`
- [ ] Verify: `bfv_greco::verify(stmt, proof, greco_witness) -> bool`
- [ ] Call from `bfv_sigma::verify` as defense-in-depth

## Success Criteria
- [ ] `cargo check --workspace` = 0 errors
- [ ] `just demo-e2e` runs with ACCEPT
- [ ] On-chain verifier checks share verification hash
- [ ] Greco quotient bounds enforced in PVSS share verification
- [ ] No new surrogates or dummy proofs
