# G.12 — Schnorr Signatures — Design Decisions

**Status**: DESIGN COMPLETE (2026-05-18)
**Next**: Implementation (estimate: ~2 days)

## Decisions

| # | Question | Decision |
|---|----------|----------|
| Q1 | Keypair origin | **Independent generation**, registered on-chain before proof submission |
| Q2 | Verification location | **In Noir circuit** (`aggregator_final`), ~3K constraints/sig. Signatures are private witness inputs; public keys are public inputs. |

## Implementation Plan

### Phase 1: Native Infrastructure
1. Add `generate_signing_keypair() -> (Fr, AffinePoint)` to keygen module
2. Add `schnorr_sign(sk: Fr, message_hash: Fr) -> SchnorrSignature` 
3. Add `schnorr_verify(pk: AffinePoint, sig: SchnorrSignature, message_hash: Fr) -> bool`
4. Wire per-party signing into the pipeline: `sig_i = schnorr_sign(sk_i, poseidon(d_i_hash, session_nonce))`
5. Store `party_pk_i` in the DKG transcript or pipeline config

### Phase 2: Circuit
6. Add `SchnorrVerifierVar` gadget: verifies `R = s*G - e*PK` where `e = Poseidon(R, PK, message)`
7. In `aggregator_final/src/main.nr`: for each share, verify signature
8. Pass `party_pk_i` as additional public inputs (32 bytes per party)
9. Pass `signature_i` as private witness inputs

### Phase 3: Pipeline Integration
10. Update `build_c7_prover_toml` to include `party_pk_i` and `signature_i`
11. Update `PipelineReport` to include signature verification status

## Circuit Constraint Budget
- ~3,000 constraints per Schnorr verification (1 scalar mult + Poseidon hash)
- For n=128: ~384,000 constraints — fits within compressor budget

# G.6-G.8 — Noir Circuit Constraints — Design Decisions

**Status**: DESIGN COMPLETE (2026-05-18)
**Next**: Implementation (estimate: ~3 days, depends on G.12)

## Decisions

| # | Question | Decision |
|---|----------|----------|
| Q3 | Share verification method | **Full in-circuit**: compute per-share hashes, verify Schnorr sigs, reconstruct `combined_share_hash` |
| Q4 | Committee binding | **In-circuit Poseidon**: circuit computes `Poseidon(committee_party_ids)` and constrains `== participant_set_hash` |

## Implementation Plan

### G.6: Participant Share Constraints
1. For each `d_i` in `participant_shares`: circuit computes `hash_i = Poseidon(d_i)` 
2. Circuit reconstructs `combined_share_hash = Poseidon(hash_0, hash_1, ..., hash_{t-1})`  
3. Circuit verifies `combined_share_hash` is bound in `d_commitment` (already done)
4. Circuit verifies `Schnorr_verify(sig_i, pk_i, hash_i || session_nonce)` for each share
5. This is ~10K constraints per share (8K Poseidon + 3K Schnorr)

### G.7: Committee Binding
1. Circuit receives `committee_party_ids: [Field; n]` as witness
2. Circuit computes `computed_ps_hash = Poseidon(committee_party_ids[0..n], DOMAIN_COMMITTEE)`
3. Circuit constrains `computed_ps_hash == participant_set_hash` (public input)
4. Removes the current `assert(participant_set_hash != 0)` placeholder (line 85)

### G.8: Threshold Enforcement
1. Circuit receives `threshold: Field` as public input
2. Circuit counts how many shares are non-zero: `used_count = sum_i is_nonzero(d_i)`
3. Circuit constrains `used_count == threshold + 1`

## ExternalInputs Changes Required
Current `aggregator_final` inputs: `participant_shares`, `committee_party_ids`, `participant_set_hash`, `d_commitment`, `ciphertext_hash`, `aggregate_pk_hash`, `threshold`, `epoch`

New inputs for G.6-G.8 + G.12:
- `party_public_keys: [Field; n]` (public) — per-party Schnorr verification keys
- `share_signatures: [SchnorrSignature; n]` (private witness) — one per share

## Dependency Chain
```
G.12 (Schnorr infra) → G.6 (share hashes + sig verify) → G.7 (committee binding) → G.8 (threshold)
```
