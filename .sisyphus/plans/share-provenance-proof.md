# Gap Analysis: Decryption Share Provenance Proof

**Raised by**: Cryptographer review  
**Reference**: `share_computation.nr` (Interfold PVSS)  

## What the NIZK Proves (Current)

The sigma protocol proves: **∃ (z_s, z_e) such that c·z_s + z_e = t + c·d_i**
- `t_rns` is bound to the challenge (t = c·z_s + z_e, the public key in RNS)
- `d_rns` is bound (the share)
- `c_rns` is bound (the ciphertext)
- `pvss_commitment` is bound (Ajtai hash of (z_s, z_e))
- `session_id`, `participant_id` are bound

## What's Missing

The proof does NOT verify that `z_s` (the witness secret) equals the party's DKG-derived secret key share `s_i`. A malicious party can:

1. Choose a random `s' ≠ s_i`
2. Compute `d' = partial_decrypt(c, s')` — this is computationally consistent
3. Generate a valid NIZK proof for `(s', d')`
4. Submit `d'` with the proof

The proof verifies ✓, but `d'` won't produce the correct plaintext when combined with honest shares.

## Why It Matters

- **Cheater identification**: When the aggregate fails, we can't identify WHICH party submitted a bad share
- **DoS vector**: A single malicious party corrupts the aggregate with an undetectable invalid share
- **Trust model**: The proof should demonstrate that each share was "correctly computed" from the party's allocated key material

## Fix: Bind z_s to the DKG Output

The secret key share `s_i` produced by DKG must be cryptographically committed to at setup time. For each party i:

1. During DKG: publish `commit(s_i) = Ajtai_hash(s_i)` as part of the party's registration  
2. The NIZK proof statement includes `commit(s_i)` — the prover must use the SAME `s_i` that was committed
3. The verifier checks that `commit(s_i)` matches the DKG-published value for party i

This binds `z_s` to the registered `s_i` without revealing it (Ajtai is hiding).

## Implementation Plan

### Phase 1: Publish secret key commitments during setup
- [x] After DKG, compute `sk_commit_i = AjtaiHash(sk_i)` for each party
- [x] Store in DKG transcript / party registry
- [x] Publish alongside `party_signing_pk` (G.12) in pipeline

### Phase 2: Add sk_commit to NIZK statement
- [x] Add `sk_commitment: [u8; 32]` to `SigmaStatement` (already exists as `pvss_commitment`)
- [x] Absorb into challenge derivation (`derive_challenge_scalar`) (already done)
- [x] Update `prove()` to require the prover's `sk_commitment` (already done)
- [x] Update `verify()` to check `sk_commitment` matches registered value (PIPELINE CHECK ADDED)

### Phase 3: Pipeline wiring
- [x] Pass `sk_commit_i` through pipeline alongside Schnorr keys
- [x] Include in `PipelineReport`
- [x] Write to Prover.toml if needed for Noir circuit

### Phase 4 (optional): In-circuit Ajtai verification
- [ ] Noir circuit verifies Ajtai commitment opening per share
- [ ] Deferred — on-chain verifier can check this

## Constraint Budget

- Native side: trivial (32-byte hash comparison, already computing Ajtai hashes)
- NIZK proof size: +32 bytes per proof (commitment hash)
- In-circuit (if deferred to on-chain): 0 constraints
