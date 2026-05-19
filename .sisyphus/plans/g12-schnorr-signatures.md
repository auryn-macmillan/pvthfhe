# G.12 Phase 1 — Native Schnorr Signature Infrastructure

**Status**: READY (design from `design-decisions.md`)
**Next**: Implementation via task delegation
**Depends on**: Nothing (head of G.12→G.6→G.7→G.8 chain)

## Tasks

### Task 1: Add Schnorr sign/verify using arkworks BN254
- [x] Create `crates/pvthfhe-nizk/src/schnorr.rs` with:
  - `fn schnorr_sign(sk: Fr, message_hash: Fr, rng: &mut impl Rng) -> (AffinePoint<Config>, Fr)` 
  - `fn schnorr_verify(pk: AffinePoint<Config>, sig_r: AffinePoint<Config>, sig_s: Fr, message_hash: Fr) -> bool`
  - Uses standard Schnorr: R = r*G, s = r + H(R||PK||msg)*sk
  - `Config` is `ark_bn254::g1::Config` (pairing-friendly BN254 G1)
- [x] Add `pub use schnorr::*;` to `crates/pvthfhe-nizk/src/lib.rs`
- [x] Add test: roundtrip sign/verify, wrong message fails, wrong key fails
- [x] Verification: `cargo test -p pvthfhe-nizk schnorr`

### Task 2: Add signing keypair generation
- [x] `fn generate_signing_keypair(rng: &mut impl Rng) -> (Fr, AffinePoint<Config>)` — returns (sk, pk)
- [x] Add to `schnorr.rs`
- [x] Test: verify that pk == sk * G

### Task 3: Wire into pipeline
- [x] In `crates/pvthfhe-cli/src/full_pipeline.rs`:
  - Generate signing keypairs for all `n` parties
  - For each party, compute `share_hash = poseidon_sponge_commit(&share_coeffs_i)`
  - Compute `message = poseidon(&[share_hash, session_nonce])`
  - Sign: `sig_i = schnorr_sign(sk_i, message)`
  - Store `party_pk_i` and `sig_i` in pipeline state
- [x] Pass `party_pk_i` through to `PipelineReport` as new field

### Task 4: Update Prover.toml generation
- [ ] `build_c7_prover_toml` now accepts `party_public_keys: &[Fr]` and `share_signatures: &[(AffinePoint, Fr)]` (or serialized)
- [ ] Write public keys as Prover.toml inputs
- [ ] Write signatures as Prover.toml witness inputs (private)
- [ ] Update all callers

## Constraint Budget Preview (for Phase 2 — circuit)
- Each Schnorr verify: 1 scalar mult (256 doubles + 256 adds) + 1 Poseidon hash (8K constraints) ~= 3K constraints
- For n=128: 384K additional constraints
