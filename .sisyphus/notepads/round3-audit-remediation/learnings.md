# Learnings — Round 3 Audit Remediation (A.1, A.2)

## A.1 — Wire CommittedSmudge mode into demo pipeline

### Pattern: Two-phase NIZK proof generation
The decrypt loop in `full_pipeline.rs` previously only verified NIZK proofs (graceful degradation
when `nizk_proof_bytes` is `None`). A.1 added proof generation BEFORE verification:
1. Generate esm noise per party and store in backend (via new `generate_deterministic_esm_noise_for_party`)
2. Compute per-party `sk_agg_share` (via `derive_party_binding` from public key) and `esm_agg_share` (from esm noise bytes)
3. Build `DecryptNizkStatement` with `CommittedSmudge` mode and `DecryptNizkWitness` with the agg shares
4. Generate proof via `DecryptNizkProver::prove()` and attach to `DecryptShare.nizk_proof_bytes`
5. Verify with same statement (mode-matched)

### Pattern: Deterministic esm noise generation
Used `ChaCha8Rng` seeded from `Sha256(party_id, seed, domain tag)` for reproducible noise.
This is acceptable for the research prototype demo pipeline. Production would require a real
DKG round producing committed esm noise shares.

### Pattern: sk_agg_share derivation
Used `derive_party_binding(party_pk)` — a SHA256-based derivation from the party's public key
that produces a u64 scalar. This is the same pattern used in the legacy fallback path and
maintains consistency between statement and witness.

## A.2 — Populate sk_agg_share/esm_agg_share from DKG commitments

### Pattern: Adapter parameter plumbing
The `prove_decrypted_share` function already accepted `committed_esm_noise_bytes: Option<Vec<u8>>`
and `sk_agg_share: Option<u64>` — they just weren't being populated. A.2 fills them from
pre-computed per-party data.

### Key: esm noise on adapter vs pipeline backend
The `LatticePvssBfvAdapter` creates its own backend internally. For `prove_decrypted_share`,
the esm noise is passed explicitly (not read from the adapter's backend). So esm noise
generated on the pipeline backend works fine for the PVSS path.

## Supporting changes
- Made `FhersBackend::esm_noise_poly_for` public (was private)
- Made `derive_party_binding` public in `pvthfhe_pvss::nizk_decrypt`
- Fixed pre-existing `DecryptShare` construction in `mock_impl.rs` (missing `nizk_proof_bytes` field)
