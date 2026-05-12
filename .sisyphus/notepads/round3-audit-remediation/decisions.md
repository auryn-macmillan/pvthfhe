# Decisions — Round 3 Audit Remediation (A.1, A.2)

## A.1: CommittedSmudge statement + witness generation

**Decision**: Generate both NIZK statement and witness in the decrypt loop of `full_pipeline.rs`,
rather than generating only the statement and expecting the backend to produce the proof.

**Rationale**: The `FhersBackend::partial_decrypt` methods all return `nizk_proof_bytes: None`.
Rather than modifying the backend (which would require threading DKG data through the FHE layer),
we generate the proof in the pipeline layer where all DKG data is accessible.

**Alternative considered**: Modify `partial_decrypt` or `partial_decrypt_committed_smudge_with_witness`
to produce NIZK proofs internally. Rejected because NIZK proof generation uses PVSS types
(`DecryptNizkProver`, `DecryptNizkStatement`, etc.) which would create a circular dependency
between pvthfhe-fhe and pvthfhe-pvss.

## A.2: esm noise on pipeline backend vs adapter backend

**Decision**: Generate esm noise on the pipeline's `FhersBackend` and pass it explicitly to
`prove_decrypted_share` as `committed_esm_noise_bytes`. Do NOT store esm noise on the
adapter's internal backend.

**Rationale**: `LatticePvssBfvAdapter::new()` creates its own `FhersBackend`. Storing data
there would require additional plumbing. The `prove_decrypted_share` function already accepts
explicit parameters for `committed_esm_noise_bytes` and `sk_agg_share`, so the explicit
parameter path is the designed interface.

## esm agg share derivation

**Decision**: Use `derive_party_binding` (SHA256-based) for both `sk_agg_share` and
`esm_agg_share` derivation. For `sk_agg_share`, hashing the party's public key. For
`esm_agg_share`, hashing the esm noise polynomial bytes.

**Rationale**: This is consistent with the legacy fallback pattern. In a production deployment,
both values would be committed during the DKG round and verified against the transcript.
The hash-based derivation provides deterministic, reproducible values that exercise the
`CommittedSmudge` code path end-to-end.
