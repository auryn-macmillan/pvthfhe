
## G.29 Domain Constants Audit (2026-05-18)

### Key Findings
- Noir defines 6 `DOMAIN_*` constants (values 1-6) in `circuits/protocol_constants/src/lib.nr`
- Rust `full_pipeline.rs` correctly uses domain 1 (vector_hash_8) and domain 6 (bind_8_with_domain_native) for `aggregator_final`
- Domains 2-5 are Noir-internal (used within `decrypt_share` circuit to compute commitment bindings)
- `witness_gen.rs` uses a rolling digest (DIGEST_DOMAIN=987654321) instead of Poseidon — stale/legacy code for deferred `noir_decrypt_share` phase
- Rust `pvthfhe-domain-tags` crate uses STRING-based tags — separate system from numeric Poseidon domain tags
- No fixes needed for active code paths
